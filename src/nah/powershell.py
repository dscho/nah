"""Minimal PowerShell command classifier.

PowerShell has fundamentally different syntax from POSIX shells — object
pipelines, cmdlets (verb-noun pairs), aliases that collide with POSIX
names (``ls``, ``cat``, ``rm``), named parameters (``-Recurse``,
``-Force``), and the call operator (``&``). Running PowerShell strings
through nah's Bash tokenizer would silently mis-classify both safe and
dangerous commands.

This classifier handles a small, deliberately conservative slice:
clearly read-only cmdlets become ALLOW, clearly dangerous patterns
become BLOCK or ASK, and everything else falls back to ASK so a human
gets the chance to inspect it. The goal is not parity with the Bash
classifier — it is to surface obvious safe and obvious dangerous
patterns at the fail-safe ASK default.

A full PowerShell tokenizer is out of scope. The implementation uses a
regex split on statement separators (``;``, newline) and pipeline
separators (``|`` outside quotes/braces), extracts the first non-flag
token of each pipeline stage as the cmdlet name, and looks it up in
small allow/deny tables. Anything that uses variable expansion, the
call operator, a subexpression, or a script block is treated as
unrecognized.
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Cmdlet tables
# ---------------------------------------------------------------------------

# Read-only cmdlets and their default aliases. All entries are
# canonicalized to lowercase here so the lookup ignores PowerShell's
# case-insensitive naming. Keep this conservative — anything whose
# default behavior writes, deletes, or executes does NOT belong here.
_SAFE_CMDLETS: frozenset[str] = frozenset({
    # Read filesystem
    "get-childitem", "gci", "dir", "ls",
    "get-content", "gc", "cat", "type",
    "get-item", "gi",
    "get-itemproperty", "gp",
    "get-location", "gl", "pwd",
    "test-path",
    "resolve-path", "rvpa",
    # Read process / system state
    "get-process", "gps", "ps",
    "get-service", "gsv",
    "get-command", "gcm",
    "get-module", "gmo",
    "get-help", "help", "man",
    "get-date",
    "get-host",
    "get-variable", "gv",
    "get-alias", "gal",
    "get-history", "ghy", "h", "history",
    "get-member", "gm",
    "get-psdrive", "gdr",
    "get-eventlog",
    # Pipeline shaping / formatting (object-only, no side effects)
    "select-object", "select",
    "where-object", "where", "?",
    "foreach-object", "foreach", "%",
    "sort-object", "sort",
    "group-object", "group",
    "measure-object", "measure",
    "compare-object", "compare", "diff",
    "format-table", "ft",
    "format-list", "fl",
    "format-wide", "fw",
    "format-custom", "fc",
    "out-string",
    "out-host",
    "out-null",
    "out-default",
    "convertto-json",
    "convertfrom-json",
    "convertto-csv",
    "convertfrom-csv",
    "convertto-xml",
    # Display
    "write-host",
    "write-output", "echo", "write",
    "write-verbose",
    "write-debug",
    "write-information",
})


# Cmdlets whose default behavior is dangerous in this context, plus any
# alias that PowerShell ships. Treated as BLOCK rather than ASK because
# the user has no way to write a safe variant without re-typing the
# whole command outside nah.
_DENY_CMDLETS: frozenset[str] = frozenset({
    "invoke-expression", "iex",     # arbitrary string eval
})


# Cmdlets that are risky but legitimate. ASK so the user inspects.
_ASK_CMDLETS: frozenset[str] = frozenset({
    "invoke-webrequest", "iwr", "curl",  # curl is a PS alias to iwr
    "invoke-restmethod", "irm",
    "set-executionpolicy",
    "start-process", "saps", "start",
    "stop-process", "kill", "spps",
    "remove-item", "rm", "ri", "del", "erase", "rd", "rmdir",
    "clear-host", "cls",
    "add-type",
    "new-service", "stop-service", "restart-service", "start-service",
    "set-service",
    "set-content", "sc",
    "add-content", "ac",
    "out-file",
    "new-item", "ni", "md", "mkdir",
    "set-item",
    "set-itemproperty",
    "copy-item", "cp", "copy", "cpi",
    "move-item", "mv", "move", "mi",
    "rename-item", "ren", "rni",
    "set-location", "cd", "chdir", "sl",
    "push-location", "pushd",
    "pop-location", "popd",
    "convertfrom-securestring",
    "convertto-securestring",
    "tee-object", "tee",
    "import-module", "ipmo",
    "set-variable", "sv", "set",
    "new-variable", "nv",
    "invoke-command", "icm",
    "enter-pssession", "etsn",
    "new-pssession", "nsn",
    # Scriptblock-executing cmdlets — the script body is opaque to a
    # static check, so each invocation needs a human in the loop.
    "start-job", "sajb",
    "start-threadjob",
    "invoke-job",
    "wait-job", "wjb",
    "receive-job", "rcjb",
    "register-objectevent",
    "register-engineevent",
    "register-wmievent",
    "new-event",
    "trace-command",
})


@dataclass(frozen=True)
class _Stage:
    """One pipeline stage with its extracted cmdlet name and raw text."""
    cmdlet: str            # canonicalized lowercase cmdlet name, or "" if unknown
    raw: str               # the original stage text (whitespace-trimmed)
    has_dynamic: bool      # variable expansion, subexpression, call op, etc.
    has_redirect: bool = False  # output redirection (>, >>, 2>, *>, etc.)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_powershell(command: str) -> dict:
    """Classify a PowerShell command string.

    Returns a decision dict shaped the same way ``hook.handle_bash``'s
    return value is consumed: ``{"decision": ..., "reason": ...,
    "_meta": {...}, "human_reason": ...}``. The ``human_reason`` field
    is populated directly so the brand-message resolver in
    ``messages.enrich_decision`` does not rewrite the PowerShell-specific
    explanation into a generic one.
    """
    text = command.strip()
    if not text:
        return _decide_allow("empty command")

    statements = _split_statements(text)

    worst = "allow"
    reasons: list[str] = []
    stages_meta: list[dict] = []

    for statement in statements:
        stages = _parse_pipeline(statement)
        if not stages:
            continue
        decision, reason = _classify_pipeline(stages)
        worst = _stricter(worst, decision)
        if reason:
            reasons.append(reason)
        for s in stages:
            stages_meta.append({
                "cmdlet": s.cmdlet,
                "raw": s.raw,
                "has_dynamic": s.has_dynamic,
            })

    if worst == "allow":
        return _decide_allow("read-only PowerShell cmdlets only")
    if worst == "block":
        return _decide_block("; ".join(reasons) or "PowerShell command blocked")
    return _decide_ask("; ".join(reasons) or "PowerShell command needs review",
                       stages=stages_meta)


# ---------------------------------------------------------------------------
# Statement / pipeline splitting
# ---------------------------------------------------------------------------


def _split_statements(text: str) -> list[str]:
    """Split on ``;`` and newlines, respecting quoted runs and braces."""
    parts: list[str] = []
    current: list[str] = []
    depth_brace = 0
    depth_paren = 0
    i = 0
    in_str: str = ""  # '"' or "'" or ""
    while i < len(text):
        ch = text[i]
        if in_str:
            current.append(ch)
            # PS single-quoted strings have no escape sequences; double-
            # quoted strings allow `` ` `` as an escape character. Treat
            # backtick + any char as a single token to avoid breaking
            # on `;` or `|` inside quotes.
            if ch == "`" and in_str == '"' and i + 1 < len(text):
                current.append(text[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = ""
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            current.append(ch)
            i += 1
            continue
        if ch == "{":
            depth_brace += 1
            current.append(ch)
            i += 1
            continue
        if ch == "}":
            depth_brace = max(0, depth_brace - 1)
            current.append(ch)
            i += 1
            continue
        if ch == "(":
            depth_paren += 1
            current.append(ch)
            i += 1
            continue
        if ch == ")":
            depth_paren = max(0, depth_paren - 1)
            current.append(ch)
            i += 1
            continue
        if (ch == ";" or ch == "\n") and depth_brace == 0 and depth_paren == 0:
            parts.append("".join(current).strip())
            current = []
            i += 1
            continue
        # PowerShell 7+ chain operators `&&` (run-if-success) and `||`
        # (run-if-failure) are statement separators, not pipelines. A
        # token sequence like `Get-Date && Remove-Item -Recurse /` is
        # two distinct statements that the classifier must inspect
        # independently; otherwise the right-hand side hides behind
        # the safe-looking left-hand side.
        if (ch in ("&", "|")
                and i + 1 < len(text)
                and text[i + 1] == ch
                and depth_brace == 0
                and depth_paren == 0):
            parts.append("".join(current).strip())
            current = []
            i += 2
            continue
        current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def _parse_pipeline(statement: str) -> list[_Stage]:
    """Split a single statement on ``|`` respecting quotes/braces, then
    classify each stage's cmdlet."""
    stages_raw: list[str] = []
    current: list[str] = []
    depth_brace = 0
    depth_paren = 0
    in_str = ""
    i = 0
    while i < len(statement):
        ch = statement[i]
        if in_str:
            current.append(ch)
            if ch == "`" and in_str == '"' and i + 1 < len(statement):
                current.append(statement[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = ""
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            current.append(ch)
            i += 1
            continue
        if ch == "{":
            depth_brace += 1
            current.append(ch)
            i += 1
            continue
        if ch == "}":
            depth_brace = max(0, depth_brace - 1)
            current.append(ch)
            i += 1
            continue
        if ch == "(":
            depth_paren += 1
            current.append(ch)
            i += 1
            continue
        if ch == ")":
            depth_paren = max(0, depth_paren - 1)
            current.append(ch)
            i += 1
            continue
        # The pipeline operator is the single `|`. PowerShell 7's `||`
        # short-circuit chain operator looks similar but is a
        # statement separator, not a pipeline stage — it is handled
        # in _split_statements and never reaches this function.
        if ch == "|" and depth_brace == 0 and depth_paren == 0:
            stages_raw.append("".join(current).strip())
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        stages_raw.append(tail)
    return [_parse_stage(s) for s in stages_raw if s]


# ---------------------------------------------------------------------------
# Stage analysis
# ---------------------------------------------------------------------------


_DYNAMIC_MARKERS = (
    "$(",   # subexpression
    "@(",   # array subexpression
    "${",   # quoted variable name
    "& ",   # call operator at statement start (with space)
    "&",    # call operator (looser — we still detect)
    "`",    # PS escape character outside strings is unusual
)


def _parse_stage(stage_text: str) -> _Stage:
    """Extract the cmdlet name and dynamic-content flag for one stage.

    A stage is "dynamic" if anything inside it (outside quoted strings)
    could execute arbitrary code that the static check cannot inspect.
    The classifier conservatively marks the stage dynamic when it
    encounters:

    - script blocks ``{ ... }`` — the body is opaque code that
      Where-Object, ForEach-Object, Start-Job, calculated properties,
      and similar cmdlets evaluate at runtime,
    - type literals or member access ``[Namespace.Type]::Method``,
    - parenthesized expressions ``( ... )`` that may wrap a command,
    - the call operator ``& $var`` or ``& 'cmd'`` that runs a value
      as a command,
    - subexpressions ``$(...)``, array subexpressions ``@(...)``, and
      braced variable names ``${...}``.

    These are deliberately coarse: parens around a value
    (`-Path (Get-Location)`) are flagged the same as parens wrapping a
    dangerous expression. The cost is a false-positive ASK for
    legitimate uses; the benefit is that no hidden code execution
    slips through to ALLOW.
    """
    text = stage_text.strip()
    has_dynamic = False
    has_redirect = False
    cmdlet = ""

    # Walk character-by-character outside of single/double-quoted runs.
    # Inside a quoted string the same characters are literal and must
    # not trigger the dynamic markers.
    in_str = ""  # '"' or "'" or ""
    i = 0
    n = len(text)
    cmdlet_start = -1
    cmdlet_done = False

    while i < n:
        ch = text[i]
        if in_str:
            # Backtick escape inside double-quoted strings only.
            if ch == "`" and in_str == '"' and i + 1 < n:
                i += 2
                continue
            if ch == in_str:
                in_str = ""
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            i += 1
            continue

        # Output redirection. PowerShell uses `>`, `>>`, `2>`, `2>>`,
        # `*>`, `*>>`, plus stream-merge `n>&m` to write a pipeline's
        # output to a file or merge streams. Any of these in a stage
        # is a disk write the static check cannot inspect, regardless
        # of which cmdlet starts the stage.
        if ch == ">":
            has_redirect = True
            i += 1
            if i < n and text[i] == ">":
                i += 1
            continue
        if (ch in "123456*") and i + 1 < n and text[i + 1] == ">":
            has_redirect = True
            i += 2
            # Skip the optional second `>` (e.g., `2>>`) and
            # stream-merge target like `&1` in `2>&1`.
            if i < n and text[i] in (">", "&"):
                i += 1
                if i < n and text[i].isdigit():
                    i += 1
            continue

        # Subexpression markers: $(...), @(...), ${...}.
        if ch == "$" and i + 1 < n and text[i + 1] == "(":
            has_dynamic = True
            i += 2
            continue
        if ch == "@" and i + 1 < n and text[i + 1] == "(":
            has_dynamic = True
            i += 2
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "{":
            has_dynamic = True
            i += 2
            continue

        # Script block / type literal / parenthesized expression.
        if ch in ("{", "[", "("):
            has_dynamic = True
            i += 1
            continue

        # Call operator. A bare `&` outside quotes runs the next token
        # as a command. The chain operators `&&` and `||` are already
        # split off at the statement level, so any `&` reaching this
        # function is the call operator.
        if ch == "&":
            has_dynamic = True
            i += 1
            continue

        # Cmdlet name: the first non-whitespace token after any leading
        # `& ` (which we skip above) and after any variable assignment
        # (`$x = ...`). We capture it once.
        if not cmdlet_done and ch not in (" ", "\t", "\n"):
            if ch == "$":
                # Plain local variable assignment of the form `$name = ...`
                # is the only assignment pattern we treat as transparent;
                # `$env:Path = ...`, `$global:foo = ...`, and provider-
                # qualified variables are mutations that must be ASK-ed.
                # The split between "plain" and "scoped" is handled in a
                # separate commit.
                eq = text.find("=", i)
                if eq != -1 and eq < n - 1 and ":" not in text[i + 1: eq]:
                    i = eq + 1
                    while i < n and text[i] in (" ", "\t"):
                        i += 1
                    continue
                # Any non-assignment use of a variable as the first
                # token is dynamic — we cannot know what it expands to.
                has_dynamic = True
                cmdlet_done = True
                i += 1
                continue
            # Read the cmdlet token.
            cmdlet_start = i
            while i < n and text[i] not in (" ", "\t", "\n"):
                ch2 = text[i]
                if ch2 in ('"', "'", "{", "[", "(", "$", "@", "&", "`"):
                    break
                i += 1
            cmdlet = text[cmdlet_start:i].lower()
            cmdlet_done = True
            continue
        i += 1

    return _Stage(cmdlet=cmdlet, raw=text, has_dynamic=has_dynamic, has_redirect=has_redirect)


def _classify_pipeline(stages: list[_Stage]) -> tuple[str, str]:
    """Reduce a pipeline to a single (decision, reason) pair.

    A pipeline is only ALLOW if every stage's cmdlet is in the
    read-only safelist and no stage has dynamic content or output
    redirection. Any deny stage promotes the whole pipeline to
    BLOCK; any ask stage, unknown stage, or redirection demotes
    to ASK.
    """
    worst = "allow"
    reasons: list[str] = []

    # Special-case pipelines that end in iex or Invoke-Expression: that
    # always means "the previous stage's output gets evaluated", which
    # is a textbook curl-pipe-bash / iwr-pipe-iex pattern. Treat as
    # BLOCK even when the source is iwr (which is otherwise ASK).
    if stages and stages[-1].cmdlet in {"iex", "invoke-expression"}:
        return "block", (
            "PowerShell pipes output into Invoke-Expression "
            "(remote code execution pattern)"
        )

    for s in stages:
        if s.has_redirect:
            worst = _stricter(worst, "ask")
            reasons.append(
                "PowerShell uses output redirection nah cannot inspect "
                f"(stage: {_truncate(s.raw)})"
            )
            continue
        if s.has_dynamic:
            worst = _stricter(worst, "ask")
            reasons.append(
                "PowerShell uses dynamic content nah cannot inspect "
                f"(stage: {_truncate(s.raw)})"
            )
            continue
        if not s.cmdlet:
            worst = _stricter(worst, "ask")
            reasons.append(
                f"PowerShell stage with no recognizable cmdlet: {_truncate(s.raw)}"
            )
            continue
        if s.cmdlet in _DENY_CMDLETS:
            worst = _stricter(worst, "block")
            reasons.append(
                f"PowerShell cmdlet not permitted: {s.cmdlet}"
            )
            continue
        if s.cmdlet in _ASK_CMDLETS:
            worst = _stricter(worst, "ask")
            reasons.append(
                f"PowerShell cmdlet needs review: {s.cmdlet}"
            )
            continue
        if s.cmdlet in _SAFE_CMDLETS:
            continue
        worst = _stricter(worst, "ask")
        reasons.append(
            f"unrecognized PowerShell cmdlet: {s.cmdlet}"
        )

    if worst == "allow":
        return "allow", ""
    return worst, "; ".join(reasons)


def _truncate(text: str, limit: int = 60) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "\u2026"


# ---------------------------------------------------------------------------
# Decision builders
# ---------------------------------------------------------------------------


_STRICTNESS = {"allow": 0, "ask": 1, "block": 2}


def _stricter(a: str, b: str) -> str:
    return a if _STRICTNESS[a] >= _STRICTNESS[b] else b


def _decide_allow(reason: str) -> dict:
    return {
        "decision": "allow",
        "_meta": {"stages": [{
            "action_type": "powershell_safe",
            "decision": "allow",
            "policy": "allow",
            "reason": reason,
        }]},
    }


def _decide_ask(reason: str, *, stages: list[dict] | None = None) -> dict:
    return {
        "decision": "ask",
        "reason": reason,
        "human_reason": reason,
        "_meta": {"stages": stages or [{
            "action_type": "powershell_unknown",
            "decision": "ask",
            "policy": "ask",
            "reason": reason,
        }]},
    }


def _decide_block(reason: str) -> dict:
    return {
        "decision": "block",
        "reason": reason,
        "human_reason": reason,
        "_meta": {"stages": [{
            "action_type": "powershell_dangerous",
            "decision": "block",
            "policy": "block",
            "reason": reason,
        }]},
    }
