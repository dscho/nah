"""Tests for the ``nah run copilot`` launcher.

The launcher has three responsibilities, and the tests are organized
around them:

- *Argv validation*: every Copilot CLI flag that auto-approves tool
  use must surface as ``CopilotRunError`` before the binary is
  exec'd. The same applies to the ``COPILOT_ALLOW_ALL`` env var.
- *PATH lookup*: ``copilot`` must be on PATH or the launcher exits
  with an actionable error.
- *Healthcheck*: a session-scoped hook (an ``~/.copilot/hooks/`` JSON
  file referencing ``nah.cli _copilot-pre-tool-use``) must exist
  and not be disabled before the launcher hands off to Copilot.

The tests use ``build_copilot_launch`` rather than ``run_copilot``
because the latter calls ``os.execvpe`` on success, which is hard
to drive from a unit test without leaving the test process behind.
``run_copilot``'s own error-printing wrapper is covered by a small
integration test at the end.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from nah import copilot_run
from nah.copilot_run import (
    CopilotRunError,
    build_copilot_launch,
    run_copilot,
)


@pytest.fixture
def hook_installed(tmp_path, monkeypatch):
    """Create a valid Copilot hook directory and pin COPILOT_HOME at it.

    Returns the hooks_dir path so individual tests can mutate the
    nah.json file (or replace it with a foreign one) when they need
    to exercise the healthcheck's negative paths.
    """
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path))
    hooks_dir = tmp_path / "hooks"
    hooks_dir.mkdir()
    hook_file = hooks_dir / "nah.json"
    hook_file.write_text(json.dumps({
        "version": 1,
        "hooks": {
            "PreToolUse": [{
                "type": "command",
                "bash": "python3 -m nah.cli _copilot-pre-tool-use",
            }],
        },
    }), encoding="utf-8")
    return hooks_dir


def _stub_copilot_on_path(monkeypatch, tmp_path):
    """Make shutil.which('copilot') return a path so PATH lookup succeeds."""
    fake = tmp_path / "fake-copilot"
    fake.write_text("#!/bin/sh\necho stub\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setattr(
        copilot_run.shutil, "which",
        lambda name: str(fake) if name == "copilot" else None,
    )
    return fake


# ---------------------------------------------------------------------------
# Argv validation — every documented bypass flag must reject.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", [
    "--allow-all",
    "--allow-all-tools",
    "--allow-all-paths",
    "--allow-all-urls",
    "--yolo",
])
def test_bypass_flags_are_rejected(flag, hook_installed, tmp_path, monkeypatch) -> None:
    """Every documented Copilot bypass flag refuses to launch.

    The five flags here are the union of the "Permissive options" the
    Copilot CLI command reference documents. Each one disables some
    layer of the approval surface that nah relies on; running under
    any of them would let Copilot execute tools without prompting
    nah's hook.
    """
    _stub_copilot_on_path(monkeypatch, tmp_path)
    with pytest.raises(CopilotRunError) as exc:
        build_copilot_launch([flag])
    msg = str(exc.value)
    assert flag in msg
    assert "permission bypass" in msg


@pytest.mark.parametrize("flag", [
    "--allow-all=true",
    "--allow-all-tools=value",
    "--yolo=anything",
])
def test_bypass_flag_with_value_is_rejected(flag, hook_installed, tmp_path, monkeypatch) -> None:
    """The ``--flag=value`` form of a bypass flag is also rejected.

    Copilot itself does not currently accept value forms for these
    flags, but a future SDK change that did would otherwise slip
    past a simple ``in _BYPASS_FLAGS`` membership check.
    """
    _stub_copilot_on_path(monkeypatch, tmp_path)
    with pytest.raises(CopilotRunError):
        build_copilot_launch([flag])


def test_bypass_env_var_is_rejected(hook_installed, tmp_path, monkeypatch) -> None:
    """``COPILOT_ALLOW_ALL`` in the environment refuses to launch.

    Per the Copilot CLI command reference, this env var is the
    documented equivalent of ``--allow-all-tools``; a flag check
    alone would let a user set it in their shell rc and silently
    re-enable the bypass.
    """
    _stub_copilot_on_path(monkeypatch, tmp_path)
    with pytest.raises(CopilotRunError) as exc:
        build_copilot_launch(
            [],
            base_env={"COPILOT_ALLOW_ALL": "1", "PATH": str(tmp_path)},
        )
    assert "COPILOT_ALLOW_ALL" in str(exc.value)


def test_double_dash_does_not_protect_user_flags(hook_installed, tmp_path, monkeypatch) -> None:
    """``--`` terminates the scan so payload args are passed through.

    A safe user payload like ``-- "echo --yolo"`` is part of a
    prompt; the literal flag string after ``--`` must not be
    interpreted as a launcher flag. Note that we cannot exec the
    real binary in tests, so we assert the build path succeeds
    instead.
    """
    _stub_copilot_on_path(monkeypatch, tmp_path)
    launch = build_copilot_launch(["--", "echo --yolo"])
    assert "--yolo" not in launch.argv[1:][0]  # not a flag in argv[1]
    assert launch.argv[1:] == ["--", "echo --yolo"]


def test_non_bypass_flag_passes_through(hook_installed, tmp_path, monkeypatch) -> None:
    """Flags Copilot accepts for normal use are forwarded unchanged."""
    _stub_copilot_on_path(monkeypatch, tmp_path)
    launch = build_copilot_launch(["--model", "claude-sonnet-4.5", "--no-banner"])
    assert launch.argv[1:] == ["--model", "claude-sonnet-4.5", "--no-banner"]


# ---------------------------------------------------------------------------
# PATH lookup — copilot must be installed.
# ---------------------------------------------------------------------------


def test_missing_copilot_binary_fails_with_actionable_message(
    hook_installed, monkeypatch,
) -> None:
    """``copilot`` not found on PATH surfaces a single-line error."""
    monkeypatch.setattr(copilot_run.shutil, "which", lambda name: None)
    with pytest.raises(CopilotRunError) as exc:
        build_copilot_launch([])
    assert "'copilot' not found on PATH" in str(exc.value)


def test_copilot_path_override_skips_which(hook_installed, tmp_path, monkeypatch) -> None:
    """Caller-supplied ``copilot_path`` short-circuits the PATH lookup.

    Used by tests and by integrations that pin a specific binary.
    """
    monkeypatch.setattr(copilot_run.shutil, "which",
                        lambda name: pytest.fail("should not be called"))
    fake = str(tmp_path / "specific-copilot")
    launch = build_copilot_launch([], copilot_path=fake)
    assert launch.argv[0] == fake


# ---------------------------------------------------------------------------
# Healthcheck — verify the hook is installed and not disabled.
# ---------------------------------------------------------------------------


def test_healthcheck_succeeds_when_hook_is_installed(
    hook_installed, tmp_path, monkeypatch,
) -> None:
    """The standard hook_installed fixture produces a passing healthcheck."""
    _stub_copilot_on_path(monkeypatch, tmp_path)
    launch = build_copilot_launch([])
    assert launch.argv[0].endswith("fake-copilot")


def test_healthcheck_fails_when_no_hook_file_present(tmp_path, monkeypatch) -> None:
    """Empty COPILOT_HOME refuses to launch with an install hint.

    Pinning the actionable error so an upgrade that broke the
    healthcheck would surface a clear test failure rather than
    silently letting users launch unguarded sessions.
    """
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path))  # no hooks/ dir
    _stub_copilot_on_path(monkeypatch, tmp_path)
    with pytest.raises(CopilotRunError) as exc:
        build_copilot_launch([])
    assert "nah install copilot" in str(exc.value)


def test_healthcheck_rejects_disabled_hook_file(
    hook_installed, tmp_path, monkeypatch,
) -> None:
    """``disableAllHooks: true`` in the hook file refuses to launch.

    A hook file with disableAllHooks set is functionally absent.
    Letting the launch proceed would expose the user to an
    unguarded session under the nah brand.
    """
    _stub_copilot_on_path(monkeypatch, tmp_path)
    hook_file = hook_installed / "nah.json"
    data = json.loads(hook_file.read_text(encoding="utf-8"))
    data["disableAllHooks"] = True
    hook_file.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CopilotRunError) as exc:
        build_copilot_launch([])
    assert "disableAllHooks" in str(exc.value)


def test_healthcheck_rejects_disabled_in_settings_json(
    hook_installed, tmp_path, monkeypatch,
) -> None:
    """``disableAllHooks: true`` in user settings.json also refuses.

    The user-level settings file can disable every Copilot hook
    across the user, including nah. The launcher refuses with an
    explicit error message rather than silently launching.
    """
    _stub_copilot_on_path(monkeypatch, tmp_path)
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"disableAllHooks": True}), encoding="utf-8")
    with pytest.raises(CopilotRunError) as exc:
        build_copilot_launch([])
    assert "disableAllHooks" in str(exc.value)


def test_healthcheck_accepts_inline_hook_in_settings(
    tmp_path, monkeypatch,
) -> None:
    """An inline ``hooks`` block in settings.json counts as installed.

    Copilot CLI merges inline hooks from settings.json with files
    in the hooks directory, so a user who chose to install nah's
    hook inline rather than as a standalone file should still be
    able to launch.
    """
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path))
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [{
                "type": "command",
                "bash": "python3 -m nah.cli _copilot-pre-tool-use",
            }],
        },
    }), encoding="utf-8")
    _stub_copilot_on_path(monkeypatch, tmp_path)
    launch = build_copilot_launch([])
    assert launch is not None


def test_healthcheck_rejects_foreign_hook_file(
    tmp_path, monkeypatch,
) -> None:
    """A hook directory with no nah-referencing entry refuses to launch.

    Even when a non-nah hook is present in
    ``$COPILOT_HOME/hooks/``, the launcher refuses because nah's
    guard is what the user invoked. The error names ``nah install
    copilot`` as the remedy.
    """
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path))
    hooks_dir = tmp_path / "hooks"
    hooks_dir.mkdir()
    foreign = hooks_dir / "something_else.json"
    foreign.write_text(json.dumps({
        "version": 1,
        "hooks": {
            "PreToolUse": [{
                "type": "command",
                "bash": "echo unrelated",
            }],
        },
    }), encoding="utf-8")
    _stub_copilot_on_path(monkeypatch, tmp_path)
    with pytest.raises(CopilotRunError) as exc:
        build_copilot_launch([])
    assert "nah install copilot" in str(exc.value)


def test_healthcheck_rejects_unparseable_hook_file(
    tmp_path, monkeypatch,
) -> None:
    """A malformed hook JSON refuses to launch and tells the user to update.

    Failing closed avoids the surprising case where a previously
    valid hook file has been corrupted and the user does not notice
    the silent fallthrough to unguarded execution.
    """
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path))
    hooks_dir = tmp_path / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / "nah.json").write_text("{not json at all", encoding="utf-8")
    _stub_copilot_on_path(monkeypatch, tmp_path)
    with pytest.raises(CopilotRunError) as exc:
        build_copilot_launch([])
    assert "nah update copilot" in str(exc.value)


def test_healthcheck_can_be_skipped_for_dry_runs(
    tmp_path, monkeypatch,
) -> None:
    """skip_healthcheck bypasses the install requirement.

    The flag exists for tests that drive the rest of the launcher
    without setting up a full COPILOT_HOME, and for future tooling
    like ``nah doctor copilot`` that wants to inspect the build
    without enforcing it.
    """
    _stub_copilot_on_path(monkeypatch, tmp_path)
    # No hook file exists; with the skip we still build a launch.
    launch = build_copilot_launch([], skip_healthcheck=True)
    assert launch.argv[0].endswith("fake-copilot")


def test_healthcheck_honors_copilot_home_change(
    tmp_path, monkeypatch,
) -> None:
    """Setting COPILOT_HOME relocates the healthcheck target.

    A user who runs with COPILOT_HOME=/elsewhere expects nah's hook
    to be looked up under /elsewhere/hooks/, not in the default
    ~/.copilot/hooks/. The healthcheck reads the env at call time.
    """
    home1 = tmp_path / "home1"
    home2 = tmp_path / "home2"
    home1.mkdir()
    home2.mkdir()
    (home1 / "hooks").mkdir()
    (home1 / "hooks" / "nah.json").write_text(json.dumps({
        "version": 1,
        "hooks": {
            "PreToolUse": [{
                "type": "command",
                "bash": "python3 -m nah.cli _copilot-pre-tool-use",
            }],
        },
    }), encoding="utf-8")
    _stub_copilot_on_path(monkeypatch, tmp_path)

    # COPILOT_HOME=home1 → succeeds.
    build_copilot_launch([], base_env={"COPILOT_HOME": str(home1), "PATH": str(tmp_path)})

    # COPILOT_HOME=home2 → no hook installed → fails.
    with pytest.raises(CopilotRunError):
        build_copilot_launch([], base_env={"COPILOT_HOME": str(home2), "PATH": str(tmp_path)})


# ---------------------------------------------------------------------------
# run_copilot — top-level error wrapper.
# ---------------------------------------------------------------------------


def test_run_copilot_prints_and_exits_on_failure(
    capsys, tmp_path, monkeypatch,
) -> None:
    """run_copilot prints CopilotRunError to stderr and returns 1.

    The launcher is invoked from cli.py, which exits with this
    return code. Pinning the integration here so a future
    refactor of the error path does not silently change the exit
    code an upstream user sees.
    """
    monkeypatch.setattr(copilot_run.shutil, "which", lambda name: None)
    code = run_copilot([])
    assert code == 1
    captured = capsys.readouterr()
    assert "'copilot' not found on PATH" in captured.err


def test_run_copilot_prints_bypass_rejection(capsys, monkeypatch, tmp_path) -> None:
    """run_copilot surfaces the bypass-flag rejection to stderr."""
    _stub_copilot_on_path(monkeypatch, tmp_path)
    # No COPILOT_HOME — healthcheck would also fire, but the flag
    # check runs first.
    code = run_copilot(["--yolo"])
    assert code == 1
    captured = capsys.readouterr()
    assert "--yolo" in captured.err
