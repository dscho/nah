"""Launcher for `nah run copilot`.

GitHub Copilot CLI loads preToolUse hooks from ``~/.copilot/hooks/*.json``
(or ``$COPILOT_HOME/hooks/``). There is no ``--settings <json>`` or
``--hooks <file>`` flag, so unlike ``nah run claude`` we cannot inject a
session-scoped hook on the command line. Instead, ``nah run copilot``:

1. Validates argv and rejects bypass flags
   (``--allow-all``, ``--allow-all-tools``, ``--allow-all-paths``,
   ``--allow-all-urls``, ``--yolo``) so the user cannot launch an
   auto-approval session under the nah brand.
2. Verifies that ``nah install copilot`` has wired the preToolUse hook
   correctly and that no ``disableAllHooks: true`` setting overrides
   it. Fails closed with an actionable error otherwise.
3. ``execvp``s ``copilot`` with the validated arguments.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from nah import agents


class CopilotRunError(Exception):
    """Raised when `nah run copilot` cannot safely launch Copilot CLI."""


@dataclass(frozen=True)
class CopilotLaunch:
    argv: list[str]
    env: dict[str, str]


# Bypass flags. See the Copilot CLI command reference:
# https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference
# https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools
_BYPASS_FLAGS = {
    "--allow-all",
    "--allow-all-tools",
    "--allow-all-paths",
    "--allow-all-urls",
    "--yolo",
}

# Env var equivalent of --allow-all-tools per the same reference.
_BYPASS_ENV = "COPILOT_ALLOW_ALL"


def build_copilot_launch(
    user_args: list[str],
    *,
    copilot_path: str | None = None,
    base_env: dict[str, str] | None = None,
    skip_healthcheck: bool = False,
) -> CopilotLaunch:
    """Build a validated Copilot CLI launch plan with nah's hook verified."""
    executable = copilot_path or shutil.which("copilot")
    if executable is None:
        raise CopilotRunError("nah run copilot: 'copilot' not found on PATH")

    args = list(user_args)
    _reject_bypass_flags(args)

    env = dict(base_env if base_env is not None else os.environ)
    if env.get(_BYPASS_ENV):
        raise CopilotRunError(
            f"nah run copilot: {_BYPASS_ENV} is set in the environment. "
            "That env var auto-approves every tool, which defeats nah. "
            f"Unset {_BYPASS_ENV} and re-run."
        )

    if not skip_healthcheck:
        _healthcheck(env)

    return CopilotLaunch(argv=[executable] + args, env=env)


def run_copilot(user_args: list[str]) -> int:
    """Validate and exec Copilot CLI under nah's preToolUse hook."""
    try:
        launch = build_copilot_launch(user_args)
    except CopilotRunError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if os.name == "nt":
        return subprocess.call(launch.argv, env=launch.env)
    os.execvpe(
        launch.argv[0],
        [os.path.basename(launch.argv[0])] + launch.argv[1:],
        launch.env,
    )
    return 127


# ---------------------------------------------------------------------------
# Argv validation
# ---------------------------------------------------------------------------


def _reject_bypass_flags(args: list[str]) -> None:
    """Reject Copilot bypass flags that would defeat nah."""
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            return
        # Direct match (e.g. --yolo).
        if tok in _BYPASS_FLAGS:
            raise CopilotRunError(_bypass_message(tok))
        # `--flag=value` form. Some Copilot bypass flags do not take a
        # value but other flags do, so we match prefix on the bypass set
        # rather than splitting blindly.
        for flag in _BYPASS_FLAGS:
            if tok.startswith(flag + "="):
                raise CopilotRunError(_bypass_message(flag))
        i += 1


def _bypass_message(flag: str) -> str:
    return (
        f"nah run copilot: {flag} is not allowed because nah cannot "
        "protect a Copilot CLI session launched with permission bypass "
        "enabled. Run `nah run copilot` without that flag, or run "
        "`copilot` directly if you intentionally want an unguarded "
        "session."
    )


# ---------------------------------------------------------------------------
# Healthcheck — install-required mode
# ---------------------------------------------------------------------------


_NAH_HOOK_MARKER = "nah.cli _copilot-pre-tool-use"


def _healthcheck(env: dict[str, str]) -> None:
    """Verify nah's preToolUse hook is installed and not disabled.

    Fails closed (raises CopilotRunError) when:
      - no hook file is present, or
      - the hook file does not invoke nah's _copilot-pre-tool-use entry, or
      - any hook file or settings file sets disableAllHooks: true.

    The healthcheck reads the user-level hooks dir under
    ``$COPILOT_HOME/hooks/`` (or ``~/.copilot/hooks/``) and the
    user-level settings file at the corresponding settings.json path.
    Repo-level ``.github/hooks/*.json`` and ``.github/copilot/settings.json``
    are intentionally not inspected: ``nah run copilot`` is a per-user
    runtime guarantee, not a repo-policy guarantee.
    """
    copilot_home = env.get("COPILOT_HOME") or str(Path.home() / ".copilot")
    hooks_dir = Path(copilot_home) / "hooks"
    settings_path = Path(copilot_home) / "settings.json"

    found_nah_hook = False
    for hooks_file in _safe_glob_json(hooks_dir):
        try:
            data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CopilotRunError(
                f"nah run copilot: cannot parse Copilot hook file "
                f"{hooks_file}: {exc}\n     Re-run `nah update copilot`."
            )
        if not isinstance(data, dict):
            continue
        if data.get("disableAllHooks") is True:
            raise CopilotRunError(
                f"nah run copilot: {hooks_file} sets "
                "disableAllHooks: true. nah cannot guard a Copilot "
                "session while hooks are disabled. Remove that flag "
                "or run `copilot` directly."
            )
        hooks_block = data.get("hooks", {})
        pre_tool_use = (
            hooks_block.get("preToolUse")
            if isinstance(hooks_block, dict)
            else None
        ) or (
            hooks_block.get("PreToolUse")
            if isinstance(hooks_block, dict)
            else None
        )
        if isinstance(pre_tool_use, list):
            for entry in pre_tool_use:
                if _entry_contains_nah(entry):
                    found_nah_hook = True
                    break
        if found_nah_hook:
            break

    # The user-level settings.json may either disable all hooks or
    # carry its own inline preToolUse stanza.
    if settings_path.exists():
        try:
            settings_data = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CopilotRunError(
                f"nah run copilot: cannot parse {settings_path}: {exc}\n"
                "     Fix the file or run `nah update copilot`."
            )
        if isinstance(settings_data, dict):
            if settings_data.get("disableAllHooks") is True:
                raise CopilotRunError(
                    f"nah run copilot: {settings_path} sets "
                    "disableAllHooks: true. That disables every Copilot "
                    "hook for sessions in this user, including nah. "
                    "Remove that flag or run `copilot` directly."
                )
            hooks_block = settings_data.get("hooks", {})
            if isinstance(hooks_block, dict):
                pre_tool_use = (
                    hooks_block.get("preToolUse")
                    or hooks_block.get("PreToolUse")
                )
                if isinstance(pre_tool_use, list):
                    for entry in pre_tool_use:
                        if _entry_contains_nah(entry):
                            found_nah_hook = True
                            break

    if not found_nah_hook:
        raise CopilotRunError(
            "nah run copilot: nah's preToolUse hook is not installed.\n"
            "     Run `nah install copilot` first."
        )


def _safe_glob_json(directory: Path) -> list[Path]:
    """Return ``directory/*.json`` deterministically; empty if missing."""
    try:
        if not directory.is_dir():
            return []
        return sorted(p for p in directory.iterdir() if p.suffix == ".json" and p.is_file())
    except OSError:
        return []


def _entry_contains_nah(entry) -> bool:
    """Check whether a Copilot hook entry runs nah's preToolUse command."""
    if not isinstance(entry, dict):
        return False
    hooks_list = entry.get("hooks")
    if not isinstance(hooks_list, list):
        return False
    for h in hooks_list:
        if not isinstance(h, dict):
            continue
        for field in ("bash", "command", "powershell"):
            value = h.get(field)
            if isinstance(value, str) and _NAH_HOOK_MARKER in value:
                return True
    return False
