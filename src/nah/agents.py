"""Agent support — tool name mapping, agent detection, output formatting.

Supports Claude Code hooks, Codex permission-hook logging, and GitHub
Copilot CLI preToolUse hooks. The hook script detects the calling agent
from payload fields and formats output accordingly.
"""

from pathlib import Path
import sys

from nah.messages import brand

# ---------------------------------------------------------------------------
# Tool name → canonical handler name
# ---------------------------------------------------------------------------

TOOL_MAP: dict[str, str] = {
    # Claude Code (canonical — identity mapping)
    "Bash": "Bash",
    "Read": "Read",
    "Write": "Write",
    "Edit": "Edit",
    "MultiEdit": "MultiEdit",
    "NotebookEdit": "NotebookEdit",
    "Glob": "Glob",
    "Grep": "Grep",
}


# Per-agent tool-name normalization tables.
# Kept separate from the global TOOL_MAP so a Copilot lowercase name like
# "grep" cannot accidentally bypass a future Claude-side handler keyed on
# the same lowercase token, and vice versa.
_AGENT_TOOL_MAPS: dict[str, dict[str, str]] = {
    # Claude Code uses PascalCase identity mapping (same as TOOL_MAP).
    "claude": dict(TOOL_MAP),
    # Codex shares Claude tool names plus apply_patch.
    "codex": {**TOOL_MAP, "apply_patch": "apply_patch"},
    # GitHub Copilot CLI uses lowercase tool names; map them to nah's
    # canonical handler names. See:
    # https://docs.github.com/en/copilot/reference/hooks-reference#tool-names-for-hook-matching
    "copilot": {
        "bash": "Bash",
        # NOTE: powershell maps to a placeholder canonical, not Bash.
        # PowerShell has fundamentally different syntax from POSIX shells:
        # object pipelines, cmdlets (Remove-Item vs rm), named parameters,
        # `;`-separated statements, no $IFS word-splitting, etc. Routing it
        # through the Bash classifier would either miss real threats (e.g.
        # `Remove-Item -Recurse -Force /`) or produce false positives. Until
        # a real PowerShell classifier exists, the copilot_hooks dispatcher
        # treats this canonical as ASK by default. See plan.md
        # "MUST-DO: real PowerShell classifier".
        "powershell": "PowerShell",
        "view": "Read",
        "create": "Write",
        "edit": "Edit",
        "glob": "Glob",
        "grep": "Grep",
        # Copilot-specific tools with no Claude analog:
        "web_fetch": "web_fetch",
        "task": "task",
        "ask_user": "ask_user",
    },
}


def normalize_tool(tool_name: str, agent: str = "") -> str:
    """Map agent-specific tool name to canonical handler name.

    When ``agent`` is provided, uses the per-agent mapping table.
    When omitted (legacy callers), falls back to the shared TOOL_MAP for
    backward compatibility.
    """
    if agent:
        agent_map = _AGENT_TOOL_MAPS.get(agent)
        if agent_map is not None:
            return agent_map.get(tool_name, tool_name)
    return TOOL_MAP.get(tool_name, tool_name)


# ---------------------------------------------------------------------------
# Agent detection
# ---------------------------------------------------------------------------

# Agent type constants
CLAUDE = "claude"
CODEX = "codex"
COPILOT = "copilot"


def detect_agent(data) -> str:
    """Detect which agent is calling.

    Accepts either a full payload dict or a bare tool name string.
    """
    return CLAUDE


# ---------------------------------------------------------------------------
# Output formatting per agent
# ---------------------------------------------------------------------------

def format_block(reason: str, agent: str) -> dict:
    """Format a block/deny response for the given agent."""
    branded = brand(
        "nah blocked",
        reason or "this was blocked before it could run",
        color=_agent_color_mode(agent),
        assume_tty=agent == CLAUDE,
    )
    if agent == COPILOT:
        # Copilot CLI preToolUse expects a bare top-level object — no
        # hookSpecificOutput envelope.
        # https://docs.github.com/en/copilot/reference/hooks-reference#pretooluse-decision-control
        result: dict = {"permissionDecision": "deny"}
        if branded:
            result["permissionDecisionReason"] = branded
        return result
    result: dict = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}}
    if branded:
        result["hookSpecificOutput"]["permissionDecisionReason"] = branded
    return result


def format_ask(reason: str, agent: str, system_message: str = "") -> dict:
    """Format an ask/confirm response for the given agent."""
    branded = brand(
        "nah paused",
        reason or "this needs confirmation before it can run",
        color=_agent_color_mode(agent),
        assume_tty=agent == CLAUDE,
    )
    if agent == COPILOT:
        result: dict = {"permissionDecision": "ask"}
        if branded:
            result["permissionDecisionReason"] = branded
        # Copilot has no equivalent of Claude's top-level systemMessage,
        # so the reason carries the only user-visible signal. The
        # system_message is therefore dropped for Copilot.
        return result
    result: dict = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}}
    if branded:
        result["hookSpecificOutput"]["permissionDecisionReason"] = branded
    if system_message:
        result["systemMessage"] = system_message  # top-level, shown to user
    return result


def format_allow(agent: str) -> dict:
    """Format an allow response for the given agent."""
    if agent == COPILOT:
        return {"permissionDecision": "allow"}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}


def format_error(error: str, agent: str) -> dict:
    """Format an error response (deny with error message)."""
    msg = (
        f"nah: internal error — blocked for safety: {error}\n"
        "      To bypass: nah uninstall | To debug: nah log --tail"
    )
    if agent == COPILOT:
        return {"permissionDecision": "deny", "permissionDecisionReason": msg}
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": msg,
    }}


def _agent_color_mode(agent: str) -> str:
    """Return the configured color mode for agent prompt messages."""
    if agent != CLAUDE:
        return "never"
    try:
        from nah.config import get_config
        return get_config().ui_color
    except Exception as exc:
        sys.stderr.write(f"nah: config: ui.color: {exc}\n")
        return "never"


# ---------------------------------------------------------------------------
# Agent install configs
# ---------------------------------------------------------------------------

# Per-agent tool matchers for hook registration.
AGENT_TOOL_MATCHERS: dict[str, list[str]] = {
    CLAUDE: ["Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "mcp__.*"],
}

# Settings/hooks file paths per agent.
AGENT_SETTINGS: dict[str, Path] = {
    CLAUDE: Path.home() / ".claude" / "settings.json",
}


def copilot_hooks_dir() -> Path:
    """Return the Copilot CLI user-level hooks directory.

    Honors COPILOT_HOME when set, otherwise defaults to ~/.copilot/hooks/.
    See:
    https://docs.github.com/en/copilot/reference/hooks-configuration#hooks-locations
    """
    import os

    home = os.environ.get("COPILOT_HOME") or str(Path.home() / ".copilot")
    return Path(home) / "hooks"


def copilot_settings_path() -> Path:
    """Return the Copilot CLI user-level settings.json path."""
    import os

    home = os.environ.get("COPILOT_HOME") or str(Path.home() / ".copilot")
    return Path(home) / "settings.json"


# Agents whose config format we can auto-install into.
INSTALLABLE_AGENTS = {CLAUDE, COPILOT}

AGENT_NAMES: dict[str, str] = {
    CLAUDE: "Claude Code",
    CODEX: "OpenAI Codex",
    COPILOT: "GitHub Copilot CLI",
}

