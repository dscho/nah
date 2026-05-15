"""GitHub Copilot CLI preToolUse hook adapter.

Copilot CLI fires the preToolUse hook before every tool call. The hook
reads a VS Code-compatible payload (configured under the PascalCase
event name ``PreToolUse``) on stdin and emits a bare top-level JSON
object on stdout that controls execution:

    {"permissionDecision": "allow" | "deny" | "ask",
     "permissionDecisionReason": "..."}

Unlike Claude's PreToolUse, Copilot's preToolUse is fail-open on
non-zero exit and on malformed output. Every error path therefore
emits a valid deny JSON with exit code 0 — never raise out of main().

See:
- https://docs.github.com/en/copilot/reference/hooks-reference
- https://docs.github.com/en/copilot/reference/hooks-configuration
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import time
from datetime import datetime, timezone

from nah import agents, hook, taxonomy
from nah.messages import enrich_decision


# Copilot tool names we have first-class handlers for. Other names fall
# through to _classify_unknown_tool via the canonical mapping in
# agents._AGENT_TOOL_MAPS["copilot"].
_NORMALIZE_DISPATCH = {
    "bash": "_normalize_bash",
    "view": "_normalize_view",
    "create": "_normalize_create",
    "edit": "_normalize_edit",
    "glob": "_normalize_glob",
    "grep": "_normalize_grep",
    "web_fetch": "_normalize_web_fetch",
    "powershell": "_normalize_passthrough",
    "task": "_normalize_passthrough",
    "ask_user": "_normalize_passthrough",
}


# Conservative allowlist of Copilot utility tools with no file or network
# side effects. These are UI labels, the tool-catalog search, the
# nah-managed memory store, read-only background-agent introspection, and
# static-documentation fetches. They never need a per-call user decision.
#
# Tools deliberately NOT on this list (and therefore still classified):
#   - write_bash / stop_bash: send input to or terminate a running bash
#     session, which can produce arbitrary side effects.
#   - manage_schedule: schedules recurring prompts that re-enter the agent
#     loop and may invoke any tool.
#   - web_search / web_fetch: data-exfil surfaces; web_fetch is already
#     routed through the synthetic-curl path on the Bash classifier.
#   - sql / session_store_sql: operate on user-visible state.
#   - mcp__* and any github-mcp-server-*: vary per server; defer to the
#     unknown-tool ASK path so the user explicitly approves.
_HARMLESS_COPILOT_TOOLS = frozenset({
    "ask_user",                        # prompts the user; never executes a tool
    "report_intent",                   # updates the visible "what I'm doing" label
    "tool_search_tool_regex",          # searches the available tool catalog by regex
    "store_memory",                    # writes to the nah-managed memory store
    "vote_memory",                     # votes on a memory store entry
    "fetch_copilot_cli_documentation", # fetches static Copilot CLI documentation
    "read_agent",                      # read-only background-agent introspection
    "list_agents",                     # read-only background-agent listing
    "list_bash",                       # read-only listing of running bash sessions
})


# Subagent-style Copilot tools. The spawned subagent's tool calls
# re-enter preToolUse (PreToolUseHooksProcessor in app.js;
# createSubagentSession inherits ``hooks: this.hooks``), so nah still
# classifies every real side effect on arrival. The same property holds
# for ``skill``: it dispatches a named skill that performs its work
# through further tool calls, each of which re-enters the hook.
_SUBAGENT_COPILOT_TOOLS = frozenset({"task", "skill"})


def main(stdin=None, stdout=None) -> int:
    """Handle a Copilot CLI preToolUse hook invocation.

    Copilot interprets stdout JSON as the permission decision. Any
    failure path emits a structured deny JSON; exit code is always 0
    so Copilot does not fail-open on non-zero exits.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    t0 = time.monotonic()

    raw = ""
    payload: dict = {}
    try:
        raw = stdin.read() or "{}"
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("payload was not a JSON object")
        payload = parsed
    except (json.JSONDecodeError, ValueError) as exc:
        _log_copilot_hook_error(f"invalid preToolUse payload: {exc}")
        _emit_fail_closed(stdout, f"invalid preToolUse payload: {exc}")
        return 0
    except Exception as exc:
        _log_copilot_hook_error(f"unexpected payload read failure: {exc}")
        _emit_fail_closed(stdout, f"unexpected payload read failure: {exc}")
        return 0

    try:
        decision, canonical, tool_input = _decide(payload)
    except Exception as exc:
        _log_copilot_hook_error(f"unexpected preToolUse decision error: {exc}")
        _emit_fail_closed(stdout, f"unexpected preToolUse decision error: {exc}")
        return 0

    try:
        _emit_decision(stdout, decision, canonical)
    except Exception as exc:
        _log_copilot_hook_error(f"emit_decision failed: {exc}")
        _emit_fail_closed(stdout, f"emit_decision failed: {exc}")
        return 0

    total_ms = int((time.monotonic() - t0) * 1000)
    try:
        _log_decision(canonical, tool_input, decision, total_ms, payload)
    except Exception as exc:
        # Logging failures must not change the decision already emitted.
        _log_copilot_hook_error(f"log decision failed: {exc}")
    return 0


# ---------------------------------------------------------------------------
# Payload normalization
# ---------------------------------------------------------------------------


def _extract_tool(payload: dict) -> tuple[str, dict, str]:
    """Extract (tool_name, tool_input, transcript_path) from either format.

    Supports both the VS Code-compatible payload (``tool_name`` /
    ``tool_input``) and the camelCase payload (``toolName`` /
    ``toolArgs``). ``transcript_path`` is best-effort — Copilot does
    not currently expose one for preToolUse, so empty is normal.
    """
    tool_name = ""
    raw_input: object = {}

    if "tool_name" in payload:
        tool_name = str(payload.get("tool_name") or "")
        raw_input = payload.get("tool_input", {})
    elif "toolName" in payload:
        tool_name = str(payload.get("toolName") or "")
        raw_input = payload.get("toolArgs", {})

    # Copilot may pass tool_input as a JSON string ("parsed from JSON
    # string when possible" per the docs). Decode defensively.
    if isinstance(raw_input, str):
        try:
            raw_input = json.loads(raw_input)
        except (json.JSONDecodeError, ValueError):
            raw_input = {"_raw": raw_input}
    if not isinstance(raw_input, dict):
        raw_input = {}

    transcript_path = str(
        payload.get("transcript_path")
        or payload.get("transcriptPath")
        or payload.get("session_id")
        or payload.get("sessionId")
        or ""
    )

    return tool_name, raw_input, transcript_path


def _normalize_bash(tool_input: dict) -> dict:
    """Copilot bash → {"command": ...} as expected by hook.handle_bash."""
    command = tool_input.get("command")
    if command is None:
        # Some Copilot SDK payloads have used `script` or `commandLine`.
        # Fall back deterministically; empty maps to ALLOW upstream.
        command = tool_input.get("script") or tool_input.get("commandLine") or ""
    return {"command": str(command)}


def _normalize_view(tool_input: dict) -> dict:
    """Copilot view → {"file_path": ...}. Field is documented as `path`."""
    path = tool_input.get("path") or tool_input.get("file_path") or ""
    return {"file_path": str(path)}


def _normalize_create(tool_input: dict) -> dict:
    """Copilot create → {"file_path": ..., "content": ...}."""
    path = tool_input.get("path") or tool_input.get("file_path") or ""
    content = (
        tool_input.get("content")
        if "content" in tool_input
        else tool_input.get("text", "")
    )
    return {"file_path": str(path), "content": str(content) if content is not None else ""}


def _normalize_edit(tool_input: dict) -> dict:
    """Copilot edit → {"file_path": ..., "new_string": ...}.

    Copilot's edit tool accepts a variety of shapes (single-edit, batch
    edits, or a full replacement). nah's Edit handler scans the
    proposed new content for credentials and dangerous patterns, so we
    flatten every replacement into one string for inspection.
    """
    path = tool_input.get("path") or tool_input.get("file_path") or ""
    if "new_string" in tool_input:
        new_text = tool_input.get("new_string") or ""
    elif "newText" in tool_input or "new_text" in tool_input:
        new_text = tool_input.get("newText") or tool_input.get("new_text") or ""
    elif "replacement" in tool_input:
        new_text = tool_input.get("replacement") or ""
    elif "content" in tool_input:
        new_text = tool_input.get("content") or ""
    elif "edits" in tool_input and isinstance(tool_input["edits"], list):
        parts: list[str] = []
        for e in tool_input["edits"]:
            if isinstance(e, dict):
                parts.append(
                    str(
                        e.get("new_string")
                        or e.get("newText")
                        or e.get("new_text")
                        or e.get("replacement")
                        or ""
                    )
                )
        new_text = "\n".join(parts)
    else:
        new_text = ""
    return {"file_path": str(path), "new_string": str(new_text)}


def _normalize_glob(tool_input: dict) -> dict:
    """Copilot glob → {"path": ...}."""
    path = tool_input.get("path") or tool_input.get("directory") or ""
    return {"path": str(path)}


def _normalize_grep(tool_input: dict) -> dict:
    """Copilot grep → {"path": ..., "pattern": ...}."""
    path = tool_input.get("path") or tool_input.get("directory") or ""
    pattern = tool_input.get("pattern") or tool_input.get("query") or ""
    return {"path": str(path), "pattern": str(pattern)}


def _normalize_web_fetch(tool_input: dict) -> dict:
    """Copilot web_fetch → emulate a Bash curl invocation for classification.

    nah's network classifier reasons about Bash tokens. Wrapping the
    requested URL in a synthetic ``curl <url>`` token list lets the
    existing network_outbound / trusted_hosts logic decide. The URL is
    quoted defensively to avoid shell metacharacter expansion in the
    tokenizer.
    """
    url = tool_input.get("url") or tool_input.get("uri") or ""
    return {"command": f"curl {json.dumps(str(url))}"}


def _normalize_passthrough(tool_input: dict) -> dict:
    """Pass through unchanged; used for tools handled out-of-band."""
    return dict(tool_input)


_NORMALIZERS = {
    "bash": _normalize_bash,
    "view": _normalize_view,
    "create": _normalize_create,
    "edit": _normalize_edit,
    "glob": _normalize_glob,
    "grep": _normalize_grep,
    "web_fetch": _normalize_web_fetch,
    "powershell": _normalize_passthrough,
    "task": _normalize_passthrough,
    "ask_user": _normalize_passthrough,
}


# ---------------------------------------------------------------------------
# Decision dispatch
# ---------------------------------------------------------------------------


def _decide(payload: dict) -> tuple[dict, str, dict]:
    """Return (decision, canonical_tool_name, normalized_tool_input)."""
    from nah.config import set_active_target

    set_active_target(agents.COPILOT, reset_cache=False)

    tool_name, raw_input, transcript_path = _extract_tool(payload)
    hook._transcript_path = transcript_path
    canonical = agents.normalize_tool(tool_name, agents.COPILOT)

    normalizer = _NORMALIZERS.get(tool_name, _normalize_passthrough)
    try:
        tool_input = normalizer(raw_input)
    except Exception as exc:
        _log_copilot_hook_error(
            f"normalizer failed for {tool_name!r}: {exc}"
        )
        # Fail closed: deny rather than dispatch with a garbage tool_input.
        return (
            {
                "decision": taxonomy.BLOCK,
                "reason": (
                    f"normalizer failed for Copilot tool {tool_name!r}: {exc}"
                ),
                "_meta": {"stages": [{
                    "action_type": taxonomy.UNKNOWN,
                    "decision": taxonomy.BLOCK,
                    "policy": taxonomy.BLOCK,
                    "reason": "copilot normalizer failed",
                }]},
            },
            canonical,
            raw_input if isinstance(raw_input, dict) else {},
        )

    decision = _classify(canonical, tool_input, tool_name)
    return decision, canonical, tool_input


def _classify(canonical: str, tool_input: dict, raw_tool_name: str) -> dict:
    """Run nah's shared classifier against a normalized payload."""

    # PowerShell: run the minimal PowerShell classifier rather than the
    # Bash tokenizer. The two languages share almost no syntax (object
    # pipelines vs text streams, cmdlets vs POSIX commands, named
    # parameters like -Recurse vs flags, aliases like `ls` that mean
    # Get-ChildItem rather than /bin/ls). See nah.powershell for the
    # conservative allowlist of read-only cmdlets and the denylist of
    # eval-pattern cmdlets like Invoke-Expression.
    if raw_tool_name == "powershell":
        from nah.powershell import classify_powershell

        command = tool_input.get("command") or ""
        if not isinstance(command, str):
            command = str(command)
        return classify_powershell(command)

    # Subagent spawners: every inner tool call re-enters preToolUse via
    # the parent's hook chain, so nah classifies each real side effect on
    # arrival. See _SUBAGENT_COPILOT_TOOLS for the membership rationale.
    if raw_tool_name in _SUBAGENT_COPILOT_TOOLS:
        return {"decision": taxonomy.ALLOW, "_meta": {"stages": [{
            "action_type": taxonomy.UNKNOWN,
            "decision": taxonomy.ALLOW,
            "policy": taxonomy.ALLOW,
            "reason": (
                f"{raw_tool_name} subagent — inner tool calls re-enter preToolUse"
            ),
        }]}}

    # Harmless Copilot utility tools: UI labels, memory store, agent
    # introspection, doc fetches. See _HARMLESS_COPILOT_TOOLS for the
    # membership rationale and the explicit exclusions.
    if raw_tool_name in _HARMLESS_COPILOT_TOOLS:
        return {"decision": taxonomy.ALLOW, "_meta": {"stages": [{
            "action_type": taxonomy.UNKNOWN,
            "decision": taxonomy.ALLOW,
            "policy": taxonomy.ALLOW,
            "reason": f"{raw_tool_name}: harmless Copilot utility tool",
        }]}}

    # Bash, web_fetch (via synthetic curl).
    if canonical == "Bash":
        with _capture_stderr(log=False):
            return hook.handle_bash(tool_input)

    # File / search tools share Claude's handlers once normalized.
    handler = hook.HANDLERS.get(canonical)
    if handler is not None:
        with _capture_stderr(log=False):
            return handler(tool_input)

    # MCP and any other unmapped Copilot tools.
    return hook._classify_unknown_tool(canonical, tool_input)


# ---------------------------------------------------------------------------
# Output emission
# ---------------------------------------------------------------------------


def _emit_decision(stdout, decision: dict, canonical: str) -> None:
    """Write Copilot's bare preToolUse output schema to stdout."""
    d = decision.get("decision", taxonomy.ALLOW)
    enrich_decision(decision, tool=canonical)
    reason = decision.get("human_reason") or decision.get("reason", "")

    if d == taxonomy.BLOCK:
        payload = {"permissionDecision": "deny"}
        if reason:
            payload["permissionDecisionReason"] = reason
    elif d == taxonomy.ASK:
        payload = {"permissionDecision": "ask"}
        if reason:
            payload["permissionDecisionReason"] = reason
    else:
        payload = {"permissionDecision": "allow"}

    json.dump(payload, stdout)
    stdout.write("\n")
    stdout.flush()


def _emit_fail_closed(stdout, reason: str) -> None:
    """Emit a structured deny on any internal failure.

    Copilot preToolUse is fail-open on non-zero exit and malformed
    output. We must always emit a valid JSON deny with exit code 0.
    """
    try:
        msg = f"nah preToolUse internal error: {reason}"
        json.dump(
            {"permissionDecision": "deny", "permissionDecisionReason": msg},
            stdout,
        )
        stdout.write("\n")
        stdout.flush()
    except BrokenPipeError:
        pass
    except Exception:
        # Last-ditch: a literal deny string with no exception escape.
        try:
            stdout.write(
                '{"permissionDecision":"deny",'
                '"permissionDecisionReason":"nah preToolUse internal error"}\n'
            )
            stdout.flush()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _log_decision(
    canonical: str,
    tool_input: dict,
    decision: dict,
    total_ms: int,
    payload: dict,
) -> None:
    old_transcript = hook._transcript_path
    transcript = str(
        payload.get("transcript_path")
        or payload.get("transcriptPath")
        or ""
    )
    hook._transcript_path = transcript
    try:
        hook._log_hook_decision(
            canonical,
            tool_input,
            copy.deepcopy(decision),
            agents.COPILOT,
            total_ms,
        )
    finally:
        hook._transcript_path = old_transcript


@contextlib.contextmanager
def _capture_stderr(*, log: bool):
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        yield
    captured = buf.getvalue().strip()
    if captured and log:
        _log_copilot_hook_error(captured)


def _log_copilot_hook_error(message: str) -> None:
    try:
        from nah.log import LOG_PATH

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "agent": agents.COPILOT,
            "tool": "preToolUse",
            "decision": "error",
            "reason": message,
        }
        import os

        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except Exception as exc:
        try:
            sys.stderr.write(f"nah: copilot hook log: {exc}\n")
        except Exception:
            pass
