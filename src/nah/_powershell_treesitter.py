"""Tree-sitter-backed PowerShell classifier.

This module is loaded only when the optional `[powershell]` extra is
installed (``pip install nah[powershell]``), which pulls in
``tree-sitter`` and ``tree-sitter-powershell``. The hand-rolled scanner
in :mod:`nah.powershell` remains the floor for users who do not
install the extra.

The tree-sitter engine produces the same allow / ask / block contract
as the hand-rolled scanner, with a few classes of input the
hand-rolled scanner cannot reliably reason about:

- here-strings (``@'...'@``, ``@"..."@``), comments (``# ...``,
  ``<# ... #>``), and the backtick escape outside double quotes —
  all handled by the real lexer instead of regex peeking,
- the difference between a redirection operator and a literal ``>``
  inside a string — distinguished by the grammar's
  ``file_redirection_operator`` node,
- the call operator and the call-operator-with-name-expression form
  (``& 'cmd' arg`` and ``& $cmd arg``) — distinguished by the
  presence of ``command_invokation_operator`` (sic — grammar typo),
- the LHS shape of an assignment — ``variable`` alone vs
  ``member_access``, ``element_access``, or ``braced_variable``
  children let us tell ``$x = ...`` from ``$x.Foo = ...``,
  ``$x[0] = ...``, and ``${env:PATH} = ...``.

The cmdlet allow/deny/ask tables are imported from
:mod:`nah.powershell` so the two engines stay in sync.

Public surface: a single :func:`classify_treesitter` function. The
:func:`nah.powershell.classify_powershell` dispatcher imports it
lazily and falls back to the hand-rolled engine on ``ImportError``.
"""

from __future__ import annotations

from typing import Iterable

import tree_sitter
import tree_sitter_powershell

from nah.powershell import (
    _ASK_CMDLETS,
    _DENY_CMDLETS,
    _SAFE_CMDLETS,
    _decide_allow,
    _decide_ask,
    _decide_block,
    _stricter,
    _truncate,
)


# A single parser is reused across calls. Constructing one is ~10 µs
# but doing it per call still costs more than the parse itself.
_LANGUAGE = tree_sitter.Language(tree_sitter_powershell.language())
_PARSER = tree_sitter.Parser(_LANGUAGE)


def classify_treesitter(command: str) -> dict:
    """Classify a PowerShell command using the tree-sitter grammar."""
    text = command.strip()
    if not text:
        return _decide_allow("empty command")

    source = text.encode("utf-8")
    tree = _PARSER.parse(source)
    root = tree.root_node

    worst = "allow"
    reasons: list[str] = []
    stages_meta: list[dict] = []

    statement_list = _find_first(root, "statement_list")
    if statement_list is None:
        # Either the program is empty or the parser produced an
        # unexpected shape. Fall back to ASK so a human can review.
        return _decide_ask(
            "PowerShell parser produced no statements",
            stages=[{"action_type": "powershell_unknown",
                     "decision": "ask",
                     "policy": "ask",
                     "reason": "no statement_list"}],
        )

    for stmt in _iter_named_children(statement_list):
        decision, reason, stage = _classify_statement(stmt, source)
        worst = _stricter(worst, decision)
        if reason:
            reasons.append(reason)
        if stage is not None:
            stages_meta.append(stage)

    if worst == "allow":
        return _decide_allow("read-only PowerShell cmdlets only")
    if worst == "block":
        return _decide_block("; ".join(reasons) or "PowerShell command blocked")
    return _decide_ask(
        "; ".join(reasons) or "PowerShell command needs review",
        stages=stages_meta,
    )


# ---------------------------------------------------------------------------
# Statement-level classification
# ---------------------------------------------------------------------------


def _classify_statement(node, source: bytes) -> tuple[str, str, dict | None]:
    """Classify one top-level statement.

    Returns ``(decision, reason, stage_meta)`` where stage_meta is a
    log-friendly dict or None.
    """
    if node.type == "pipeline":
        return _classify_pipeline_node(node, source)
    # Tree-sitter wraps `$x = ...` inside a pipeline at top level too,
    # but defensively handle the bare assignment shape just in case.
    if node.type == "assignment_expression":
        return _classify_assignment(node, source)
    # ``empty_statement`` is the AST node produced for a bare statement
    # separator such as the ``;`` in ``Get-Date; Get-Location``. It does
    # nothing, so it does nothing to the decision either.
    if node.type == "empty_statement":
        return ("allow", "", None)
    # Any other top-level statement (function defs, if blocks, loops,
    # etc.) — we cannot statically reason about whether their body is
    # safe, so route to ASK with a structural reason.
    return ("ask",
            f"PowerShell {node.type} cannot be statically classified",
            _stage_meta(node.type, "ask", source, node))


def _classify_pipeline_node(node, source: bytes) -> tuple[str, str, dict | None]:
    """Classify a top-level pipeline.

    A pipeline at top level may either be an assignment_expression (which
    in the grammar lives directly under `pipeline`) or one or more
    pipeline_chain nodes separated by pipeline_chain_tail (`&&` / `||`).
    Each chain is its own statement-shaped unit.
    """
    # Assignment wrapped in a pipeline.
    for c in _iter_named_children(node):
        if c.type == "assignment_expression":
            return _classify_assignment(c, source)

    worst = "allow"
    reasons: list[str] = []
    stages: list[dict] = []
    for chain in _iter_named_children(node):
        if chain.type != "pipeline_chain":
            continue
        d, r, st = _classify_pipeline_chain(chain, source)
        worst = _stricter(worst, d)
        if r:
            reasons.append(r)
        for s in (st or []):
            stages.append(s)
    # If we never saw a pipeline_chain, the pipeline contained
    # something unexpected; ASK conservatively.
    if not stages and worst == "allow":
        return ("ask",
                "PowerShell pipeline with no recognizable chain",
                _stage_meta("pipeline", "ask", source, node))
    # Pack multiple stage dicts into one composite for the caller.
    if len(stages) == 1:
        return worst, "; ".join(reasons), stages[0]
    return worst, "; ".join(reasons), {
        "kind": "pipeline",
        "decision": worst,
        "stages": stages,
    }


def _classify_assignment(node, source: bytes) -> tuple[str, str, dict | None]:
    """Classify `$lhs = rhs` and compound assignments.

    Plain local-variable assignment (`$name = ...`) is transparent —
    the RHS pipeline is classified normally. Anything else (scoped
    variable, member access, element access, braced variable) is a
    mutation in its own right and must surface as ASK.
    """
    lhs = _find_first(node, "left_assignment_expression")
    if lhs is None:
        return ("ask",
                "PowerShell assignment with unrecognized LHS",
                _stage_meta("assignment_expression", "ask", source, node))

    if not _lhs_is_plain_variable(lhs):
        return ("ask",
                f"PowerShell scoped or member assignment: {_truncate(_text(lhs, source))}",
                _stage_meta("assignment_expression", "ask", source, node))

    # Plain assignment — the right-hand side is the second `pipeline`
    # child of the assignment_expression. The grammar wraps the RHS as
    # a `pipeline` even when it is a single expression.
    rhs = None
    for c in _iter_named_children(node):
        if c.type == "pipeline":
            rhs = c
            break
    if rhs is None:
        return ("allow", "", _stage_meta("assignment_expression", "allow", source, node))
    return _classify_pipeline_node(rhs, source)


def _lhs_is_plain_variable(lhs) -> bool:
    """Return True iff the LHS is a bare `$name` variable."""
    var = _find_first(lhs, "variable")
    if var is None:
        return False
    # `${env:Path}` parses as `variable` with a `braced_variable`
    # child. Plain `$name` has no named children.
    if any(c.is_named for c in var.children):
        return False
    # `$env:PATH`, `$global:foo`, etc. — the colon makes it scoped.
    text = bytes(var.text).decode("utf-8", errors="replace")
    if ":" in text:
        return False
    # `$x.Foo` — the variable node is wrapped in a member_access.
    # `$x[0]` — wrapped in an element_access.
    # Walk up from var to lhs and reject either.
    parent = var.parent
    while parent is not None and parent.id != lhs.id:
        if parent.type in ("member_access", "element_access"):
            return False
        parent = parent.parent
    return True


# ---------------------------------------------------------------------------
# Pipeline-chain classification (a chain is one segment of `&&`/`||`)
# ---------------------------------------------------------------------------


def _classify_pipeline_chain(node, source: bytes) -> tuple[str, str, list[dict] | None]:
    """Classify one pipeline chain (one statement-shaped unit)."""
    # Collect `command` children. The grammar may also include
    # `logical_expression` and others when the chain is just an
    # expression rather than a command; treat those as dynamic.
    commands: list = []
    has_non_command = False
    for c in _iter_named_children(node):
        if c.type == "command":
            commands.append(c)
        else:
            has_non_command = True

    # If the only content is a non-command expression (e.g.
    # `[Type]::Method(...)` at the top level), classify as dynamic.
    if not commands and has_non_command:
        snippet = _truncate(_text(node, source))
        return ("ask",
                f"PowerShell expression evaluated as a statement: {snippet}",
                [_stage_meta("expression", "ask", source, node)])

    # iex / Invoke-Expression at the end of a multi-command pipeline
    # is the textbook curl-pipe-bash equivalent.
    cmdlets = [_cmdlet_name(cmd, source) for cmd in commands]
    if cmdlets and cmdlets[-1] in {"iex", "invoke-expression"}:
        # All commands have a clean name (no call op, no name expr)?
        # If the iex stage itself has a call op or name expr, fall
        # through to the per-stage loop which will still block on the
        # cmdlet name.
        if len(commands) > 1:
            return ("block",
                    "PowerShell pipes output into Invoke-Expression "
                    "(remote code execution pattern)",
                    [_stage_meta(name, "block", source, cmd)
                     for name, cmd in zip(cmdlets, commands)])
        return ("block",
                "PowerShell Invoke-Expression evaluates a string as code "
                "(remote code execution pattern)",
                [_stage_meta(cmdlets[0], "block", source, commands[0])])

    worst = "allow"
    reasons: list[str] = []
    stages: list[dict] = []
    for cmd, name in zip(commands, cmdlets):
        d, r, stage = _classify_command(cmd, name, source)
        worst = _stricter(worst, d)
        if r:
            reasons.append(r)
        stages.append(stage)
    return worst, "; ".join(reasons), stages


# ---------------------------------------------------------------------------
# Command-level classification
# ---------------------------------------------------------------------------


def _classify_command(node, name: str, source: bytes) -> tuple[str, str, dict]:
    """Classify a single `command` node."""
    raw = _truncate(_text(node, source))

    # The call operator (`& $cmd`, `& 'something'`) makes the cmdlet
    # name dynamic — the actual command run is whatever the operand
    # resolves to at runtime.
    if _has_child_type(node, "command_invokation_operator"):
        return ("ask",
                f"PowerShell call operator runs a dynamic command: {raw}",
                _stage_meta(name or "&", "ask", source, node))
    # Same for `command_name_expr` (which the grammar uses when the
    # name is a string or variable rather than a bare identifier).
    if _has_child_type(node, "command_name_expr"):
        return ("ask",
                f"PowerShell command name is an expression: {raw}",
                _stage_meta(name or "<expr>", "ask", source, node))

    elements = _find_first(node, "command_elements", recurse=False)

    # Output redirection — distinguished by the grammar as a
    # `redirection` node anywhere inside command_elements.
    if elements is not None and _has_descendant_type(elements, "redirection"):
        return ("ask",
                f"PowerShell uses output redirection nah cannot inspect (stage: {raw})",
                _stage_meta(name, "ask", source, node))

    # Type-method invocation, parenthesized expressions, subexpressions,
    # array subexpressions — anything that could execute arbitrary code
    # under the guise of an argument. Script blocks are handled
    # separately via _collect_script_block_statement_lists so their
    # bodies can be classified instead of treated as opaque.
    if elements is not None and _has_dynamic_argument(elements):
        return ("ask",
                f"PowerShell uses dynamic content nah cannot inspect (stage: {raw})",
                _stage_meta(name, "ask", source, node))

    # Resolve the cmdlet's own verdict first.
    if not name:
        cmd_decision: tuple[str, str, dict] = (
            "ask",
            f"PowerShell stage with no recognizable cmdlet: {raw}",
            _stage_meta("", "ask", source, node),
        )
    elif name in _DENY_CMDLETS:
        cmd_decision = (
            "block",
            f"PowerShell cmdlet not permitted: {name}",
            _stage_meta(name, "block", source, node),
        )
    elif name in _ASK_CMDLETS:
        cmd_decision = (
            "ask",
            f"PowerShell cmdlet needs review: {name}",
            _stage_meta(name, "ask", source, node),
        )
    elif name in _SAFE_CMDLETS:
        cmd_decision = ("allow", "", _stage_meta(name, "allow", source, node))
    else:
        cmd_decision = (
            "ask",
            f"unrecognized PowerShell cmdlet: {name}",
            _stage_meta(name, "ask", source, node),
        )

    # Recurse into any script block arguments. The script body's
    # decision composes with the command's own — the worst verdict
    # wins, but a safe-cmdlet host with a benign script block stays
    # ALLOW. The recursion makes
    # `Where-Object { Remove-Item -Recurse / }` correctly become ASK
    # ("PowerShell cmdlet needs review: remove-item") instead of the
    # less informative "PowerShell uses dynamic content" message that
    # the hand-rolled scanner has to fall back to.
    decision, reason, stage = cmd_decision
    for stmt_list in _collect_script_block_statement_lists(elements):
        inner_decision, inner_reason = _classify_statement_list(stmt_list, source)
        decision = _stricter(decision, inner_decision)
        if inner_reason:
            reason = f"{reason}; {inner_reason}" if reason else inner_reason
    return decision, reason, stage


def _cmdlet_name(command_node, source: bytes) -> str:
    """Return the lowercased text of a command's command_name, or ""."""
    name_node = _find_first(command_node, "command_name", recurse=False)
    if name_node is None:
        return ""
    return _text(name_node, source).lower()


# ---------------------------------------------------------------------------
# Dynamic-argument detection
# ---------------------------------------------------------------------------


_DYNAMIC_NODE_TYPES = frozenset({
    "invokation_expression",
    "sub_expression",
    "array_expression",
    "parenthesized_expression",
})


def _has_dynamic_argument(elements_node) -> bool:
    """Return True if any descendant of command_elements is dynamic.

    ``script_block_expression`` is handled separately by
    :func:`_collect_script_block_statement_lists` so the inner script
    body can be classified rather than treated as opaque dynamic
    content.
    """
    for desc in _iter_descendants(elements_node):
        if desc.type in _DYNAMIC_NODE_TYPES:
            return True
    return False


def _collect_script_block_statement_lists(elements_node) -> list:
    """Return every statement_list nested inside a script block argument.

    A command like ``Where-Object { Remove-Item C:\\tmp }`` parses to a
    command with a ``script_block_expression`` arg. The grammar nests
    its body as ``script_block_expression`` → ``script_block`` →
    ``script_block_body`` → ``statement_list``. Returning the
    statement_list lets the caller recursively classify what the block
    actually does rather than treat every script block as ASK.
    """
    if elements_node is None:
        return []
    found = []
    for desc in _iter_descendants(elements_node):
        if desc.type == "script_block_expression":
            stmt_list = _find_first(desc, "statement_list")
            if stmt_list is not None:
                found.append(stmt_list)
    return found


def _classify_statement_list(stmt_list, source: bytes) -> tuple[str, str]:
    """Reduce a statement_list to a single (decision, reason) pair.

    Used to classify the body of a script block argument recursively.
    The stage records are intentionally collapsed to a single summary
    string here — the parent command's stage record is what gets
    logged.
    """
    worst = "allow"
    reasons: list[str] = []
    for stmt in _iter_named_children(stmt_list):
        decision, reason, _stage = _classify_statement(stmt, source)
        worst = _stricter(worst, decision)
        if reason:
            reasons.append(reason)
    return worst, "; ".join(reasons)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _iter_named_children(node) -> Iterable:
    for c in node.children:
        if c.is_named:
            yield c


def _iter_descendants(node):
    """Pre-order traversal of all descendants (named and anonymous)."""
    stack = [node]
    while stack:
        n = stack.pop()
        for c in reversed(n.children):
            stack.append(c)
        if n.id != node.id:
            yield n


def _find_first(node, type_name: str, *, recurse: bool = True):
    """Return the first descendant of ``node`` with the given type."""
    if not recurse:
        for c in node.children:
            if c.type == type_name:
                return c
        return None
    for d in _iter_descendants(node):
        if d.type == type_name:
            return d
    return None


def _has_child_type(node, type_name: str) -> bool:
    for c in node.children:
        if c.type == type_name:
            return True
    return False


def _has_descendant_type(node, type_name: str) -> bool:
    return _find_first(node, type_name) is not None


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _stage_meta(name: str, decision: str, source: bytes, node) -> dict:
    return {
        "action_type": (
            "powershell_safe" if decision == "allow"
            else "powershell_dangerous" if decision == "block"
            else "powershell_unknown"
        ),
        "decision": decision,
        "policy": decision,
        "reason": _truncate(_text(node, source)),
        "cmdlet": name,
    }
