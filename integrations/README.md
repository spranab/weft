# Weft integrations

Three ways to give an agent framework a verification gate. Pick by how much
you want to write.

| | Path | Works with | Code to write |
|---|---|---|---|
| 1 | **MCP** (recommended) | anything with an MCP client — Hermes, OpenClaw, Claude Code, Codex, code_puppy | none |
| 2 | **[Native OpenClaw plugin](openclaw-weft/)** | OpenClaw | ships here |
| 3 | **[Native Hermes plugin](hermes-weft/)** | Hermes Agent | ships here |

All three end in the same place: the agent proposes, the gate decides, and
whatever lands carries signed provenance back to a human authority key. And
all three keep the agent's Ed25519 private key on the agent's machine — the
hub returns a digest to sign and only ever receives signatures.

## 1. MCP — zero code

Weft ships an MCP server ([`weft-mcp`](../weft-mcp/)), so any framework with
an MCP client gets the whole workflow without an integration layer.

**Hermes Agent** — `~/.hermes/mcp.json` (or the dashboard's MCP section):

```jsonc
{ "mcpServers": { "weft": {
    "command": "weft-mcp",
    "env": { "WEFT_HUB": "http://127.0.0.1:8747", "WEFT_MODEL": "hermes" } } } }
```

**OpenClaw** — the same server, configured as an MCP entry in your OpenClaw
config. **Claude Code** — a `.mcp.json` like the one in this repo's root.

Tools: `repo_status`, `whoami`, `intent_create` / `intent_list` /
`intent_lease`, `workspace`, `change_submit`, `approve`, `note_add`, `notes`,
`provenance`.

## 2 & 3. Native plugins — when you want more than tools

Go native when you want framework-specific lifecycle behaviour: OpenClaw's
service/logging surface and typed config schema, or Hermes hooks like
`on_session_end` writing a session note into the repo's own memory.

Both plugins are modelled directly on the structure of shipped plugins for
those hosts, and expose the same five tools:

- `weft_status` — trunk seq, queue depth, approvals due, this agent's key
- `weft_intents` — the machine-readable work graph
- `weft_workspace` — the head tree as **numbered lines**, with untrusted-data
  hedges on files whose authors lack the `instruct` capability (RFC §12.1)
- `weft_submit` — edit by **line number**; the plugin does the
  position→identity translation, proposes, and reports
  `landed` / `pending_approval` / `rejected`
- `weft_provenance` — walk any change to the authority root

### The delegation loop (the important part)

On first run the plugin mints its own Ed25519 key and **writes are refused**:

```
no live capability granting 'publish_change' is delegated to this agent key
(57a4a022…). Ask a human to open the Weft console → Access → mint a
Contributor capability for that key.
```

That refusal *is* the onboarding instruction. A human opens the console,
pastes the key, picks Contributor + an expiry, signs — and the agent's next
submission lands. Reads keep working throughout. This is the whole security
model in one interaction: agents don't get accounts, they get scoped,
expiring, revocable capabilities.

## What's verified

- **Hermes plugin**: end-to-end against a live hub —
  `python integrations/hermes-weft/selftest.py` walks refusal → delegation →
  landed → provenance-to-root → session note. Run a hub first
  (`cargo run --release -p weftd`).
- **OpenClaw plugin**: written against the OpenClaw plugin SDK
  (`definePluginEntry` / `api.registerTool` / `api.registerService`) and
  typechecks with the SDK present; install it into an OpenClaw host to
  exercise the host-side wiring.
- **MCP path**: covered by `cargo test -p weft-mcp` — a real MCP client
  session driving a real gate.
