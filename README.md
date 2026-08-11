# Weft — the execution ledger for autonomous coding agents

[![CI](https://github.com/spranab/weft/actions/workflows/ci.yml/badge.svg)](https://github.com/spranab/weft/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Spec](https://img.shields.io/badge/RFC--0001-v0.3-d9a441.svg)](rfcs/0001-weft-protocol.md)

**Weft is a coordination and verification protocol for autonomous software
agents** — an open-source, self-hosted execution ledger where **verification,
not human code review, is the merge gate**. To humans it presents as version
control for AI agents; to a swarm of agents (Claude, GPT, Qwen, or yours) it
is the substrate they coordinate on, prove work against, and land certified
changes through. Git remains a first-class import/export format, not the
model.

```text
human software development         autonomous software development

developer                          intent
   ↓                                  ↓
branch → commit                    agents acquire scoped capabilities
   ↓                                  ↓
pull request                       agents work concurrently
   ↓                                  ↓
human review                       changes + read-sets + provenance
   ↓                                  ↓
CI                                 evidence
   ↓                                  ↓
merge                              verification gate → certified landing
```

The right-hand pipeline needs no branches and no pull requests — that is the
thesis. The name is the mechanism: a loom holds the *warp* under tension
while the *weft* is woven across it, one pick at a time. The certified
landing log is the warp; every agent's change is weft beaten into fabric by
a verification gate. Swarms of threads, one cloth.

## Why not just git + GitHub?

Everything git and forges layered on top of it assumes **human attention is
the scarce resource**: prose commits, PRs batched for human eyes, identity as
a config string, permissions in a forge database that doesn't replicate.
Agents break every one of those assumptions.

| git / forges | Weft |
|---|---|
| Commit = snapshot + prose message | Change = operations + intent + provenance + read-set + evidence |
| Identity = `user.email` string | Identity = Ed25519 keypair; every object signed; capabilities delegated, scoped, expiring, revocable |
| Merge = line-based 3-way text merge, human-reviewed | Merge = CRDT line-identity commutation; validity = evidence passing, certified by a gate quorum |
| Issues / CI / review live in a forge's database | Intents, evidence, policy, and approvals are protocol objects that replicate with the repo |
| History = ordered branch of commits | State = a *set* of changes (cherry-pick is free); trunk = a hash-chained certified landing log |
| Permissions = rows an admin can bypass | Unauthorized writes are *unrepresentable* — every object carries a capability chain to the authority key |

## Live demo

**https://weftgate.com** — the project site, and
**https://demo.weftgate.com** — a read-only public hub whose entire state
(certified landings from three models, a stale-read rejection, a
revoked-credential rejection, provenance chains to the authority root) was
produced by the real gate at boot. Click any change to walk its capability
chain. Hosting notes: [HOSTING.md](HOSTING.md).

## Try it in 60 seconds

```bash
curl -fsSL https://weftgate.com/install | sh   # prebuilt binaries, no signup
weftd                                          # hub + gate + console on :8747
# open http://localhost:8747 → Access → Generate key → Create repository
```

From source instead: `git clone https://github.com/spranab/weft && cd weft && cargo run --release -p weftd`

You are now the authority root of a Weft repo. Mint a role (Maintainer /
Contributor / Reader — roles are just capability templates), create an
intent, and watch agent work land through the approval gate you control.

Or start from an existing git repository — Weft becomes the agent-side
execution layer and GitHub keeps its front door:

```bash
cargo run --release -p weft-cli -- clone https://github.com/you/yourrepo
# agents land certified work through the gate, then:
cargo run --release -p weft-cli -- export --git yourrepo
git -C yourrepo log weft-export   # conventional commits, provenance trailers
```

## See the thesis run

```bash
cargo run --release -p weftd --example swarm
```

```text
weft swarm demo — 50 agents · 100 tasks · 1 repository · no branches · no PRs

  ✓ 82 changes landed across 14 certified landings (6.8s wall)
  ✓ largest batch: 32 independent changes in ONE landing (commutation)
  ✓ 2 same-anchor races converged deterministically (order markers)
  ✗ 8 stale-read changes rejected — reasoning was invalidated by concurrent work
  ✗ 8 planted bugs rejected by evidence (11 batch bisections isolated them)
  ✗ 3 revoked-credential attempts refused at certification

  the same workload on git: 100 branches, 100 PRs, and a human week.
```

Fifty concurrent workers (signing as three different models) hammer one
repository. Disjoint work commutes into batched certified landings; agents
whose *observations* went stale under them are caught even though their
patches don't overlap anything; planted bugs are isolated by binary-search
bisection of failing batches; revoked credentials bounce at certification.
Nobody read a diff.

## Four agents write a research paper

```bash
ollama serve && cargo run --release -p weftd --example paper
```

Real local models, working concurrently on one document. A citation checker
runs as gate evidence on the exact bytes; a judge attests from outside the
sandbox. One agent fabricates a citation — the way real models do — and
bisection isolates it: three sections land, that one doesn't.

Full walkthrough, including Hermes agent prompts and a traditional-vs-Weft
comparison: [docs/multi-agent-research-paper.md](docs/multi-agent-research-paper.md).
The verbatim output of a real run — including the prose the models produced and
the refused section — is in [docs/runs/paper.txt](docs/runs/paper.txt), alongside
[recorded runs](docs/runs/) of every demo, the full test suite, and the installer.

## How much work is a gate?

Usually one line — your existing test command *is* the recipe:

```jsonc
"recipes": [ { "kind": "test", "cmd": ["python", "-m", "pytest", "-q"] } ]
```

That's the whole gate for [one showcase scenario](docs/showcase/existing-tests/),
where an agent "improves" a function, breaks the existing test, and is refused.
The ladder from there — CI checks, domain validators, human approvals,
independent judges — with honest costs per rung:
[docs/writing-gates.md](docs/writing-gates.md).

## For AI agents (MCP)

Weft ships an [MCP server](weft-mcp/) — agents connect over the Model Context
Protocol and get the full workflow: `intent_create`, `intent_lease`,
`workspace` (numbered lines — agents never see internal line-IDs),
`change_submit` (edit by line number → signed change → proposal → reports
landed / pending-approval / rejected), `approve`, `note_add` / `notes` (the
repo's durable memory), and `provenance` (walk any change to its authority
root).

```jsonc
// .mcp.json (ships in this repo — Claude Code picks it up automatically)
{ "mcpServers": { "weft": {
    "command": "cargo", "args": ["run", "--quiet", "--release", "-p", "weft-mcp"],
    "env": { "WEFT_HUB": "http://127.0.0.1:8747" } } } }
```

The agent generates its own Ed25519 key on first run. Until a human delegates
it a capability in the console, every write is refused with the public key to
authorize — the delegation loop between the human UI and the agent door is
the product. Agent onboarding docs: [CLAUDE.md](CLAUDE.md) · [llms.txt](llms.txt).

Native plugins ship for two hosts alongside the zero-code MCP path —
[Hermes Agent](integrations/hermes-weft/) (verified end-to-end against a live
hub) and [OpenClaw](integrations/openclaw-weft/). See
[integrations/](integrations/).

## How it works

1. **Objects** — 20 content-addressed, Ed25519-signed types over deterministic
   CBOR (BLAKE3 addressing): changes, patches, states, manifests, intents,
   capabilities, evidence, policy, landings, certificates…
   [RFC-0001](rfcs/0001-weft-protocol.md) is the source of truth.
2. **Content model** — an RGA-family CRDT over line identities. Materialization
   is a pure function of the change *set*, byte-identical on every node, with
   a Merkle **manifest** making tree, file-map, and conflict roots verifiable.
3. **The gate** — proposals queue; footprint-disjoint work batches into one
   landing (one evidence run for N changes); overlapping work serializes.
   Policy pins evidence recipes by digest, demands attestor trust roots, and
   can require human approvals — minted as signed evidence from a browser key.
4. **Governance console** — served by the daemon at `/`: landing log,
   provenance drill-down, intent board, role console, policy view. The UI
   renders the capability graph; it never owns a users/roles database.

## Benchmarks

`cargo run --release -p weftd --example bench` (32-core dev machine,
in-memory store, evidence execution excluded):

| Bench | Result | What it measures |
|---|---|---|
| Object ingest | **~27,000 obj/s** | canonical decode + Ed25519 verify + store |
| Materialize 5,000 concurrent changes | **10.4 ms** | the CRDT engine hot path |
| Gate, disjoint work | **~55,000 chg/s** — 500 proposals → **1 landing** | batching amortizes verification |
| Gate, contended file | **~975 chg/s**, fully serialized | ~1 ms per certified landing |

The engine is not the bottleneck: real throughput is dominated by evidence
execution (your test suite), which is exactly what batching amortizes.

## Project status

Working, tested, pre-1.0. The spec survived four kinds of adversary — two
frontier models (77 findings), an executable prototype (7 more), and CI — all
[dispositioned in the review log](rfcs/0001-review-log.md).

| Component | State |
|---|---|
| [RFC-0001 spec](rfcs/0001-weft-protocol.md) (v0.3) + [review log](rfcs/0001-review-log.md) | ✅ |
| [`weft-core`](weft-core/) — engine: CBOR, signatures, CRDT + manifests, capabilities, certification | ✅ fuzzed, 9 tests |
| [`weftd`](weftd/) — hub: gate + merge queue, approval-gated landings, governance console, **crash-durable store** (`--data`), **sandboxed evidence** (`--sandbox unshare`), **verify-don't-trust replication** (`--follow <peer>`) | ✅ 5 e2e suites |
| [`weft-mcp`](weft-mcp/) — agent door over MCP | ✅ e2e-tested |
| [`prototype/`](prototype/) — original Python executable spec | ✅ kept as reference |
| [`weft-cli`](weft-cli/) — **git bridge** + porcelain: `weft clone <url>` / `weft init --git <dir>` imports a git HEAD through the gate; agents land certified work; `weft export --git <dir>` writes conventional commits with `Weft-Change`/`Weft-Model`/`Weft-Author-Key` trailers, chained onto the original git history, byte-deterministic across re-exports | ✅ round-trip e2e |
| multi-gate quorums (threshold > 1) · heterogeneous evidence quorums · QUIC/push gossip · full-history git import | 🚧 roadmap |

## Keywords

Version control for AI agents · agentic coding · autonomous software
development · git alternative for agents · multi-agent collaboration · MCP
server · Model Context Protocol · CRDT merge · capability-based permissions ·
self-hosted forge · evidence-gated merging · AI code review · provenance.

## License

MIT (see [LICENSE](LICENSE)). Dual MIT/Apache-2.0 will be considered before
the first tagged release.
