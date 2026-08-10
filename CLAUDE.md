# Weft (agchub) — agent session guide

Weft is a version-control protocol for autonomous coding agents; this repo is
its spec + reference implementation. You (the agent) are the primary user
this project is built for.

## Commands

- `cargo test --workspace` — full suite (core regression + fuzz, weftd swarm
  e2e, approval e2e, MCP e2e). Everything must stay green.
- `cargo clippy --workspace --examples` — CI enforces `-D warnings`.
- `cargo run --release -p weftd` — hub + gate + governance console on :8747.
- `cargo run --release -p weftd --example bench` — benchmark suite.
- `python prototype/weft_fuzz.py` — the Python executable-spec fuzzer.
- `cargo run --release -p weft-cli -- <init|clone|status|export>` — the git
  bridge: import a git HEAD, export landed history as conventional commits.

## Using Weft itself (dogfooding)

This repo ships `.mcp.json` wiring the `weft` MCP server to a hub at
`http://127.0.0.1:8747`. Start `weftd`, then use the MCP tools:
`repo_status`, `intent_create`/`intent_lease`, `workspace` (1-based line
numbers), `change_submit` (edits by line number; `create:true` for new
files; reports landed/pending_approval/rejected), `approve`, `note_add`/
`notes`, `provenance`, `whoami`. On first use your key has no capability —
the refusal message contains the public key a human must delegate to via the
console (Access tab).

## Architecture map

- `rfcs/0001-weft-protocol.md` — **source of truth.** Any behavior change
  must update the spec; any discovered defect gets a numbered finding in
  `rfcs/0001-review-log.md` with a disposition.
- `weft-core/src/cbor.rs` — deterministic CBOR (no floats — ints only).
- `weft-core/src/object.rs` — envelopes: sign pre-`sig` fields (domain
  context `weft/0.1`), then OID = BLAKE3 of the signed envelope.
- `weft-core/src/engine.rs` — patches + RGA materialization. Identities are
  `(patch-oid, ordinal)`; SELF sentinel `[null, ordinal]` for intra-patch
  references; ordinals count mkfiles AND inserted lines in op order.
- `weft-core/src/gate.rs` — states (delta form, closure-digest summaries),
  capability chains (revocation-aware `_r` variants), §7.3 certification.
- `weftd/src/lib.rs` — gate loop (batch disjoint footprints, serialize
  overlaps), approval gating (`ts=0` on state/manifest keeps manifest OIDs
  stable across re-attempts — do not "fix" this), HTTP + browser signing
  (`/prepare` → client signs → `/submit`), governance endpoints.
- `weftd/src/dashboard.html` — single-file console. No client-side user/role
  state ever: roles are capability minting templates (RFC §11).

## Invariants and conventions

1. **Determinism is load-bearing**: `∀ permutations of a change set →
   identical manifest`. Never introduce iteration-order dependence; sort
   explicitly or prove order-freedom. The fuzzers exist to catch you.
2. **Never assert a specific sibling order** at a shared RGA anchor in tests
   — order depends on patch-OID comparison and varies per run. Assert region
   placement instead (we shipped that flake once; CI caught it).
3. Canonical bytes are the object: relays never re-serialize; decoders
   reject non-minimal ints and unsorted map keys.
4. Authorization is checked at certification time and frozen forever after;
   revocation/expiry gate future landings only.
5. Commit style: what + why, findings referenced by number (`finding W7`),
   `Co-Authored-By` trailer per harness convention. Push only when the full
   suite and clippy are green; CI must stay green on `main`.
6. New spec defects found while implementing → add a `W*n*` row to Review C
   in the review log AND fix the RFC in the same commit.
