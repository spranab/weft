# agchub

**Home of Weft — a version-control protocol and self-hosted hub built for the
agentic world.**

The name is the mechanism: a loom holds the *warp* under tension while the
*weft* is woven across it, one pick at a time. Weft's certified landing log is
the warp; every agent's change is weft beaten into fabric by a verification
gate. Swarms of threads, one cloth.

Git was created for Linux — one brutally demanding human workflow, generalized later.
agchub is created for the workflow that git is bad at: **N autonomous agents working the
same repository concurrently, merging continuously, with verification — not human
review — as the gate.**

## Status

**Design phase — RFC-0001 at Draft v0.2.** The spec was drafted by Claude
Fable 5, then hardened through independent adversarial review by GPT-5.6-sol
and Qwen 3.8 Max (77 findings, all dispositioned):

- [RFC-0001: The Weft Protocol](rfcs/0001-weft-protocol.md) — object model,
  identity & capabilities, RGA content model with verifiable materialization
  manifests, quorum-certified landing log, evidence-gated policy, sync, agent
  interface, git bridge.
- [Review log](rfcs/0001-review-log.md) — every finding from both reviews with
  its disposition (accept / modify / defer / reject), plus the
  implementation-testing findings below.

## Prototype (it runs)

[prototype/](prototype/) is an executable subset of the RFC — real
deterministic CBOR, real Ed25519, the RGA materialization engine with
manifests, capability chains, and a live gate with a merge queue:

- `weft_core.py` — the protocol engine
- `weft_fuzz.py` — **0/300 determinism violations** across 8 shuffled orders
  per scenario, identical on Windows and Linux; targeted convergence tests
  all pass
- `weftd.py` + `swarm_demo.py` — three concurrent agents (run from Windows)
  work one repo through a certified gate (run in WSL Ubuntu): the gate
  batched disjoint work, serialized overlapping work, flagged the same-anchor
  append race with an order marker, caught a stale read, executed the pinned
  evidence recipe in a sandbox, and certified three landings — then a
  Windows light client re-materialized the Linux gate's state to **identical
  manifest roots** and walked one line's provenance back to the authority
  key. `3/3 workers landed`.

Building it surfaced six spec defects the two model reviews missed (findings
W1–W6 in the review log) — all fixed in RFC v0.3. The spec has now survived
three kinds of adversary: two frontier models, and the compiler.

## What's different from git

| Git | Weft |
|---|---|
| Commit = snapshot + prose message | Change = operations + intent + provenance + evidence |
| Identity = `user.email` config string | Identity = keypair; every object signed; capabilities are delegated and revocable |
| Merge = line-based 3-way text merge | Merge = commutation over line-identity; validity = evidence passing post-merge |
| Issues/CI/review live in a forge's database | Intents, evidence, and policy are protocol objects that replicate with the repo |
| History = ordered branch of commits | State = an unordered *set* of changes; cherry-pick is free |
| Humans are the actors | Agents are first-class; humans approve intents, not lines |

## Planned components

1. `rfcs/` — the protocol spec (the product, in a protocol project) ✅
2. [`weft-core/`](weft-core/) — the Rust engine: canonical CBOR, BLAKE3 +
   Ed25519 signed objects, RGA materialization with manifests, capability
   chains, the landing checklist. **9/9 tests green on Windows and Linux**,
   including the determinism fuzzer (200 scenarios × 6 permutations) and
   regression tests for every implementation finding. 🚧 next: sync + gate
   daemon
3. [`weftd/`](weftd/) — reference hub: object store, trunk gate with merge
   queue (batches footprint-disjoint proposals, serializes overlapping ones),
   sandboxed evidence execution, certified landings, HTTP surface. Integration
   test runs three concurrent workers over real HTTP through the gate with
   light-client verification. 🚧 next: sync frames (§8), multi-gate quorums,
   MCP server
4. `weft` — CLI porcelain for humans
4. MCP server — the *primary* agent interface, first-class before any web UI
5. Git bridge — two-way mirror so agchub repos keep a GitHub front door

## License

MIT (see [LICENSE](LICENSE)). Dual MIT/Apache-2.0 will be considered before
the first public release for the patent-grant benefit.
