# Recorded runs

Unedited output from real runs on real machines. Nothing here is a mockup;
every file is what the terminal actually printed. Each one is reproducible
with the command in its first line.

| Run | What it shows |
|---|---|
| [tests.txt](tests.txt) | `cargo test --workspace` — 18 tests across 8 suites, all passing |
| [swarm.txt](swarm.txt) | 50 agents, 100 tasks, one repo: what landed, what bounced, and why |
| [paper.txt](paper.txt) | four local models write a research paper; the fabricated citation is refused, with the prose they wrote |
| [docs.txt](docs.txt) | a handbook gated by a doc-linter plus a judge; an unfinished section refused even though the judge approved |
| [bench.txt](bench.txt) | ingest, CRDT materialization, and gate throughput (batched vs contended) |
| [hermes-selftest.txt](hermes-selftest.txt) | the Hermes plugin against a live gate: refusal → delegation → landed → provenance to the authority root |
| [install.txt](install.txt) | `curl -fsSL https://weftgate.com/install \| sh` on a clean Ubuntu, then the hub starting with its sandbox active |

Two things these deliberately show rather than hide:

- **Rejections outnumber nothing.** The swarm and paper runs are interesting
  precisely because work *bounces* — stale reads, planted bugs, revoked
  credentials, a fabricated citation. A demo where everything passes proves
  only that the gate is off.
- **Numbers vary by machine.** The benchmark figures here come from a 32-core
  Windows box; yours will differ. The shape is what matters: batching turns
  many changes into one verification, contention serializes.
