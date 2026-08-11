# Showcase — the same work, with and without a gate

Three workloads. In each one, the *same* agents produce the *same*
contributions, and the output is assembled two ways:

- **`without-weft/`** — everything the agents produced, merged in arrival
  order, the way a naive pipeline does it
- **`with-weft/`** — only what the verification gate let land
- **`gate.log`** — what the gate refused, and why

Then the **same validator** runs over both directories. The difference isn't
an argument; it's an exit code.

| Workload | Without Weft | With Weft | Artifacts |
|---|---|---|---|
| [Spreadsheet](sales-report/) — four agents append regional rows to one CSV | **FAIL** — `quarter 'Q2 2026' is not YYYY-Qn; revenue 'approx 350k' is not a number` | **PASS** — 6 clean rows | [without](sales-report/without-weft/sales.csv) · [with](sales-report/with-weft/sales.csv) · [log](sales-report/gate.log) |
| [Code](api-client/) — three agents extend a Python client | **FAIL** — the module no longer compiles, so every test fails | **PASS** — imports and tests pass | [without](api-client/without-weft/client.py) · [with](api-client/with-weft/client.py) · [log](api-client/gate.log) |
| [Document](policy-brief/) — three agents write a policy brief | **FAIL** — `fabricated citation(s): [7]` | **PASS** — all citations resolve | [without](policy-brief/without-weft/brief.md) · [with](policy-brief/with-weft/brief.md) · [log](policy-brief/gate.log) |
| [Existing tests](existing-tests/) — the gate is `python -m pytest -q`, unchanged | **FAIL** — `1 failed` (an agent redefined `retry()`) | **PASS** — `1 passed` | [without](existing-tests/without-weft/retryx.py) · [with](existing-tests/with-weft/retryx.py) · [log](existing-tests/gate.log) |

**4/4 unguarded outputs failed their own validator. 4/4 gated outputs passed
it.**

The fourth is the one to look at if you're wondering how much work a gate is:
its recipe is the repository's own `pytest` command, verbatim. Nothing was
written for Weft. See [writing gates](../writing-gates.md).

## The point

The agents are identical in both columns. Nobody got smarter, nobody wrote a
better prompt. The only difference is whether anything checked *before* the
work became the artifact.

Look at what actually differs. In the spreadsheet, one row:

```diff
  west,2026-Q3,2402,617300.00
- east,Q2 2026,1450,approx 350k
- east,2026-Q3,1502,371200.00
```

That row is the kind of thing that survives review — it looks like data, it's
in the right column count, and a human skimming a diff of four agents' work
sees numbers and moves on. A spreadsheet consumer finds it three weeks later
when a sum is wrong.

In the code, an unbalanced parenthesis at the end of a plausible-looking
retry helper. It doesn't fail *that agent's* work; it breaks the whole module
for everyone who imports it.

In the brief, a confident sentence citing `[7]` — a source that does not
exist. This is the failure mode language models are most reliably good at
producing, and the one a reader is least equipped to catch.

## Reproduce

```bash
cargo run --release -p weftd --example showcase
```

Regenerates every file in this directory. The scenarios, the flawed
contributions, and the validators are all in
[`weftd/examples/showcase.rs`](../../weftd/examples/showcase.rs) — the flawed
contribution in each is marked `flawed: true` with a comment explaining the
realistic mistake it represents.

One honest note: the flaws here are *planted*, so the demo is deterministic
and reviewable. They're modelled on mistakes agents actually make — format
drift, a syntax error inside otherwise-fine code, a fabricated citation —
not strawmen. The gate has no special knowledge of them; it runs the same
validator you'd write for your own repo.
