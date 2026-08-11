# How hard is it to write a gate?

The honest answer, up front: **for most repositories, you don't write one.
You point at the checks you already have.**

A gate's evidence recipe is a command. If your project has a test command,
that command is a valid recipe today, unmodified.

```jsonc
"recipes": [ { "kind": "test", "cmd": ["python", "-m", "pytest", "-q"] } ]
```

That is the entire gate for
[`docs/showcase/existing-tests/`](showcase/existing-tests/) — a real scenario
where three agents extend a module, one of them "improves" a function in a
way that breaks the existing test, and the gate refuses it. Nothing was
written for Weft. `cargo test`, `npm test`, `go test ./...`, `make check`,
`ruff check .` all work the same way.

## The ladder, and what each rung costs you

**Rung 0 — no recipes at all.** `"recipes": []` is legal. You still get
concurrent agents landing without branches, signed provenance on every
change, scoped and revocable capabilities, stale-read detection, and a
hash-chained history. *Cost: nothing.* This is a reasonable place to start.

**Rung 1 — your existing test command.** One line, as above. *Cost: one line.*
This is where most teams should live on day one.

**Rung 2 — add the checks you already run in CI.** A linter, a type checker,
a formatter in `--check` mode. Each is another entry in `recipes`. *Cost: one
line each.* You are not writing new logic; you are moving your CI config over
a line at a time.

**Rung 3 — a domain check for the thing you actually care about.** The
showcase scenarios are all ~10 lines of Python: a CSV schema validator, a
citation checker, a front-matter linter. *Cost: an afternoon, once.* Write it
the way you'd write any small script — it gets a directory of files and exits
non-zero with a message.

**Rung 4 — human approval on sensitive paths.** `"approvals": 1` plus a
capability granting `approve`. *Cost: one line, plus deciding who holds the
key.* Use it where the stakes justify a person.

**Rung 5 — independent judges from distinct trust roots.** For subjective
work — is this prose good, is this analysis sound — require attestations that
chain to different roots, so one compromised or lazy judge isn't sufficient.
*Cost: real design work.* This is the frontier, and the site says so.

Most repositories will be happy between rungs 1 and 3 indefinitely.

## What a recipe actually is

Three fields, and only `cmd` is load-bearing:

```jsonc
{
  "kind": "test",                      // a label for humans and policy
  "image": "local",                    // pin the environment (OCI digest, or "local")
  "cmd":  ["cargo", "test", "--workspace"]
}
```

The gate materializes the candidate state into a scratch directory, runs the
command there with the working directory set to the root of that tree, and
treats **exit code 0 as pass**. That's the whole contract. If your check runs
in CI today, it runs here.

Three properties come free because it's a Weft recipe rather than a CI job:

- **It's pinned by digest.** An agent can't quietly swap the checker for a
  weaker one; the policy names which recipe counts.
- **It's bound to exact bytes.** The evidence references a Merkle manifest of
  the materialized tree, so "tests passed" means *these tests passed on this
  content*, not "green on some branch at some point".
- **It's sandboxed.** With `--sandbox unshare`, recipes run in a fresh user
  and network namespace. A check cannot phone home, and a malicious
  contribution cannot use your gate as a proxy.

That last one has a consequence worth stating plainly: **a recipe has no
network, so an LLM judge cannot be a recipe.** Judges are independent
attestors that sign evidence from outside the gate. Deterministic checks run
inside; judgement signs from outside. See
[the research-paper walkthrough](multi-agent-research-paper.md) for both
halves working together.

## What is genuinely work — no hedging

Grok's review named this, and it's fair:

1. **Key management.** Someone holds the authority key. Agents hold delegated
   capabilities. That is real operational responsibility, and Weft doesn't
   make it disappear — it makes it *explicit* instead of a shared bot token
   nobody audits. Capabilities expire by default, which converts most of the
   problem from revocation to renewal.
2. **Running the hub.** One binary, one port, and a WAL file
   (`weftd --data hub.wal`). It's less than a CI runner, more than nothing.
   See [HOSTING.md](../HOSTING.md).
3. **Deciding policy.** Which paths need approvals, how many attestations,
   whether stale reads reject or warn. This is a judgement call, and it's the
   part you should spend thought on.
4. **A bad check is worse than no check.** A gate that passes everything
   teaches people the gate is meaningless. A gate that flakes teaches agents
   to retry until it's green. Write checks you'd defend in review.

## The trade you're making

Without a gate, a check that isn't run is free and an error that ships is
expensive. With a gate, the check runs every time and the error never becomes
the artifact. The showcase quantifies it on four workloads:
**4/4 unguarded outputs failed their own validator; 4/4 gated outputs passed
it** — with identical agents on both sides.

If you already have tests, your gate is one line away. If you don't, Weft
still gives you provenance and concurrency at rung 0, and the ladder is there
when you want it.
