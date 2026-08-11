# Walkthrough: four agents write a research paper

The question this answers: *what actually changes when a swarm produces a
document instead of code?*

Short version — the same thing that changes for code. Work gets checked
against machine-verifiable criteria before it's part of the artifact, and
every paragraph keeps a signed trail back to the model and human authority
that produced it.

## Run it (real local models, ~2 minutes)

```bash
ollama serve                                       # any local model
cargo run --release -p weftd --example paper
```

Four agents write four sections of a paper concurrently — each is a real
local model call — and submit them to a gate. One of them fabricates a
citation, the way real models do.

```text
weft · four agents write a research paper

  topic     verification-gated merging for autonomous coding agents
  inference local — ollama/gemma4:e4b

  references landed — the citable ground truth

  agents writing (concurrently)…
    claude-fable-5 wrote paper/abstract.md (3 lines)
    gpt-5.6-sol wrote paper/background.md (2 lines)
    qwen3.8-max wrote paper/method.md (7 lines)
    local-drafter wrote paper/findings.md (2 lines)

  gate…
citation-check: paper/findings.md: citation [9] is not in references.md
citation-check: ok

  ── the paper ──
    ✓ paper/abstract.md
    ✓ paper/background.md
    ✓ paper/method.md
    ✓ paper/references.md
    ✗ paper/findings.md — refused
```

Configure with `WEFT_LLM=qwen3.6:27b`, `WEFT_JUDGE=...`, `WEFT_OLLAMA=...`.
No Ollama? It falls back to canned sections and the gate story is identical.

## What just happened

1. **A human landed the references first** — the citable ground truth every
   agent must write against.
2. **Four agents worked concurrently**, each holding its own scoped,
   expiring capability, each signing its own section.
3. **The gate ran a citation checker** on the exact materialized bytes:
   every `[n]` marker must resolve in `references.md`, every section needs
   front-matter. Deterministic, offline, pinned by digest so no agent can
   quietly swap the checker.
4. **A judge attested quality** — with its own key, from *outside* the
   sandbox. That's not an accident of implementation: gate-executed recipes
   have no network, so an LLM judge cannot be a recipe. It is an independent
   attestor signing evidence, which is exactly what `distinct_roots` is for.
   Deterministic checks run inside the gate; judgement signs from outside it.
5. **The batch failed, and bisection isolated the culprit.** Three sections
   landed; the one citing `[9]` did not. Innocent work was not punished for
   its neighbour.

## Traditional vs Weft, on the same workload

| | Traditional | Weft |
|---|---|---|
| Merging four agents' work | four branches; a human concatenates and skims | disjoint sections commute into certified landings |
| The fabricated `[9]` | ships unless a reviewer checks every bracket by hand | never lands — the checker ran on the exact bytes |
| Blast radius of one bad section | the whole batch is reverted, or nothing is | bisection isolates it; the other three land |
| "Which model wrote this paragraph?" | reconstructed from chat logs, if at all | signed provenance: model → delegation → authority key |
| "What proved this was acceptable?" | a green check on a branch, somewhere | evidence bound to a Merkle manifest of those bytes |
| Revoking a contributor | rotate a shared token, hope | revoke the capability; certified history stays valid |

The honest framing: none of this makes an agent *smarter*. It makes the
difference between "an agent claimed this is fine" and "this passed a
check you chose, on these exact bytes, and here's who authorized it."

## Doing this with Hermes agents

Install the plugin, point it at a hub, and give each agent a section.

```bash
source ~/.hermes/hermes-agent/venv/bin/activate
hermes plugins install spranab/weft-hermes-plugin
pip install requests cryptography
export WEFT_HUB=http://127.0.0.1:8747
```

Start a hub and create the repo (console at `http://localhost:8747`):

```bash
cargo run --release -p weftd
```

### The human's setup prompt

> Using the weft tools: call `weft_status` to confirm you're connected, then
> create three intents with `intent_create` — "abstract", "background",
> "method" — each with the acceptance criterion *"every bracketed citation
> resolves in paper/references.md"*. Then show me your public key so I can
> delegate a capability.

Paste that key into the console → **Access → Contributor → 24 hours → Mint**.
(Until you do, every write is refused *with the key to authorize* — that
refusal is the onboarding step, not an error.)

### The writer-agent prompt (run one per agent)

> You are writing the **{SECTION}** section of a paper on {TOPIC}.
>
> 1. `weft_workspace` — read `paper/references.md`. You may cite **only**
>    the numbers listed there. Do not invent citations.
> 2. Draft 4–6 sentences of plain prose. No headings, no fences.
> 3. `weft_submit` with `create: true` for `paper/{section}.md`, front-matter
>    (`---` / `title:` / `---`), a `## {SECTION}` heading, then your prose.
> 4. Report the outcome verbatim. If it is `rejected`, read the reason, fix
>    the actual problem, and resubmit. Do not weaken the check.
>
> You are one of several agents writing concurrently. Touch only your own
> file — the gate serializes overlapping work and rejects stale reasoning.

### The reviewer-agent prompt (the judge)

> Call `weft_status`. For each entry under `pending_approvals`, review the
> changes against this rubric: prose is specific rather than filler, claims
> that need support carry a citation, and the section matches its title.
> If it passes, call `approve` with that manifest. If not, say why and
> approve nothing — a withheld approval is a valid outcome.

### What you'll see

Agents that cite honestly land. An agent that fabricates a citation gets
`rejected` with the exact reason, fixes it, and resubmits — no human read a
diff to make that happen. Then:

```bash
weft export --git ./paper     # conventional git commits, provenance in trailers
```

and every commit carries `Weft-Change`, `Weft-Model`, `Weft-Author-Key`.

## Where this goes next

The demo's citation checker is deliberately simple. The same slot takes a
fact-checker against source documents, a schema validator, a plagiarism
check, a numerical-claims verifier, or several independent model judges
required to chain to *distinct trust roots* — which is the real answer to
"who verifies the verifier" for subjective work. Policy declares what
combination is sufficient; the gate enforces it.

See also: [`--example docs`](../weftd/examples/docs.rs) (a handbook, same
pattern, smaller), [`--example swarm`](../weftd/examples/swarm.rs) (50
agents on code), and [integrations/](../integrations/) for the MCP and
native-plugin paths.
