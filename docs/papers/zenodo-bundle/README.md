# Weft whitepaper — Zenodo bundle

**Weft: Evidence-Gated Version Control for Autonomous Agent Swarms**
Pranab Sarkar · ORCID 0009-0009-8683-1481 · August 2026 · CC-BY-4.0

## Contents

| File | What it is |
|---|---|
| `weft-whitepaper.pdf` | the paper, 10 pages |
| `source.md` | markdown source of the paper |
| `weft-evidence.tar.gz` | every number in §8, as raw output |
| `ZENODO.md` | paste-ready deposit metadata |

## What's in the evidence archive

- `docs/runs/` — unedited terminal output: the full test suite, the 50-agent
  swarm, the multi-model research paper, the handbook, the benchmarks, the
  Hermes plugin self-test against a live gate, and a clean-machine install.
- `docs/showcase/` — the §8.1 artifacts. For each of four workloads:
  `without-weft/` (agent output merged in arrival order), `with-weft/` (what
  the gate admitted), and `gate.log` (what was refused and why). The same
  validator was run over both directories; its verdict is recorded in each log.
- `rfcs/0001-review-log.md` — all 92 findings from the five review classes
  described in §7.2, each with its disposition.

## Reproducing the paper

```bash
pandoc source.md -o weft-whitepaper.pdf --pdf-engine=xelatex \
  --toc --toc-depth=3 -N \
  -V mainfont="Calibri" -V monofont="Consolas" \
  -V fontsize=11pt -V geometry:margin=1in \
  -V colorlinks=true -V linkcolor=black -V urlcolor=blue
```

Requires pandoc 3.x and XeLaTeX (MiKTeX or TeX Live).

## Reproducing the results

```bash
git clone https://github.com/spranab/weft && cd weft

cargo test --workspace                              # §7.1  18 tests, 8 suites
cargo run --release -p weftd --example showcase     # §8.1  4/4 vs 4/4
cargo run --release -p weftd --example swarm        # §8.2  50 agents, 100 tasks
cargo run --release -p weftd --example bench        # §8.4  protocol overhead
ollama serve && cargo run --release -p weftd --example paper   # local models
```

The showcase and swarm figures are deterministic across runs. Benchmark
figures in §8.4 are machine-dependent; the reported values come from a
32-core Windows workstation with an in-memory store. The `paper` example
performs live local-model inference, so its prose differs per run — the
gate's verdict on the fabricated citation does not.

## Honest scope

The flawed contributions in §8.1 are planted, so the comparison is
deterministic and reviewable. They are modelled on observed agent failure
modes — format drift, a syntax error inside otherwise-plausible code, a
fabricated citation, a redefinition that breaks an existing test — but this is
a controlled demonstration rather than a field study. Weft has not been
evaluated on a large production repository under sustained multi-agent load;
§9 states this as the most important missing evidence.
