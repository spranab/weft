# Zenodo deposit metadata — paste-ready

**Upload manually at https://zenodo.org/uploads/new.** Do *not* use the
GitHub–Zenodo release integration for this: it auto-publishes before the
metadata can be corrected, and it defaults the title to the release name, the
description to release notes, the resource type to *Software*, and the author
to the GitHub login.

## Files to attach (in this order)

1. `weft-whitepaper.pdf` — the paper (10 pages)
2. `source.md` — markdown source, for reproducibility of the rendering
3. `weft-evidence.tar.gz` — the evidence referenced in §8: all recorded runs,
   the showcase artifacts (with/without gate, plus gate logs), and the complete
   review log with 92 dispositioned findings

## Resource type

**Publication → Preprint**

## Title

```
Weft: Evidence-Gated Version Control for Autonomous Agent Swarms
```

## Authors

| Field | Value |
|---|---|
| Name | `Sarkar, Pranab` |
| ORCID | `0009-0009-8683-1481` |
| Affiliation | *(leave blank — independent)* |

Paste the ORCID into the dedicated **Author ORCID** field, not the description,
so the record auto-pushes to ORCID Works.

## Description / abstract

```
Version control systems assume that a human reads each change before it is integrated. Commit messages are prose for a reader; pull requests exist to partition work into human-reviewable units; branch protection encodes "someone approved this." Autonomous coding agents violate that assumption by roughly two orders of magnitude in throughput, leaving practitioners to choose between throttling agents to human reading speed and abandoning pre-integration verification altogether. This paper presents Weft, a version-control and coordination protocol in which integration is gated by machine-checkable evidence bound to exact content rather than by human attention. Weft contributes: a change object carrying an explicit read-set, enabling detection of semantically stale work whose textual footprint does not conflict — a failure class three-way textual merge cannot observe; evidence bound to a Merkle materialization manifest, so an attestation refers to specific bytes rather than a mutable reference; capability-based agent identity with authorization frozen at certification time, so credential expiry and revocation cannot retroactively invalidate history; and a batching-and-bisection gate that amortizes verification across commutable work while isolating faults. A reference implementation in approximately 7,000 lines of Rust is evaluated on four workloads spanning code, structured data, and prose. Across all four, output assembled without a gate fails its own validator while gated output passes; a 50-agent, 100-task workload lands 82 changes in 15 certified landings, refusing 8 of 8 stale-read changes, 8 of 8 seeded defects, and 3 of 3 revoked credentials. The specification underwent adversarial review by two frontier language models, an executable prototype, continuous integration, and public critique, yielding 92 dispositioned findings.
```

## License

**Creative Commons Attribution 4.0 International (CC-BY-4.0)**

Note on the choice: prior deposits used CC-BY-NC-ND-4.0. CC-BY-4.0 is
recommended here because this paper documents a protocol whose adoption
depends on others being free to quote, adapt, and build derivative
specifications; ND in particular would discourage exactly that. The
implementation is MIT. Change it in the form if you prefer the stricter
precedent.

## Keywords

```
version control
autonomous agents
multi-agent systems
software verification
optimistic concurrency control
CRDT
capability-based security
supply chain attestation
```

## Related identifiers

| Relation | Identifier |
|---|---|
| *is supplement to* | `https://github.com/spranab/weft` (URL) |
| *is documented by* | `https://weftgate.com` (URL) |

If you want it linked to the earlier substrate papers, add
*is related to* → the relevant Zenodo DOIs.

## Version

`1.0`

## After publishing

1. Add the assigned DOI to the repository `README.md` and `CITATION.cff`.
2. Add a `Cite this paper` line to https://weftgate.com.
3. The record auto-pushes to ORCID Works; confirm it appears.
4. Do **not** paste any API token into a shell that logs — a prior session
   leaked a Zenodo token prefix into an error trace.
