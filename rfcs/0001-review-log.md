# RFC-0001 Adversarial Review Log

*(Both reviews were conducted against v0.1, when the protocol's working name
was "AGC"; it was renamed **Weft** alongside the v0.2 revision. Section
references below are to v0.1 numbering.)*

RFC-0001 v0.1 was submitted to two frontier models acting as independent
adversarial reviewers: **GPT-5.6-sol** (via codex CLI, reading the spec from
disk) and **Qwen 3.8 Max** (via API). Instructions: attack technical soundness,
adoption risk, and missing primitives; no praise permitted. Every finding gets a
disposition here, and accepted findings are integrated in RFC-0001 v0.2.

Legend: **ACCEPT** (integrated as proposed) · **MODIFY** (integrated with
changes, reason given) · **DEFER** (real, but scoped to a later version) ·
**REJECT** (reason given).

---

## Review A — GPT-5.6-sol (27 findings)

### Technical unsoundness

| # | Sev | Finding | Disposition |
|---|---|---|---|
| A1 | FATAL | Genesis OID is a hash fixed-point: envelope requires `repo: <genesis-oid>` but Genesis *is* that object. | **ACCEPT.** Genesis carries `repo: null`; repo ID = Genesis OID. (§4.1, §5.1) |
| A2 | MAJOR | Line/file-IDs embed `this-change-oid`, but Change OID depends on Patch OID → hash cycle; and one Patch referenced by two Changes yields ambiguous identity. | **ACCEPT.** Identities now derive from **Patch OID**: `(patch-oid, ordinal)`. Patch gains `nonce`; a Patch is bound to exactly one Change and validators reject a second claimant. Intrinsic deps reference patch-oids. (§5.7–§6.1) |
| A3 | FATAL | Signed counter + local CAS is not a distributed CAS; two authorized writers permanently split a ref across peers. | **ACCEPT** — superseded by the Landing log (A27). Protected refs are now an explicit CP service. (§7) |
| A4 | FATAL | Ref acceptance never required the new State to contain the old one → authorized silent history deletion. | **ACCEPT.** Landing validation requires `target = base ∪ closure(delta)`, no removals; reverts are explicit new Changes. (§7.3) |
| A5 | FATAL | "Active policy = newest Policy in the State of the policy ref" — Policies are not members of States, and "newest" is undefined in an unordered set. | **ACCEPT.** Policy activation is now explicit: each Landing names the active `policy`; a Landing may carry `policy_next` (gated by the current policy) to activate a successor. The separate `policy` ref is removed. (§5.12, §7.3) |
| A6 | FATAL | Capability expiry/revocation retroactively invalidates already-merged history. | **ACCEPT.** Authorization is frozen at **certification time**: a certified Landing remains valid forever; expiry/revocation only affects future acceptance. (§5.4, §7.3, §12.2) |
| A7 | FATAL | Quorum authority actions declared but no multisignature format exists. | **ACCEPT.** The `certificate` object (key-sorted signature collection over a target OID) is now normative, used for Landings and authority actions. (§7.2) |
| A8 | MAJOR | Only Change names its capability chain; ten other object types have no authorization field and no action vocabulary. | **ACCEPT.** Envelope gains `auth: <capability-oid>` (required for all types except `genesis`/`identity`); normative action-mapping table added. (§4.1, §5.3) |
| A9 | MAJOR | Path-scoped authorization is state-dependent (ops name fids, not paths) — same Change authorized in one State, not another. | **MODIFY.** Scope is evaluated **at certification against the Landing's base State** (base path of each touched fid ∪ resulting paths). Attenuation containment uses a conservative syntactic-refinement rule (normative appendix). Cheaper than per-State proofs; deterministic because certification is now a serialized event. (§5.3, §7.3) |
| A10 | FATAL | "Topological order + OID tiebreak" does not define a total order; multi-line insert semantics unspecified. | **ACCEPT.** Normative RGA traversal: a multi-line insert forms a chain (each line anchors on its predecessor); materialization is depth-first from START, visiting each anchor's child inserts in descending patch-OID order; tombstones traversed but not emitted; test vectors required of `agc-core`. (§6.2) |
| A11 | MAJOR | Same-anchor concurrent inserts flagged as conflicts turns routine additive work (EOF appends, import lists) into permanent false conflicts. | **MODIFY.** `order` overlap is downgraded from conflict to **advisory marker** — deterministic OID order applies, the State stays clean, and evidence catches semantic breakage (the protocol's own thesis). Policy may escalate markers to conflicts for designated paths. `edit-delete` and `tree` remain true conflicts. (§6.3) |
| A12 | MAJOR | Byte-for-byte determinism claimed but no canonical byte model (newlines, encodings, path rules, symlinks, collisions). | **ACCEPT.** New §6.4 canonical VFS: lines are byte strings sans terminator, LF-joined, per-file final-newline flag; paths UTF-8/NFC/`/`-separated with forbidden-component rules; files are exclusively line-mode or blob-mode; case-collision handling defined. (§6.4) |
| A13 | FATAL | Policy counts evidence by `kind` — two signed *failure* reports or two no-op commands satisfy a test requirement. | **ACCEPT.** Policy requirements now pin **recipe digests** (or intent criteria refs); all results must be `pass`; subject must equal the Landing's target State; the Landing enumerates exactly which Evidence counted. (§5.11–§5.12, §7.3) |
| A14 | FATAL | "Independent attestations" = distinct keys = Sybil-trivial for anyone with delegation authority. | **MODIFY.** Policy attestor constraints: `from:` root sets and `distinct_roots: n` — attestors must chain to *distinct listed trust roots*, not merely distinct keys. Honestly acknowledged: signatures prove claims, not execution; hardware attestation is out of scope for v1. (§5.12, §12.3) |
| A15 | FATAL | Partial replication contradicts mandatory validation — filtered nodes can't validate what they don't have. | **ACCEPT** — resolved by the Landing model: only **gate nodes** validate fully; everyone else verifies certificates (light-client model). Changes gain a certified `footprint` (declared touched paths, checked at certification) enabling path-filtered trust. (§7.4, §8) |
| A16 | MAJOR | No atomicity: ref update can arrive before its objects; GC roots undefined; different arrival orders → different decisions. | **ACCEPT.** A Landing enumerates its full closure and is applied only when the closure is present; GC roots = the certified Landing log ∪ coordination objects within the horizon. (§7.3, §8, §12.4) |
| A17 | FATAL | Exact-State evidence + landing race = livelock: 49 of 50 agents' evidence invalidated per landing; starvation at scale. | **ACCEPT.** The gate is a **serializing merge queue**: it batches compatible proposals, fixes the target State first, then acquires evidence once for that State. Compositional/selective re-verification specified as the v0.2 priority (§15) with the footprint field already in place for it. (§7.5) |
| A18 | FATAL | Full-list States grow quadratically; unsuitable for the stated workload before v0.2. | **ACCEPT.** State becomes **delta-form**: `{base: <state-oid>, add: [...]}` with recursive summary digest; full-form allowed for small sets. Merkle set-tree remains v0.2 for proofs, but quadratic transfer/hashing is fixed in v0.1. (§5.10) |
| A19 | FATAL | Git bridge: nondeterministic export rules; undefined import parent semantics; two competing authorities for trunk. | **MODIFY.** Per-ref **ownership rule**: exactly one side is authoritative (`export` or `import` mode), the other is a read-only mirror; synthesis rules pinned (fixed committer identity, timestamps from landing seq). Full field-level determinism spec moves to the implementation guide. (§10) |
| A20 | FATAL | Line-identity model performs worst on agent-typical changes (formatters, codegen, lockfiles); position→identity translation ambiguous under duplicates/moves. | **MODIFY** — partially conceded. New Limitations section (§6.5): generated files should use blob-mode (`generated` attr); translation heuristics documented as non-normative client behavior; the epoch/compaction primitive (A25) addresses identity churn. Core stays line-based: every alternative (AST, pure snapshot) fails worse on the design-center workload. |
| A21 | FATAL | Gates execute repository-controlled commands; `instruct` doesn't cover executable recipes; containers ≠ sandbox; provenance labels don't stop injection already in context. | **ACCEPT.** Gates only execute recipes whose authoring chain carries `instruct`; normative sandbox minimums (no network by default, no ambient secrets, resource caps); `is_instruction` reframed as per-object provenance labeling with mixed-authorship files always data; honest limits stated. (§12.1, §12.5) |

### Missing agent-native primitives

| # | Sev | Finding | Disposition |
|---|---|---|---|
| A22 | FATAL | No read-set/observed-state dependency — concurrent change to what an agent *read* invalidates its reasoning yet commutes silently. | **ACCEPT.** `provenance.reads`: content digests of observed paths + observed intent/note OIDs; gate detects stale reads at certification; policy chooses `reject` or `warn`. The most agent-native finding of the review. (§5.7, §7.3) |
| A23 | MAJOR | No work-attempt/proposal lifecycle; Intent lacks even a target ref. | **ACCEPT.** New `proposal` object — the unit submitted to the gate queue: base, delta, evidence refs, lifecycle (`open/landed/superseded/withdrawn/failed` via supersession). Intent gains `ref`. (§5.14, §7.5) |
| A24 | MAJOR | No compositional proof — all evidence is whole-State, causing A17. | **DEFER** to v0.2 (§15) with the design sketch and the `footprint` groundwork landed in v0.1. Doing this right needs implementation data. |
| A25 | MAJOR | No checkpoint/identity-compaction — tombstones and creator patches reachable forever. | **DEFER** to v0.2 (§15): signed `epoch` objects introducing compact identities + verifiable old→new mapping. |
| A26 | MAJOR | Execution provenance too weak for incident reconstruction. | **ACCEPT** (light form): `provenance.manifest` — digest-bound, selectively disclosable execution manifest blob; schema in the implementation guide. (§5.7) |

### Highest-leverage improvement

| # | Sev | Finding | Disposition |
|---|---|---|---|
| A27 | FATAL | Replace mutable ref updates with a quorum-certified **Landing log** + gate merge queue (full design supplied). | **ACCEPT wholesale.** This is the centerpiece of v0.2: per-ref gate sets and thresholds in Genesis (`n=q=1` solo → BFT quorums), landing objects binding base/delta/target/policy/evidence/authorizations, certificates, contiguous-log ref resolution. It simultaneously resolves A3, A4, A5, A6, A15, A16, and hosts the A17 fix. (§7) |

---

## Review B — Qwen 3.8 Max (50 findings)

Findings that duplicate Review A are marked ≈A*n* and share that disposition.
The duplication itself is signal: two independent frontier reviewers converging
on the same defects is the strongest confirmation those defects were real.

### Encoding & addressing

| # | Sev | Finding | Disposition |
|---|---|---|---|
| B1 | FATAL | OID vs signature construction is circular/ambiguous (is `sig` inside the hashed envelope?). | **ACCEPT.** Normative order: sign the pre-`sig` fields (with domain-separation context), then OID = hash of the complete signed envelope. (§4) |
| B2 | FATAL | "Preserve unknown fields" contradicts canonical re-serialization by relays. | **ACCEPT.** The canonical bytes **are** the object: relays and stores pass bytes verbatim and never re-serialize; canonical form is an authoring-time obligation checked at validation. (§4) |
| B3 | FATAL | Genesis self-reference. | ≈A1. |
| B38 | MINOR | Display OIDs have no checksum. | **ACCEPT.** Display encoding gains a bech32m-style checksum. (§4) |
| B39 | MINOR | No domain separation in signatures. | **ACCEPT.** Signing context `"agc/0.1" ‖ repo ‖ type` prepended. (§4) |

### Content model & materialization

| # | Sev | Finding | Disposition |
|---|---|---|---|
| B5 | FATAL | RGA order not uniquely defined. | ≈A10 — normative traversal algorithm added. |
| B6 | FATAL | Conflicts are unverifiable side-band data — no object, no hash, no policy visibility. | **ACCEPT** via B50: the **materialization manifest**. Conflicts become Merkle-rooted, hashable, policy-visible facts. (§5.14, §6.3) |
| B7 | FATAL | Intrinsic dependencies incomplete for `rmfile`/`move`/`putblob`/`setattr`/same-path `mkfile`. | **ACCEPT.** Per-operation dependency rules table added; tree-namespace collisions handled at materialization and recorded in the manifest. (§6.1) |
| B20 | FATAL | Position→line-ID translation has no working-copy identity index; unimplementable. | **MODIFY.** The workspace format (base manifest + identity index) is named and required, with its schema in the implementation guide — client-local, not wire-visible, so it does not belong in the protocol's object model. (§9) |
| B21 | FATAL | `putblob` undefined against the line model. | **ACCEPT.** Files are exclusively line-mode or blob-mode; explicit `to_blob`/`to_lines` transition ops with defined tombstoning and cross-mode conflict semantics. (§5.8) |
| B22 | MAJOR | No directories/metadata parity (ignore rules, submodules, …). | **MODIFY.** Directories stay implicit (non-goal); ignore rules, limits, merge drivers move to the new `config` object; submodules deferred with rationale. (§5.17, §13) |
| B23 | MAJOR | Chunking declared but chunk-list object absent. | **ACCEPT.** Minimal `chunklist` object specified. (§5.9) |
| B41 | MINOR | Note anchors dangle on tombstoned lines. | **ACCEPT.** Anchors to tombstoned identities stay valid (notes reference history); resolution semantics defined. (§5.18) |
| B42 | MAJOR | Missing: content-addressed materialization manifest. | **ACCEPT** — B50, adopted wholesale. |
| B50 | FATAL | Highest-leverage: normative `manifest` object `{state, algorithm, tree_root, file_map_root, conflict_root, clean}` bound into Evidence and ref advancement. | **ACCEPT wholesale.** Composes with Review A's landing log: a Landing certifies (state, manifest, evidence) together. The two reviews' flagship fixes interlock. (§5.14, §7) |

### Refs, policy, capabilities

| # | Sev | Finding | Disposition |
|---|---|---|---|
| B10, B11, B43, B46 | FATAL/MAJOR | Ref CAS divergence; rollback; need hash-chained ref log; need atomic batch landing. | ≈A3/A4/A27 — the Landing log is exactly the hash-chained, atomic, batched ref log both reviewers demanded. |
| B4, B13 | FATAL | Policy-in-State structurally impossible; "newest" undefined. | ≈A5. |
| B12 | FATAL | Policy bootstrap impossible — genesis names no initial Policy. | **ACCEPT.** Genesis embeds `policy_init` (and `config_init`) OIDs. (§5.1) |
| B14 | FATAL | Evidence matching too weak to gate merges. | ≈A13. |
| B15, B16 | FATAL | Capability temporality undefined; revocation scope ambiguous. | ≈A6, plus normative revocation-scope table (revoke-cap vs revoke-key semantics). (§5.4) |
| B17 | FATAL | Glob attenuation undecidable as written. | ≈A9 — conservative syntactic-refinement rule. |
| B18 | FATAL | Action vocabulary can't express the protocol's own operations. | ≈A8 — full action-mapping table, including `read`, `attest`, `propose`, `land`. |
| B19 | FATAL | Intent satisfaction unstable; no target ref; `closes` unauthorized. | ≈A23 + `closes` honored only when certified by a Landing on the intent's target ref. (§5.5, §7.3) |
| B45 | MAJOR | Missing: quorum multisig + authority rotation. | ≈A7 + new `amendment` object for certified authority rotation. (§5.4a) |

### Evidence & trust

| # | Sev | Finding | Disposition |
|---|---|---|---|
| B24 | MAJOR | Recipe pinning insufficient for reproducibility. | ≈A14 (honesty amendments): the spec now claims *re-runnability with bounded variance*, not determinism. (§12.3) |
| B25 | MAJOR | Evidence logs unbounded — DoS vector. | **ACCEPT.** Normative size caps; logs are external blobs referenced by digest. (§5.15) |
| B33, B49 | MAJOR | Attestor independence gameable; no runner attestation. | ≈A14; runner attestation explicitly deferred with design sketch. (§15) |
| B35 | MAJOR | Identity `meta` claims (operator, model) are self-asserted — impersonation trivial. | **ACCEPT.** Operator/model claims require counter-signature by the claimed operator key; otherwise display-only. (§5.2) |
| B36 | MAJOR | `provenance.onbehalf` is forgeable free text. | **ACCEPT.** `onbehalf` is now **computed** from the capability chain's audience sequence, never asserted. A clean example of deriving trust instead of declaring it. (§5.7) |

### Sync, interfaces, adoption

| # | Sev | Finding | Disposition |
|---|---|---|---|
| B8, B27, B44 | FATAL/MAJOR | Partial nodes can't validate; no touched-path index. | ≈A15 — certified footprints + light-client certificate verification. |
| B9 | FATAL | Full-list States infeasible. | ≈A18 — delta-form States in v0.1. |
| B26, B47 | FATAL/MAJOR | No read authorization; private repos impossible. | **MODIFY.** `read` capability action added and enforced at sync (node-level ACL) in v0.1; object-level E2E encryption remains v0.2 — honest layering, stated as such. (§8.2, §15) |
| B28 | MAJOR | No subscription cursors/replay/delivery guarantees. | **ACCEPT.** Cursors, resume, at-least-once delivery specified. (§8.3) |
| B29 | FATAL | Git bridge too lossy to be credible. | ≈A19 + explicit lossy-import table (what is preserved vs flattened). (§10) |
| B30 | FATAL | MCP-only is an adoption bottleneck. | **MODIFY.** The sync protocol is the wire API; `agchubd` additionally exposes the same tool surface over plain HTTP/JSON-RPC; SDKs on the roadmap. MCP stays the *primary agent* interface, not the only interface. (§9) |
| B31 | MAJOR | Human governance not operational. | **MODIFY.** The enforceable gate already exists (approval evidence + policy); assignment/notification are subscription consumers, spec'd as reference-UI behavior, not protocol. (§11) |
| B32 | MAJOR | `instruct` labeling is advisory, not control. | ≈A21 — reframed honestly as provenance-based labeling that converts injection into a detectable policy violation; never claimed to constrain model behavior. (§12.1) |
| B34 | MAJOR | GC/retention undefined for audit. | ≈A16 + retention windows in `config`. (§5.17, §12.4) |
| B37 | MAJOR | Lease storms; no renewal/observability. | **MODIFY.** Renewal-by-supersession and subscription observability defined; duplicate-work throttling stays an orchestrator concern (protocol provides the visibility, not the scheduler). (§5.6) |
| B40 | MINOR | `summary` digest redundant. | **ACCEPT.** Repurposed as the delta-form recursive digest, now load-bearing. (§5.10) |
| B48 | MAJOR | Missing repo config/metadata object. | **ACCEPT.** New `config` object, activated via Landing like Policy. (§5.17) |

---

## Review C — Implementation testing (prototype, 2026-08-09)

The strongest review turned out to be the compiler. An executable subset of
v0.2 was built (`prototype/`: real deterministic CBOR, real Ed25519, the RGA
engine with manifests, capability chains, and a live gate server) and run:
a 300-scenario × 8-permutation determinism fuzzer (0 violations, Windows and
Linux), plus a live three-agent swarm through a `weftd` gate in WSL Ubuntu
with light-client verification across the OS boundary (PASS). Building it
surfaced **six defects neither model review caught**:

| # | Sev | Finding (confirmed by execution) | Disposition |
|---|---|---|---|
| W1 | MAJOR | §6.2 pins sibling order across patches (descending patch-OID) but not *within* a patch: two insert ops in one patch at one anchor have no specified relative order. | **ACCEPT.** Normative: ordinal-ASCENDING within a patch; full sibling key is (patch-OID desc, ordinal asc). (§6.2) |
| W2 | MAJOR | §6.3's conflict table has no row for `rmfile` vs a concurrent edit of the same file — the fuzzer's T5 case falls through every class. | **ACCEPT.** New `edit-rm` conflict class. (§6.3) |
| W3 | FATAL | §5.1 `policy_init: <policy-oid>` is a cross-object hash cycle: a policy envelope must bind `repo` (= the genesis OID), so genesis cannot reference it by OID. Same for `config_init`. The A1 fix (`repo: null` on genesis) was necessary but not sufficient — bootstrap *references* cycle too. | **ACCEPT.** Genesis embeds initial policy and config bodies **inline**; their digests, not OIDs, are what later landings chain from. (§5.1) |
| W4 | MAJOR | §5.10's recursive delta summary is representation-dependent: the same closure reached via different base/add splits yields different summaries (fuzzer T6 proves it). "Load-bearing for cheap equality" is false. | **ACCEPT.** `summary` = digest of the full sorted closure, computable incrementally from the base summary only when splits are append-only along one chain; equality checks MUST use closure digests, never delta-shape. (§5.10) |
| W5 | FATAL | A single patch cannot create a file and populate it: its `insert` would reference a file-ID containing its own patch OID — a self-hash-cycle. (The concrete manifestation of A2's warning, one level down.) Every scaffold-and-fill change needs two patches under v0.2 rules. | **ACCEPT.** `SELF` sentinel: intra-patch identity references use `[null, ordinal]`, resolved to the enclosing patch's OID after hashing. (§5.8) |
| W9 | FATAL | §6.3's `edit-delete` class fired on *sequential* history, not just concurrent edits: every multi-line insert is a chain (line N+1 anchors line N), so deleting ANY non-terminal line made the state permanently conflicted — mid-file deletion was effectively impossible. Found when the swarm demo's refactor task was silently rejected as "conflicted" and the stale-read scenario never triggered. | **ACCEPT.** Conflict requires the insert and delete to be **concurrent** — neither patch in the other's dependency closure (memoized reachability over intrinsic deps). Sequential edits are normal history. (§6.3) |
| W8 | MINOR | §5.5 declared `priority: 0.0-1.0`, but the deterministic-CBOR subset (§4) deliberately excludes floats — the field was unrepresentable. Found when weft-mcp's intent_create hit the canonical encoder. | **ACCEPT.** Integer `priority: 0-100`. (§5.5) |
| W7 | MINOR | Manifest roots are "over canonical records" but the record *sort order* was unpinned — the Python prototype sorted by Python list comparison, the Rust core by encoded bytes; same conflicts, different roots. Found while porting to Rust. | **ACCEPT.** Normative: records sorted by their canonical CBOR encoding. (§5.11) |
| W6 | MAJOR | Whole-file `reads` digests make append workflows self-stale: two agents appending to one file each invalidate the other's read of it, though neither invalidated the other's *reasoning*. Observed live in the swarm demo (spurious stale-read warnings on every EOF race). | **MODIFY.** `reads` entries gain optional line-range scope (`{path, lines: [line-ID…], digest}`); gates check region digests when present, whole-file otherwise; a change's own footprint is excluded from its staleness check. (§5.7) |

Empirical results worth recording: the certified-landing pipeline worked as
designed on first full run — the gate batched footprint-disjoint proposals
into one landing, serialized overlapping ones, surfaced `order` markers on
the same-anchor append race, executed the pinned recipe in its sandbox, and
a Windows light client re-materialized the Linux gate's state to identical
manifest roots. Set-semantics ordering was visible in practice: a later
landing's line sorted *above* an earlier one's at the same anchor, per OID
order, identically on both OSes.

## Review D — Public positioning review (ChatGPT, 2026-08-10)

After publication, an unsolicited external review (ChatGPT, reading the
public repo) assessed the technical idea and architecture at 9/10 and raised
strategy-level findings rather than protocol defects:

| # | Finding | Disposition |
|---|---|---|
| D1 | "Version control for AI agents" invites a fight about Git instead of a conversation about verification; position as a **coordination and verification protocol / execution ledger**, with git as import/export. | **ACCEPT.** README, repo description, and pitch reframed; the human-vs-autonomous pipeline diagram added. |
| D2 | The git bridge is existential for adoption (`weft clone` → agents work → export conventional commits) and belongs at the top of the roadmap, not the bottom. | **ACCEPT.** Roadmap reordered — bridge is the next milestone after this revision. |
| D3 | Verification quality is the real bottleneck: "who verifies the verifier" (agent writes bug + bad test → 'verified'). Heterogeneous evidence quorums (compiler + tests + property + independent model reviews + runtime traces) with weighted policy. | **ALIGNED.** Already §15's top item (compositional evidence) + attestor trust roots (A14); §15 wording strengthened with the verifier-quorum framing. |
| D4 | The protocol is sophisticated before there is a killer demo — build the "50 agents, 100 tasks, no branches, no PRs" demonstration with a visible scoreboard. | **ACCEPT.** `weftd/examples/swarm.rs` ships exactly that; gate hardened (per-proposal pre-check, solo bisection on batch evidence failure) so the numbers are honest. |
| D5 | Instruction provenance deserves headline treatment — protocol-level answer to repository prompt injection. | **ACCEPT.** `/workspace` now labels every file `instruction` vs data from live-line authorship capability chains; weft-mcp banners untrusted files. |
| D6 | Keep Weft independent of YantrikDB: memory substrate (knows) vs action substrate (did/proved) vs capability substrate (can); interoperate, don't merge. | **ACCEPT** — matches the standing design intent; Weft `note` objects remain the auditable layer YantrikDB may *observe*, never the reverse. |

## Outcome

- **v0.2 integrates:** the Landing log (A27 ≡ B43/B46), the materialization
  manifest (B50 ≡ A-implied), certification-time authorization freezing,
  patch-derived identities, pinned-recipe pass-semantics evidence,
  attestor trust roots, delta-form states, read-set dependencies, proposals,
  the `config` object, computed `onbehalf`, canonical VFS byte model, and the
  normative RGA traversal.
- **Deliberately deferred (with groundwork landed):** compositional evidence,
  epoch/identity compaction, E2E encryption, runner attestation, Merkle set
  states.
- **Rejected:** nothing outright — every finding was either integrated,
  integrated in modified form, or deferred with rationale.

