//! # weft-core
//!
//! Core engine of the **Weft** protocol (RFC-0001, Draft v0.3): version
//! control designed for autonomous agent swarms. Content-addressed signed
//! objects over deterministic CBOR; an RGA line-identity content model with
//! verifiable materialization manifests; capability delegation chains; and
//! the certified-landing checklist that makes verification — not human
//! review — the merge gate.
//!
//! The load-bearing invariant, enforced by test:
//! *∀ permutations of a change set: identical manifest.*

pub mod cbor;
pub mod engine;
pub mod gate;
pub mod object;

pub use cbor::V;
pub use engine::{materialize, patch_deps, patch_paths, Anchor, Mat};
pub use gate::{cap_chain_valid, cap_chain_valid_r, check_landing,
               check_landing_r, closure_ok, closure_summary, make_state,
               state_set, LandingCheck};
pub use object::{as_oid, assemble_obj, h, keygen, make_obj, sig_payload_hash,
                 verify_obj, Oid, Store, CTX};
