//! States (delta form, closure-digest summaries — finding W4), capability
//! chains (RFC §5.3), and the landing certification checklist (RFC §7.3).

use crate::cbor::{encode, V};
use crate::engine::{materialize, patch_deps, patch_paths, Fid};
use crate::object::{as_oid, h, make_obj, Oid, Store};
use ed25519_dalek::SigningKey;
use std::collections::{BTreeMap, BTreeSet};

// ------------------------------------------------------------- states ------

pub fn state_set(store: &Store, state: &Oid) -> BTreeSet<Oid> {
    let mut out = BTreeSet::new();
    let mut cur = Some(*state);
    while let Some(s) = cur {
        let body = store.body(&s);
        for c in body.get("add").and_then(V::arr).unwrap_or(&[]) {
            out.insert(as_oid(c));
        }
        cur = match body.get("base") {
            Some(V::Null) | None => None,
            Some(b) => Some(as_oid(b)),
        };
    }
    out
}

/// Summary = digest of the FULL sorted closure (finding W4: never the
/// delta shape). Equal closures ⇒ equal summaries, regardless of split.
pub fn closure_summary(closure: &BTreeSet<Oid>) -> Oid {
    h(&encode(&V::Arr(closure.iter().map(|c| V::Bytes(c.to_vec())).collect())))
}

pub fn make_state(sk: &SigningKey, repo: Oid, base: Option<Oid>, add: &[Oid],
                  store: &mut Store, ts: i64) -> Oid {
    let mut closure = base.map(|b| state_set(store, &b)).unwrap_or_default();
    closure.extend(add.iter().copied());
    let mut add_sorted: Vec<Oid> = add.to_vec();
    add_sorted.sort();
    let body = V::map(vec![
        ("base", base.map(|b| V::Bytes(b.to_vec())).unwrap_or(V::Null)),
        ("add", V::Arr(add_sorted.iter().map(|c| V::Bytes(c.to_vec())).collect())),
        ("summary", V::Bytes(closure_summary(&closure).to_vec())),
    ]);
    let (oid, raw) = make_obj(sk, Some(repo), "state", body, None, ts);
    store.put(raw).expect("state stores");
    oid
}

pub fn closure_ok(store: &Store, changes: &BTreeSet<Oid>) -> bool {
    let patches: BTreeSet<Oid> = changes.iter()
        .map(|c| as_oid(store.body(c).get("patch").expect("patch ref")))
        .collect();
    changes.iter().all(|c| {
        let p = as_oid(store.body(c).get("patch").expect("patch ref"));
        patch_deps(store.body(&p), &p).is_subset(&patches)
    })
}

// ------------------------------------------------------- capabilities ------

fn glob1(pat: &str, path: &str) -> bool {
    if pat == "**" {
        return true;
    }
    if let Some(prefix) = pat.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    pat == path
}

fn covered(path: &str, patterns: &[V]) -> bool {
    let mut ok = false;
    for pat in patterns {
        let pat = pat.text().expect("pattern text");
        let neg = pat.starts_with('!');
        if glob1(pat.trim_start_matches('!'), path) {
            ok = !neg;
        }
    }
    ok
}

/// Walk a capability chain to an authority root (RFC §5.3): audience links,
/// attenuated actions/paths, unexpired, root key in the authority set.
pub fn cap_chain_valid(store: &Store, cap: &Oid, actor: &[u8], action: &str,
                       paths: &BTreeSet<String>, authority: &[Vec<u8>],
                       now_ms: i64) -> Result<(), String> {
    let mut link = store.get(cap);
    if link.get("body").unwrap().get("audience").unwrap().bytes() != Some(actor) {
        return Err("audience mismatch".into());
    }
    loop {
        let body = link.get("body").unwrap();
        if now_ms > body.get("exp").and_then(V::int).unwrap_or(0) {
            return Err("expired".into());
        }
        let scope = body.get("scope").ok_or("no scope")?;
        let actions = scope.get("actions").and_then(V::arr).ok_or("no actions")?;
        if !actions.iter().any(|a| a.text() == Some(action)) {
            return Err(format!("action {action} not granted"));
        }
        let pats = scope.get("paths").and_then(V::arr).ok_or("no paths")?;
        for p in paths {
            if !covered(p, pats) {
                return Err(format!("path {p} out of scope"));
            }
        }
        match body.get("parent") {
            Some(V::Null) | None => {
                let author = link.get("author").unwrap().bytes().unwrap();
                return if authority.iter().any(|k| k == author) {
                    Ok(())
                } else {
                    Err("root not an authority key".into())
                };
            }
            Some(parent) => {
                let parent = store.get(&as_oid(parent));
                let expect = link.get("author").unwrap().bytes().unwrap();
                if parent.get("body").unwrap().get("audience").unwrap().bytes()
                    != Some(expect) {
                    return Err("chain link broken".into());
                }
                link = parent;
            }
        }
    }
}

// ----------------------------------------------------------- landings ------

pub struct LandingCheck {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// RFC §7.3 checklist (structure, closure, footprints, auth chains, reads,
/// manifest re-materialization). Evidence *execution* is the gate's caller.
/// `stale_reads`: "reject" | "warn". Own-footprint paths are excluded from
/// staleness (finding W6).
pub fn check_landing(store: &Store, body: &V, authority: &[Vec<u8>], now_ms: i64,
                     stale_reads: &str) -> LandingCheck {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let base: BTreeSet<Oid> = match body.get("base_state") {
        Some(V::Null) | None => BTreeSet::new(),
        Some(b) => state_set(store, &as_oid(b)),
    };
    let target = state_set(store, &as_oid(body.get("target_state").expect("target")));
    let delta: BTreeSet<Oid> = body.get("delta").and_then(V::arr).unwrap_or(&[])
        .iter().map(as_oid).collect();
    let union: BTreeSet<Oid> = base.union(&delta).copied().collect();
    if !base.is_subset(&target) || target != union {
        errors.push("target != base ∪ delta (supersets only)".into());
    }
    if !closure_ok(store, &target) {
        errors.push("dependency closure violated".into());
    }
    let base_mat = if base.is_empty() {
        None
    } else {
        materialize(store, &base.iter().copied().collect::<Vec<_>>()).ok()
    };
    let target_vec: Vec<Oid> = target.iter().copied().collect();
    let mat = match materialize(store, &target_vec) {
        Ok(m) => m,
        Err(e) => {
            errors.push(format!("materialization failed: {e}"));
            return LandingCheck { errors, warnings };
        }
    };
    // §5.3: footprint resolution = base paths ∪ resulting paths
    let mut fidp: BTreeMap<Fid, String> = mat.file_map.iter()
        .filter_map(|(f, p)| p.clone().map(|p| (*f, p))).collect();
    if let Some(bm) = &base_mat {
        for (f, p) in &bm.file_map {
            if let Some(p) = p {
                fidp.insert(*f, p.clone());
            }
        }
    }
    for c in &delta {
        let ch = store.get(c);
        let cb = ch.get("body").unwrap();
        let p = as_oid(cb.get("patch").expect("patch"));
        let touched = patch_paths(store.body(&p), &p, &fidp);
        let declared: BTreeSet<String> = cb.get("footprint").and_then(V::arr)
            .unwrap_or(&[]).iter().filter_map(|x| x.text().map(String::from)).collect();
        if touched != declared {
            errors.push(format!("footprint mismatch on {}", hex8(c)));
        }
        match ch.get("auth") {
            Some(V::Null) | None => errors.push(format!("no auth on {}", hex8(c))),
            Some(a) => {
                if let Err(why) = cap_chain_valid(
                    store, &as_oid(a), ch.get("author").unwrap().bytes().unwrap(),
                    "publish_change", &touched, authority, now_ms) {
                    errors.push(format!("auth invalid on {}: {why}", hex8(c)));
                }
            }
        }
        for rd in cb.get("reads").and_then(V::arr).unwrap_or(&[]) {
            let rd = rd.arr().expect("read entry");
            let path = rd[0].text().expect("read path");
            if declared.contains(path) {
                continue; // own footprint excluded (finding W6)
            }
            if let Some(bm) = &base_mat {
                if let Some(content) = bm.tree.get(path) {
                    if h(content) != as_oid(&rd[1]) {
                        let msg = format!("stale read of {path} in {}", hex8(c));
                        if stale_reads == "reject" {
                            errors.push(msg);
                        } else {
                            warnings.push(msg);
                        }
                    }
                }
            }
        }
    }
    let man = store.body(&as_oid(body.get("manifest").expect("manifest")));
    for k in ["tree_root", "file_map_root", "conflict_root", "clean"] {
        if man.get(k) != mat.manifest.get(k) {
            errors.push(format!("manifest field {k} does not match re-materialization"));
        }
    }
    if !mat.clean() {
        errors.push("target state is conflicted".into());
    }
    LandingCheck { errors, warnings }
}

fn hex8(oid: &Oid) -> String {
    oid[..4].iter().map(|b| format!("{b:02x}")).collect()
}
