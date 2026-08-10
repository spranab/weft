//! The content model: patches, identities, and deterministic materialization
//! (RFC §5.8, §6). Identities are (patch-oid, ordinal); intra-patch
//! references use the SELF sentinel `[null, ordinal]` (finding W5).
//! Materialization is a pure function of the change SET; every
//! order-sensitive step sorts explicitly.

use crate::cbor::{encode, V};
use crate::object::{as_oid, h, Oid, Store};
use std::collections::{BTreeMap, BTreeSet};

pub type LineId = (Oid, i64);
pub type Fid = (Oid, i64);
/// Per-anchor child inserts: (patch-oid, ordinal, line bytes).
type Children = BTreeMap<Anchor, Vec<(Oid, i64, Vec<u8>)>>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Anchor {
    Start,
    Line(LineId),
}

/// Decode an id reference from a patch body, resolving SELF (`[null, n]`).
fn rid(v: &V, self_oid: &Oid) -> (Oid, i64) {
    let a = v.arr().expect("id is a 2-array");
    let oid = match &a[0] {
        V::Null => *self_oid,
        other => as_oid(other),
    };
    (oid, a[1].int().expect("ordinal"))
}

/// Intrinsic dependencies of a patch body (RFC §5.8 table). SELF references
/// contribute no external dependency.
pub fn patch_deps(body: &V, self_oid: &Oid) -> BTreeSet<Oid> {
    let mut deps = BTreeSet::new();
    let mut add = |v: &V| {
        if !matches!(v.arr().expect("id")[0], V::Null) {
            deps.insert(rid(v, self_oid).0);
        }
    };
    for op in body.get("ops").and_then(V::arr).unwrap_or(&[]) {
        let op = op.arr().expect("op array");
        match op[0].text().expect("op kind") {
            "insert" => {
                add(&op[1]);
                if op[2].arr().map(|a| a.len()) == Some(2) {
                    add(&op[2]);
                }
            }
            "delete" => {
                add(&op[1]);
                for lid in op[2].arr().expect("delete ids") {
                    add(lid);
                }
            }
            "rmfile" | "move" => add(&op[1]),
            _ => {}
        }
    }
    deps
}

struct FileMeta {
    claims: Vec<(Oid, String)>,
    rm: BTreeSet<Oid>,
}

pub struct Mat {
    pub tree: BTreeMap<String, Vec<u8>>,
    pub file_map: BTreeMap<Fid, Option<String>>,
    pub conflicts: Vec<V>,
    pub markers: Vec<V>,
    pub line_index: BTreeMap<String, Vec<LineId>>,
    pub manifest: V,
}

impl Mat {
    pub fn clean(&self) -> bool {
        self.conflicts.is_empty()
    }
}

fn fid_v(f: &Fid) -> V {
    V::Arr(vec![V::Bytes(f.0.to_vec()), V::Int(f.1)])
}

pub fn materialize(store: &Store, changes: &[Oid]) -> Result<Mat, String> {
    // gather patches; a patch claimed by two changes is invalid (RFC §5.8)
    let mut patches: BTreeMap<Oid, &V> = BTreeMap::new();
    for c in changes {
        let p = as_oid(store.body(c).get("patch").ok_or("change without patch")?);
        if patches.insert(p, store.body(&p)).is_some() {
            return Err("patch claimed by two changes".into());
        }
    }

    let mut files: BTreeMap<Fid, FileMeta> = BTreeMap::new();
    let mut children: BTreeMap<Fid, Children> = BTreeMap::new();
    let mut tombs: BTreeMap<Fid, BTreeMap<LineId, BTreeSet<Oid>>> = BTreeMap::new();

    for (poid, body) in &patches {
        let mut n: i64 = 0;
        for op in body.get("ops").and_then(V::arr).unwrap_or(&[]) {
            let op = op.arr().expect("op");
            match op[0].text().expect("kind") {
                "mkfile" => {
                    let fid = (*poid, n);
                    n += 1;
                    let m = files.entry(fid).or_insert(FileMeta { claims: vec![], rm: BTreeSet::new() });
                    m.claims.push((*poid, op[1].text().expect("path").to_string()));
                    children.entry(fid).or_default();
                    tombs.entry(fid).or_default();
                }
                "insert" => {
                    let fid = rid(&op[1], poid);
                    let mut anchor = if op[2].arr().map(|a| a.len()) == Some(1) {
                        Anchor::Start
                    } else {
                        Anchor::Line(rid(&op[2], poid))
                    };
                    let ch = children.entry(fid).or_default();
                    for line in op[3].arr().expect("lines") {
                        let lid = (*poid, n);
                        n += 1;
                        ch.entry(anchor).or_default()
                            .push((*poid, lid.1, line.bytes().expect("line bytes").to_vec()));
                        anchor = Anchor::Line(lid); // chain
                    }
                }
                "delete" => {
                    let fid = rid(&op[1], poid);
                    let td = tombs.entry(fid).or_default();
                    for l in op[2].arr().expect("ids") {
                        td.entry(rid(l, poid)).or_default().insert(*poid);
                    }
                }
                "rmfile" => {
                    let fid = rid(&op[1], poid);
                    files.entry(fid).or_insert(FileMeta { claims: vec![], rm: BTreeSet::new() })
                        .rm.insert(*poid);
                }
                "move" => {
                    let fid = rid(&op[1], poid);
                    files.entry(fid).or_insert(FileMeta { claims: vec![], rm: BTreeSet::new() })
                        .claims.push((*poid, op[2].text().expect("path").to_string()));
                }
                other => return Err(format!("unknown op {other}")),
            }
        }
    }

    let mut conflicts: Vec<V> = Vec::new();
    let mut markers: Vec<V> = Vec::new();

    // path resolution (RFC §6.3 tree class + edit-rm, finding W2)
    let mut file_map: BTreeMap<Fid, Option<String>> = BTreeMap::new();
    for (fid, meta) in &files {
        if !meta.rm.is_empty() {
            file_map.insert(*fid, None);
            let editors: BTreeSet<Oid> = children.get(fid).map(|ch| {
                ch.values().flatten().map(|(p, _, _)| *p)
                    .filter(|p| p != &fid.0 && !meta.rm.contains(p)).collect()
            }).unwrap_or_default();
            if !editors.is_empty() {
                conflicts.push(V::Arr(vec![V::Text("edit-rm".into()), fid_v(fid)]));
            }
            continue;
        }
        let mut claims = meta.claims.clone();
        claims.sort();
        let distinct: BTreeSet<&String> = claims.iter().map(|(_, p)| p).collect();
        if distinct.len() > 1 {
            conflicts.push(V::Arr(vec![V::Text("move-move".into()), fid_v(fid)]));
        }
        file_map.insert(*fid, claims.last().map(|(_, p)| p.clone()));
    }

    let mut by_path: BTreeMap<String, Vec<Fid>> = BTreeMap::new();
    for (fid, path) in &file_map {
        if let Some(p) = path {
            by_path.entry(p.clone()).or_default().push(*fid);
        }
    }
    for (path, fids) in &by_path {
        if fids.len() > 1 {
            conflicts.push(V::Arr(vec![V::Text("tree".into()), V::Text(path.clone())]));
            for fid in &fids[1..] {
                let hex: String = fid.0[..4].iter().map(|b| format!("{b:02x}")).collect();
                file_map.insert(*fid, Some(format!("{path}~{hex}")));
            }
        }
    }

    // RGA traversal (RFC §6.2, sibling order per finding W1)
    let mut tree = BTreeMap::new();
    let mut line_index = BTreeMap::new();
    for (fid, path) in &file_map {
        let Some(path) = path else { continue };
        let ch = children.get(fid).cloned().unwrap_or_default();
        let dead = tombs.get(fid).cloned().unwrap_or_default();
        for (anchor, cs) in &ch {
            let authors: BTreeSet<Oid> = cs.iter().map(|(p, _, _)| *p).collect();
            if authors.len() > 1 {
                markers.push(V::Arr(vec![V::Text("order".into()), V::Text(path.clone())]));
            }
            if let Anchor::Line(l) = anchor {
                if let Some(deleters) = dead.get(l) {
                    if cs.iter().any(|(p, _, _)| !deleters.contains(p)) {
                        conflicts.push(V::Arr(vec![V::Text("edit-delete".into()),
                                                   V::Text(path.clone())]));
                    }
                }
            }
        }
        // stack pop order = (patch-oid DESC, ordinal ASC) → push the inverse
        let push_key = |t: &(Oid, i64, Vec<u8>)| (t.0, -t.1);
        let mut stack: Vec<(Oid, i64, Vec<u8>)> =
            ch.get(&Anchor::Start).cloned().unwrap_or_default();
        stack.sort_by_key(|t| push_key(t));
        let (mut out, mut idx) = (Vec::new(), Vec::new());
        while let Some((poid, ordn, text)) = stack.pop() {
            let lid = (poid, ordn);
            if !dead.contains_key(&lid) {
                out.push(text);
                idx.push(lid);
            }
            let mut kids = ch.get(&Anchor::Line(lid)).cloned().unwrap_or_default();
            kids.sort_by_key(|t| push_key(t));
            stack.extend(kids);
        }
        let mut content: Vec<u8> = out.join(&b"\n"[..]);
        if !out.is_empty() {
            content.push(b'\n');
        }
        tree.insert(path.clone(), content);
        line_index.insert(path.clone(), idx);
    }

    // manifest roots — records sorted by canonical encoding (normative)
    let sort_enc = |mut v: Vec<V>| {
        v.sort_by_key(encode);
        V::Arr(v)
    };
    conflicts.sort_by_key(encode);
    conflicts.dedup();
    markers.sort_by_key(encode);
    let tree_root = h(&encode(&sort_enc(tree.iter().map(|(p, c)| {
        V::Arr(vec![V::Text(p.clone()), V::Bytes(h(c).to_vec())])
    }).collect())));
    let file_map_root = h(&encode(&sort_enc(file_map.iter().map(|(f, p)| {
        V::Arr(vec![fid_v(f), p.clone().map(V::Text).unwrap_or(V::Null)])
    }).collect())));
    let conflict_root = h(&encode(&V::Arr(conflicts.clone())));
    let clean = conflicts.is_empty();
    let manifest = V::map(vec![
        ("algorithm", V::Text("weft-rga-v1".into())),
        ("tree_root", V::Bytes(tree_root.to_vec())),
        ("file_map_root", V::Bytes(file_map_root.to_vec())),
        ("conflict_root", V::Bytes(conflict_root.to_vec())),
        ("clean", V::Bool(clean)),
    ]);
    Ok(Mat { tree, file_map, conflicts, markers, line_index, manifest })
}

/// Touched paths of a patch, resolved against a fid→path map (RFC §7.3).
pub fn patch_paths(body: &V, self_oid: &Oid, fidp: &BTreeMap<Fid, String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for op in body.get("ops").and_then(V::arr).unwrap_or(&[]) {
        let op = op.arr().expect("op");
        match op[0].text().expect("kind") {
            "mkfile" => {
                out.insert(op[1].text().expect("path").to_string());
            }
            "move" => {
                out.insert(op[2].text().expect("path").to_string());
                if let Some(p) = fidp.get(&rid(&op[1], self_oid)) {
                    out.insert(p.clone());
                }
            }
            _ => {
                if let Some(p) = fidp.get(&rid(&op[1], self_oid)) {
                    out.insert(p.clone());
                }
            }
        }
    }
    out
}
