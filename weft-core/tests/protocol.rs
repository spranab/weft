//! Regression tests for review findings (T*/W*) and the determinism fuzzer —
//! the load-bearing invariant: ∀ permutations of a change set: identical
//! manifest.

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::collections::BTreeSet;
use weft_core::cbor::{decode, encode, V};
use weft_core::*;

const TS: i64 = 1_000;
const REPO: Oid = [1u8; 32];

fn id_v(oid: Option<&Oid>, ord: i64) -> V {
    V::Arr(vec![oid.map(|o| V::Bytes(o.to_vec())).unwrap_or(V::Null), V::Int(ord)])
}
fn start() -> V {
    V::Arr(vec![V::Text("S".into())])
}
fn lines(xs: &[&str]) -> V {
    V::Arr(xs.iter().map(|x| V::Bytes(x.as_bytes().to_vec())).collect())
}

struct Ctx {
    store: Store,
    sk: ed25519_dalek::SigningKey,
}

impl Ctx {
    fn new() -> Self {
        let (sk, _) = keygen();
        Ctx { store: Store::default(), sk }
    }
    fn publish(&mut self, typ: &str, body: V, auth: Option<Oid>) -> Oid {
        let (_, raw) = make_obj(&self.sk, Some(REPO), typ, body, auth, TS);
        self.store.put(raw).expect("valid object")
    }
    fn change(&mut self, ops: Vec<V>, nonce: &[u8]) -> (Oid, Oid) {
        let p = self.publish("patch", V::map(vec![
            ("nonce", V::Bytes(nonce.to_vec())), ("ops", V::Arr(ops))]), None);
        let c = self.publish("change", V::map(vec![
            ("patch", V::Bytes(p.to_vec())),
            ("footprint", V::Arr(vec![])),
            ("reads", V::Arr(vec![])),
            ("message", V::Text("test".into()))]), None);
        (p, c)
    }
    /// Single-patch scaffold-and-fill via the SELF sentinel (finding W5).
    fn base(&mut self, nfiles: usize, nlines: usize) -> (Vec<Oid>, Oid, Vec<(Oid, i64)>) {
        let mut ops: Vec<V> = (0..nfiles).map(|f| {
            V::Arr(vec![V::Text("mkfile".into()), V::Text(format!("f{f}.txt"))])
        }).collect();
        let mut ord = nfiles as i64;
        let mut line_ords = Vec::new();
        for f in 0..nfiles {
            let texts: Vec<String> =
                (0..nlines).map(|j| format!("file{f} line{j}")).collect();
            ops.push(V::Arr(vec![V::Text("insert".into()),
                                 id_v(None, f as i64), start(),
                                 lines(&texts.iter().map(|s| s.as_str())
                                       .collect::<Vec<_>>())]));
            for _ in 0..nlines {
                line_ords.push(ord);
                ord += 1;
            }
        }
        let (p, c) = self.change(ops, b"basefill");
        let lids: Vec<(Oid, i64)> = line_ords.into_iter().map(|o| (p, o)).collect();
        (vec![c], p, lids)
    }
}

fn fingerprint(m: &Mat) -> Vec<u8> {
    encode(&m.manifest)
}

// ------------------------------------------------------------ regressions --

#[test]
fn cbor_roundtrip_and_canonical_rejection() {
    let v = V::map(vec![
        ("b", V::Int(-1000)),
        ("a", V::Arr(vec![V::Bool(true), V::Null, V::Bytes(vec![0; 300])])),
    ]);
    // encode canonicalizes map order; decode returns the canonical form,
    // and re-encoding it is byte-identical (canonical idempotence)
    let bytes = encode(&v);
    let round = decode(&bytes).unwrap();
    assert_eq!(encode(&round), bytes);
    assert_eq!(round.get("b"), v.get("b"));
    assert_eq!(round.get("a"), v.get("a"));
    // map with keys out of canonical order must be rejected
    assert!(decode(&[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02]).is_err());
    // non-minimal int must be rejected
    assert!(decode(&[0x18, 0x05]).is_err());
}

#[test]
fn w5_self_sentinel_single_patch_creates_and_fills() {
    let mut cx = Ctx::new();
    let (base, _, _) = cx.base(1, 3);
    let m = materialize(&cx.store, &base).unwrap();
    assert_eq!(m.tree["f0.txt"], b"file0 line0\nfile0 line1\nfile0 line2\n");
    assert!(m.clean());
}

#[test]
fn t1_same_anchor_append_is_marker_not_conflict() {
    let mut cx = Ctx::new();
    let (base, p, lids) = cx.base(1, 3);
    let last = lids.last().unwrap();
    let (_, ca) = cx.change(vec![V::Arr(vec![V::Text("insert".into()),
        id_v(Some(&p), 0), id_v(Some(&last.0), last.1), lines(&["from-A"])])], b"aaaa");
    let (_, cb) = cx.change(vec![V::Arr(vec![V::Text("insert".into()),
        id_v(Some(&p), 0), id_v(Some(&last.0), last.1), lines(&["from-B"])])], b"bbbb");
    let mut all = base.clone();
    all.extend([ca, cb]);
    let m = materialize(&cx.store, &all).unwrap();
    assert!(m.clean(), "order overlap must stay clean");
    assert_eq!(m.markers.len(), 1);
    let text = String::from_utf8(m.tree["f0.txt"].clone()).unwrap();
    assert!(text.contains("from-A") && text.contains("from-B"));
}

#[test]
fn t2_edit_delete_is_conflict() {
    let mut cx = Ctx::new();
    let (base, p, lids) = cx.base(1, 3);
    let victim = lids[1];
    let (_, cdel) = cx.change(vec![V::Arr(vec![V::Text("delete".into()),
        id_v(Some(&p), 0), V::Arr(vec![id_v(Some(&victim.0), victim.1)])])], b"dddd");
    let (_, cins) = cx.change(vec![V::Arr(vec![V::Text("insert".into()),
        id_v(Some(&p), 0), id_v(Some(&victim.0), victim.1),
        lines(&["anchored-on-deleted"])])], b"iiii");
    let mut all = base.clone();
    all.extend([cdel, cins]);
    let m = materialize(&cx.store, &all).unwrap();
    assert!(!m.clean());
    assert!(m.conflicts.iter().any(|c| c.arr().unwrap()[0].text() == Some("edit-delete")));
}

#[test]
fn w2_rmfile_vs_edit_is_conflict() {
    let mut cx = Ctx::new();
    let (base, p, lids) = cx.base(1, 2);
    let (_, crm) = cx.change(vec![V::Arr(vec![V::Text("rmfile".into()),
        id_v(Some(&p), 0)])], b"rrrr");
    let (_, ced) = cx.change(vec![V::Arr(vec![V::Text("insert".into()),
        id_v(Some(&p), 0), id_v(Some(&lids[0].0), lids[0].1),
        lines(&["typed into removed file"])])], b"eeee");
    let mut all = base.clone();
    all.extend([crm, ced]);
    let m = materialize(&cx.store, &all).unwrap();
    assert!(m.conflicts.iter().any(|c| c.arr().unwrap()[0].text() == Some("edit-rm")));
}

#[test]
fn t4_move_move_is_conflict_with_deterministic_winner() {
    let mut cx = Ctx::new();
    let (base, p, _) = cx.base(1, 2);
    let (_, c1) = cx.change(vec![V::Arr(vec![V::Text("move".into()),
        id_v(Some(&p), 0), V::Text("left.txt".into())])], b"1111");
    let (_, c2) = cx.change(vec![V::Arr(vec![V::Text("move".into()),
        id_v(Some(&p), 0), V::Text("right.txt".into())])], b"2222");
    let mut all = base.clone();
    all.extend([c1, c2]);
    let m = materialize(&cx.store, &all).unwrap();
    assert!(m.conflicts.iter().any(|c| c.arr().unwrap()[0].text() == Some("move-move")));
    assert_eq!(m.tree.len(), 1);
}

#[test]
fn w4_summary_is_split_invariant() {
    let mut cx = Ctx::new();
    let (base, p, _) = cx.base(1, 2);
    let (_, c3) = cx.change(vec![V::Arr(vec![V::Text("insert".into()),
        id_v(Some(&p), 0), start(), lines(&["top"])])], b"3333");
    let mut all = base.clone();
    all.push(c3);
    let sk = keygen().0;
    // split A: everything in one root state
    let sa = make_state(&sk, REPO, None, &all, &mut cx.store, TS);
    // split B: base first, then c3 on top
    let sb1 = make_state(&sk, REPO, None, &base, &mut cx.store, TS);
    let sb2 = make_state(&sk, REPO, Some(sb1), &[c3], &mut cx.store, TS);
    assert_eq!(state_set(&cx.store, &sa), state_set(&cx.store, &sb2));
    let sum = |s: &Oid| cx.store.body(s).get("summary").unwrap().bytes().unwrap().to_vec();
    assert_eq!(sum(&sa), sum(&sb2),
               "equal closures must have equal summaries (finding W4)");
}

#[test]
fn landing_checklist_end_to_end() {
    let mut cx = Ctx::new();
    let authority = vec![cx.sk.verifying_key().to_bytes().to_vec()];
    let actor = cx.sk.verifying_key().to_bytes();
    let cap = cx.publish("capability", V::map(vec![
        ("audience", V::Bytes(actor.to_vec())),
        ("parent", V::Null),
        ("scope", V::map(vec![
            ("actions", V::Arr(vec![V::Text("publish_change".into())])),
            ("paths", V::Arr(vec![V::Text("**".into())]))])),
        ("exp", V::Int(TS + 1_000_000)),
    ]), None);

    // base landing state: single self-filling change, correct footprint + auth
    let (bp, _) = cx.change(vec![], b"unused_"); // placeholder to vary oids
    let _ = bp;
    let p = cx.publish("patch", V::map(vec![
        ("nonce", V::Bytes(b"landing_".to_vec())),
        ("ops", V::Arr(vec![
            V::Arr(vec![V::Text("mkfile".into()), V::Text("a.txt".into())]),
            V::Arr(vec![V::Text("insert".into()), id_v(None, 0), start(),
                        lines(&["hello weft"])])]))]), None);
    let c = cx.publish("change", V::map(vec![
        ("patch", V::Bytes(p.to_vec())),
        ("footprint", V::Arr(vec![V::Text("a.txt".into())])),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("seed".into()))]), Some(cap));

    let sk = cx.sk.clone();
    let st = make_state(&sk, REPO, None, &[c], &mut cx.store, TS);
    let target: Vec<Oid> = state_set(&cx.store, &st).into_iter().collect();
    let mat = materialize(&cx.store, &target).unwrap();
    let man = cx.publish("manifest", mat.manifest.clone(), None);
    let body = V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("seq", V::Int(0)),
        ("prev", V::Null),
        ("base_state", V::Null),
        ("delta", V::Arr(vec![V::Bytes(c.to_vec())])),
        ("target_state", V::Bytes(st.to_vec())),
        ("manifest", V::Bytes(man.to_vec())),
    ]);
    let chk = check_landing(&cx.store, &body, &authority, TS + 1, "reject");
    assert!(chk.errors.is_empty(), "clean landing must pass: {:?}", chk.errors);

    // tamper: declare a wrong footprint → certification error
    let p_bad = cx.publish("patch", V::map(vec![
        ("nonce", V::Bytes(b"badfoot_".to_vec())),
        ("ops", V::Arr(vec![
            V::Arr(vec![V::Text("mkfile".into()), V::Text("b.txt".into())])]))]),
        None);
    let c_bad = cx.publish("change", V::map(vec![
        ("patch", V::Bytes(p_bad.to_vec())),
        ("footprint", V::Arr(vec![V::Text("elsewhere.txt".into())])),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("liar".into()))]), Some(cap));
    let st2 = make_state(&sk, REPO, Some(st), &[c_bad], &mut cx.store, TS);
    let t2: Vec<Oid> = state_set(&cx.store, &st2).into_iter().collect();
    let mat2 = materialize(&cx.store, &t2).unwrap();
    let man2 = cx.publish("manifest", mat2.manifest.clone(), None);
    let body2 = V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("seq", V::Int(1)),
        ("prev", V::Null),
        ("base_state", V::Bytes(st.to_vec())),
        ("delta", V::Arr(vec![V::Bytes(c_bad.to_vec())])),
        ("target_state", V::Bytes(st2.to_vec())),
        ("manifest", V::Bytes(man2.to_vec())),
    ]);
    let chk2 = check_landing(&cx.store, &body2, &authority, TS + 1, "reject");
    assert!(chk2.errors.iter().any(|e| e.contains("footprint mismatch")));
}

#[test]
fn stale_read_detected_at_certification() {
    let mut cx = Ctx::new();
    let authority = vec![cx.sk.verifying_key().to_bytes().to_vec()];
    let actor = cx.sk.verifying_key().to_bytes();
    let cap = cx.publish("capability", V::map(vec![
        ("audience", V::Bytes(actor.to_vec())),
        ("parent", V::Null),
        ("scope", V::map(vec![
            ("actions", V::Arr(vec![V::Text("publish_change".into())])),
            ("paths", V::Arr(vec![V::Text("**".into())]))])),
        ("exp", V::Int(TS + 1_000_000)),
    ]), None);
    let sk = cx.sk.clone();

    // base: a.txt with one line; capture its digest (what an agent "read")
    let (base, p, lids) = cx.base(1, 1);
    let base_mat = materialize(&cx.store, &base).unwrap();
    let old_digest = h(&base_mat.tree["f0.txt"]);

    // concurrent refactor changes f0.txt underneath the reader
    let (_, c_ref) = cx.change(vec![
        V::Arr(vec![V::Text("delete".into()), id_v(Some(&p), 0),
                    V::Arr(vec![id_v(Some(&lids[0].0), lids[0].1)])]),
        V::Arr(vec![V::Text("insert".into()), id_v(Some(&p), 0), start(),
                    lines(&["refactored"])])], b"refac___");
    let mut head: Vec<Oid> = base.clone();
    head.push(c_ref);
    let st_head = make_state(&sk, REPO, None, &head, &mut cx.store, TS);

    // the stale worker: footprint on a NEW file, reads = old f0.txt digest
    let p_new = cx.publish("patch", V::map(vec![
        ("nonce", V::Bytes(b"staleeee".to_vec())),
        ("ops", V::Arr(vec![
            V::Arr(vec![V::Text("mkfile".into()), V::Text("new.txt".into())]),
            V::Arr(vec![V::Text("insert".into()), id_v(None, 0), start(),
                        lines(&["built on stale assumptions"])])]))]), None);
    let c_stale = cx.publish("change", V::map(vec![
        ("patch", V::Bytes(p_new.to_vec())),
        ("footprint", V::Arr(vec![V::Text("new.txt".into())])),
        ("reads", V::Arr(vec![V::Arr(vec![
            V::Text("f0.txt".into()), V::Bytes(old_digest.to_vec())])])),
        ("message", V::Text("stale".into()))]), Some(cap));

    let st2 = make_state(&sk, REPO, Some(st_head), &[c_stale], &mut cx.store, TS);
    let t2: Vec<Oid> = state_set(&cx.store, &st2).into_iter().collect();
    let mat2 = materialize(&cx.store, &t2).unwrap();
    let man2 = cx.publish("manifest", mat2.manifest.clone(), None);
    let body = V::map(vec![
        ("base_state", V::Bytes(st_head.to_vec())),
        ("delta", V::Arr(vec![V::Bytes(c_stale.to_vec())])),
        ("target_state", V::Bytes(st2.to_vec())),
        ("manifest", V::Bytes(man2.to_vec())),
    ]);
    let chk = check_landing(&cx.store, &body, &authority, TS + 1, "reject");
    assert!(chk.errors.iter().any(|e| e.contains("stale read")),
            "stale read must be rejected, got: {:?}", chk.errors);
}

// ---------------------------------------------------------- the fuzzer -----

#[test]
fn determinism_fuzz() {
    let mut rng = StdRng::seed_from_u64(42);
    for scenario in 0..200 {
        let mut cx = Ctx::new();
        let nfiles = rng.gen_range(1..=2);
        let nlines = rng.gen_range(3..=10);
        let (base, p, lids) = cx.base(nfiles, nlines);
        let mut all = base.clone();
        for w in 0..rng.gen_range(2..=5) {
            let mut ops = Vec::new();
            for _ in 0..rng.gen_range(1..=4) {
                let roll: f64 = rng.gen();
                let fid_ord = rng.gen_range(0..nfiles) as i64;
                if roll < 0.55 {
                    let anchor = if rng.gen_bool(0.4) {
                        start()
                    } else {
                        let l = lids[rng.gen_range(0..lids.len())];
                        id_v(Some(&l.0), l.1)
                    };
                    let n = rng.gen_range(1..=3);
                    let texts: Vec<String> = (0..n)
                        .map(|_| format!("w{w}x{}", rng.gen_range(0..999))).collect();
                    ops.push(V::Arr(vec![V::Text("insert".into()),
                        id_v(Some(&p), fid_ord), anchor,
                        lines(&texts.iter().map(|s| s.as_str()).collect::<Vec<_>>())]));
                } else if roll < 0.75 {
                    let l = lids[rng.gen_range(0..lids.len())];
                    ops.push(V::Arr(vec![V::Text("delete".into()),
                        id_v(Some(&p), fid_ord),
                        V::Arr(vec![id_v(Some(&l.0), l.1)])]));
                } else if roll < 0.85 {
                    ops.push(V::Arr(vec![V::Text("move".into()),
                        id_v(Some(&p), fid_ord),
                        V::Text(format!("moved/w{w}_{}.txt", rng.gen_range(0..99)))]));
                } else if roll < 0.92 {
                    ops.push(V::Arr(vec![V::Text("mkfile".into()),
                        V::Text(format!("new/w{w}_{}.txt", rng.gen_range(0..999)))]));
                } else {
                    ops.push(V::Arr(vec![V::Text("rmfile".into()),
                        id_v(Some(&p), fid_ord)]));
                }
            }
            let nonce: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
            let (_, c) = cx.change(ops, &nonce);
            all.push(c);
        }
        let set: BTreeSet<Oid> = all.iter().copied().collect();
        assert!(closure_ok(&cx.store, &set), "scenario {scenario} closure");
        let mut order = all.clone();
        let mut reference: Option<Vec<u8>> = None;
        for _ in 0..6 {
            order.shuffle(&mut rng);
            let fp = fingerprint(&materialize(&cx.store, &order).unwrap());
            match &reference {
                None => reference = Some(fp),
                Some(r) => assert_eq!(&fp, r,
                    "DETERMINISM VIOLATION in scenario {scenario}"),
            }
        }
    }
}
