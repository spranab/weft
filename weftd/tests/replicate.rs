//! Multi-node replication (RFC §8): a follower converges on a gate hub's
//! certified history by VERIFYING it, not trusting it. Covers bootstrap from
//! genesis over the wire, convergence of head/seq/workspace, a forged landing
//! (valid signature, wrong key) being refused, a landing with no certificate
//! being refused, and fork detection when two certified landings claim the
//! same slot.

use weft_core::cbor::V;
use weft_core::*;

const PORT: u16 = 18760;

fn ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn land(hub: &weftd::Shared, sk: &ed25519_dalek::SigningKey, repo: Oid, cap: Oid,
        path: &str, line: &str, nonce: &[u8]) -> Oid {
    let put = |raw: Vec<u8>| hub.lock().unwrap().store.put(raw).expect("put");
    let (_, p_raw) = make_obj(sk, Some(repo), "patch", V::map(vec![
        ("nonce", V::Bytes(nonce.to_vec())),
        ("ops", V::Arr(vec![
            V::Arr(vec![V::Text("mkfile".into()), V::Text(path.into())]),
            V::Arr(vec![V::Text("insert".into()),
                V::Arr(vec![V::Null, V::Int(0)]),
                V::Arr(vec![V::Text("S".into())]),
                V::Arr(vec![V::Bytes(line.as_bytes().to_vec())])])]))]), None, ts());
    let patch = put(p_raw);
    let (_, c_raw) = make_obj(sk, Some(repo), "change", V::map(vec![
        ("patch", V::Bytes(patch.to_vec())),
        ("footprint", V::Arr(vec![V::Text(path.into())])),
        ("reads", V::Arr(vec![])),
        ("message", V::Text(format!("add {path}"))),
        ("provenance", V::map(vec![("model", V::Text("claude-fable-5".into()))]))]),
        Some(cap), ts());
    let change = put(c_raw);
    let (_, pr_raw) = make_obj(sk, Some(repo), "proposal", V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
        ("status", V::Text("open".into()))]), Some(cap), ts());
    let prop = put(pr_raw);
    hub.lock().unwrap().queue.push(prop);
    weftd::gate_tick(hub);
    change
}

fn bootstrap(hub: &weftd::Shared, auth_sk: &ed25519_dalek::SigningKey,
             auth_pub: [u8; 32]) -> (Oid, Oid) {
    let gate_pub = hub.lock().unwrap().gate_pub;
    let (_, gen_raw) = make_obj(auth_sk, None, "genesis", V::map(vec![
        ("name", V::Text("replicate-e2e".into())),
        ("authority", V::Arr(vec![V::Bytes(auth_pub.to_vec())])),
        ("quorum", V::Int(1)),
        ("refs", V::map(vec![("trunk", V::map(vec![
            ("gates", V::Arr(vec![V::Bytes(gate_pub.to_vec())])),
            ("threshold", V::Int(1))]))])),
        ("policy_init", V::map(vec![
            ("rules", V::Arr(vec![])), ("recipes", V::Arr(vec![])),
            ("approvals", V::Int(0)), ("stale_reads", V::Text("reject".into()))])),
        ("config_init", V::map(vec![]))]), None, 1_000);
    let repo = {
        let mut h = hub.lock().unwrap();
        let gen = h.store.put(gen_raw).unwrap();
        h.repo = Some(gen);
        h.authority = vec![auth_pub.to_vec()];
        h.policy = h.store.get(&gen).get("body").unwrap().get("policy_init").cloned();
        gen
    };
    let (_, cap_raw) = make_obj(auth_sk, Some(repo), "capability", V::map(vec![
        ("audience", V::Bytes(auth_pub.to_vec())),
        ("parent", V::Null),
        ("scope", V::map(vec![
            ("actions", V::Arr(vec![V::Text("publish_change".into())])),
            ("paths", V::Arr(vec![V::Text("**".into())]))])),
        ("exp", V::Int(i64::MAX / 2))]), None, 1_000);
    let cap = hub.lock().unwrap().store.put(cap_raw).unwrap();
    (repo, cap)
}

#[test]
fn follower_converges_and_refuses_forgeries() {
    // ── the gate hub, serving over HTTP ──────────────────────────────────
    let gate = weftd::new_hub();
    {
        let gate = gate.clone();
        std::thread::spawn(move || weftd::serve(PORT, gate));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    let (auth_sk, auth_pub) = keygen();
    let (repo, cap) = bootstrap(&gate, &auth_sk, auth_pub);
    land(&gate, &auth_sk, repo, cap, "a.txt", "woven on the gate", b"rep1____");
    land(&gate, &auth_sk, repo, cap, "b.txt", "second landing", b"rep2____");
    assert_eq!(gate.lock().unwrap().seq, 1);

    // ── a fresh follower bootstraps from genesis and converges ───────────
    let peer = format!("http://127.0.0.1:{PORT}");
    let follower = weftd::new_hub();
    let fetched = weftd::sync::pull(&follower, &peer).expect("pull");
    assert!(fetched > 5, "objects replicated: {fetched}");
    {
        let g = gate.lock().unwrap();
        let f = follower.lock().unwrap();
        assert_eq!(f.repo, g.repo, "genesis bootstrapped over the wire");
        assert_eq!(f.seq, g.seq, "seq converged");
        assert_eq!(f.head, g.head, "head converged");
        // the follower re-materialized the state itself — same bytes
        let st = f.head_state.unwrap();
        let t: Vec<Oid> = state_set(&f.store, &st).into_iter().collect();
        let mat = materialize(&f.store, &t).unwrap();
        assert_eq!(mat.tree["a.txt"], b"woven on the gate\n");
        assert_eq!(mat.tree["b.txt"], b"second landing\n");
        assert_eq!(f.log.len(), 2, "landing log rebuilt on the follower");
    }

    // ── incremental: a new landing on the gate replicates on next pull ───
    land(&gate, &auth_sk, repo, cap, "c.txt", "third landing", b"rep3____");
    weftd::sync::pull(&follower, &peer).expect("pull 2");
    assert_eq!(follower.lock().unwrap().seq, 2, "incremental sync");
    assert_eq!(follower.lock().unwrap().head, gate.lock().unwrap().head);

    // ── forgery 1: a landing signed by a NON-gate key is refused ─────────
    let head_before = follower.lock().unwrap().head;
    let (rogue_sk, _) = keygen();
    let (rogue_land, rogue_raw) = {
        let f = follower.lock().unwrap();
        let head = f.head.unwrap();
        let body = f.store.body(&head).clone();
        // same shape as a real landing, next seq, correct prev/base
        let mut fields = vec![
            ("ref", V::Text("trunk".into())),
            ("seq", V::Int(3)),
            ("prev", V::Bytes(head.to_vec())),
            ("base_state", body.get("target_state").unwrap().clone()),
            ("delta", V::Arr(vec![])),
            ("target_state", body.get("target_state").unwrap().clone()),
            ("manifest", body.get("manifest").unwrap().clone()),
            ("evidence", V::Arr(vec![])),
        ];
        fields.sort_by_key(|(k, _)| *k);
        make_obj(&rogue_sk, Some(repo), "landing", V::map(fields), None, ts())
    };
    follower.lock().unwrap().store.put(rogue_raw).unwrap();
    // even self-certified, the certificate author is not a gate key
    let (_, rogue_cert) = make_obj(&rogue_sk, Some(repo), "certificate", V::map(vec![
        ("subject", V::Bytes(rogue_land.to_vec())),
        ("signatures", V::Arr(vec![]))]), None, ts());
    follower.lock().unwrap().store.put(rogue_cert).unwrap();
    let chain = weftd::sync::verify_landing_chain(&follower.lock().unwrap());
    assert_eq!(chain.head, head_before, "forged landing must not advance the head");
    assert_eq!(chain.seq, 2);

    // ── forgery 2: a landing by the real gate key but UNCERTIFIED ────────
    let (uncert, uncert_raw) = {
        let f = follower.lock().unwrap();
        let head = f.head.unwrap();
        let body = f.store.body(&head).clone();
        let mut fields = vec![
            ("ref", V::Text("trunk".into())),
            ("seq", V::Int(3)),
            ("prev", V::Bytes(head.to_vec())),
            ("base_state", body.get("target_state").unwrap().clone()),
            ("delta", V::Arr(vec![])),
            ("target_state", body.get("target_state").unwrap().clone()),
            ("manifest", body.get("manifest").unwrap().clone()),
            ("evidence", V::Arr(vec![])),
        ];
        fields.sort_by_key(|(k, _)| *k);
        let gate_sk = gate.lock().unwrap().gate_sk.clone();
        make_obj(&gate_sk, Some(repo), "landing", V::map(fields), None, ts())
    };
    let _ = uncert;
    follower.lock().unwrap().store.put(uncert_raw).unwrap();
    let chain = weftd::sync::verify_landing_chain(&follower.lock().unwrap());
    assert_eq!(chain.head, head_before,
               "landing without a gate certificate must not advance the head");

    // ── fork: two CERTIFIED landings claiming the same slot are flagged ──
    let gate_sk = gate.lock().unwrap().gate_sk.clone();
    for tag in [b"forkA___", b"forkB___"] {
        let f_head = follower.lock().unwrap().head.unwrap();
        let body = follower.lock().unwrap().store.body(&f_head).clone();
        let mut fields = vec![
            ("ref", V::Text("trunk".into())),
            ("seq", V::Int(3)),
            ("prev", V::Bytes(f_head.to_vec())),
            ("base_state", body.get("target_state").unwrap().clone()),
            ("delta", V::Arr(vec![])),
            ("target_state", body.get("target_state").unwrap().clone()),
            ("manifest", body.get("manifest").unwrap().clone()),
            ("evidence", V::Arr(vec![])),
            ("nonce", V::Bytes(tag.to_vec())),
        ];
        fields.sort_by_key(|(k, _)| *k);
        let (l, raw) = make_obj(&gate_sk, Some(repo), "landing", V::map(fields), None, ts());
        follower.lock().unwrap().store.put(raw).unwrap();
        let (_, cert) = make_obj(&gate_sk, Some(repo), "certificate", V::map(vec![
            ("subject", V::Bytes(l.to_vec())),
            ("signatures", V::Arr(vec![]))]), None, ts());
        follower.lock().unwrap().store.put(cert).unwrap();
    }
    let chain = weftd::sync::verify_landing_chain(&follower.lock().unwrap());
    assert!(chain.fork.is_some(), "equivocation must be detected, not resolved");
    assert_eq!(chain.head, head_before, "a forked ref does not advance");
}
