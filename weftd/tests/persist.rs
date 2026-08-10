//! Production-readiness: the hub survives restarts. A WAL-backed store
//! replays with every signature re-verified; hub state (head landing, seq,
//! repo, authority, unlanded queue) rebuilds from objects; a torn tail is
//! truncated at the last good frame; and the gate key is stable across
//! reboots so the genesis stays valid.

use weft_core::cbor::V;
use weft_core::*;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn boot(data: &std::path::Path) -> weftd::Shared {
    let (hub, _) = weftd::new_hub_persistent(data).expect("open");
    hub
}

fn land_one(hub: &weftd::Shared, sk: &ed25519_dalek::SigningKey, repo: Oid,
            cap: Oid, path: &str, line: &str, nonce: &[u8]) -> Oid {
    let put = |body_raw: Vec<u8>| -> Oid {
        hub.lock().unwrap().store.put(body_raw).expect("put")
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let (_, p_raw) = make_obj(sk, Some(repo), "patch", V::map(vec![
        ("nonce", V::Bytes(nonce.to_vec())),
        ("ops", V::Arr(vec![
            V::Arr(vec![V::Text("mkfile".into()), V::Text(path.into())]),
            V::Arr(vec![V::Text("insert".into()),
                V::Arr(vec![V::Null, V::Int(0)]),
                V::Arr(vec![V::Text("S".into())]),
                V::Arr(vec![V::Bytes(line.as_bytes().to_vec())])])]))]), None, ts);
    let patch = put(p_raw);
    let (_, c_raw) = make_obj(sk, Some(repo), "change", V::map(vec![
        ("patch", V::Bytes(patch.to_vec())),
        ("footprint", V::Arr(vec![V::Text(path.into())])),
        ("reads", V::Arr(vec![])),
        ("message", V::Text(format!("add {path}")))]), Some(cap), ts);
    let change = put(c_raw);
    let (_, pr_raw) = make_obj(sk, Some(repo), "proposal", V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
        ("status", V::Text("open".into()))]), Some(cap), ts);
    let prop = put(pr_raw);
    hub.lock().unwrap().queue.push(prop);
    weftd::gate_tick(hub);
    change
}

#[test]
fn hub_state_survives_restarts_and_torn_tails() {
    let dir = std::env::temp_dir().join(format!("weft-persist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data = dir.join("hub.wal");

    // ── boot 1: genesis + capability + one landed change ─────────────────
    let (auth_sk, auth_pub) = keygen();
    let (repo, cap, head1);
    {
        let hub = boot(&data);
        let gate_pub = hub.lock().unwrap().gate_pub;
        let ts = 1_000;
        let (_, gen_raw) = make_obj(&auth_sk, None, "genesis", V::map(vec![
            ("name", V::Text("persist-e2e".into())),
            ("authority", V::Arr(vec![V::Bytes(auth_pub.to_vec())])),
            ("quorum", V::Int(1)),
            ("refs", V::map(vec![("trunk", V::map(vec![
                ("gates", V::Arr(vec![V::Bytes(gate_pub.to_vec())])),
                ("threshold", V::Int(1))]))])),
            ("policy_init", V::map(vec![
                ("rules", V::Arr(vec![])), ("recipes", V::Arr(vec![])),
                ("approvals", V::Int(0)), ("stale_reads", V::Text("reject".into()))])),
            ("config_init", V::map(vec![]))]), None, ts);
        {
            let mut h = hub.lock().unwrap();
            let gen = h.store.put(gen_raw).unwrap();
            repo = gen;
            h.repo = Some(gen);
            h.authority = vec![auth_pub.to_vec()];
            h.policy = h.store.get(&gen).get("body").unwrap()
                .get("policy_init").cloned();
        }
        let (_, cap_raw) = make_obj(&auth_sk, Some(repo), "capability", V::map(vec![
            ("audience", V::Bytes(auth_pub.to_vec())),
            ("parent", V::Null),
            ("scope", V::map(vec![
                ("actions", V::Arr(vec![V::Text("publish_change".into())])),
                ("paths", V::Arr(vec![V::Text("**".into())]))])),
            ("exp", V::Int(i64::MAX / 2))]), None, ts);
        cap = hub.lock().unwrap().store.put(cap_raw).unwrap();
        land_one(&hub, &auth_sk, repo, cap, "a.txt", "first life", b"boot1___");
        let h = hub.lock().unwrap();
        assert_eq!(h.seq, 0);
        head1 = h.head.unwrap();
    }

    // ── boot 2: replay — same repo, same head, same gate key; land more ──
    {
        let hub = boot(&data);
        let (seq, head, repo2) = {
            let h = hub.lock().unwrap();
            (h.seq, h.head, h.repo)
        };
        assert_eq!(seq, 0, "seq survives restart");
        assert_eq!(head, Some(head1), "head landing survives restart");
        assert_eq!(repo2, Some(repo), "genesis side-effects rebuilt");
        assert_eq!(hub.lock().unwrap().log.len(), 1, "log rebuilt");
        land_one(&hub, &auth_sk, repo, cap, "b.txt", "second life", b"boot2___");
        assert_eq!(hub.lock().unwrap().seq, 1, "can land after replay");
    }

    // ── torn tail: garbage appended to the WAL is truncated on open ──────
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&data).unwrap();
        f.write_all(&[0xde, 0xad, 0xbe, 0xef, 0x99]).unwrap();
    }
    {
        let hub = boot(&data);
        let h = hub.lock().unwrap();
        assert_eq!(h.seq, 1, "state intact after torn-tail truncation");
        // both files present in the head workspace
        let st = h.head_state.unwrap();
        let t: Vec<Oid> = state_set(&h.store, &st).into_iter().collect();
        let mat = materialize(&h.store, &t).unwrap();
        assert!(mat.tree.contains_key("a.txt") && mat.tree.contains_key("b.txt"));
        assert_eq!(mat.tree["a.txt"], b"first life\n");
    }

    // ── unlanded proposals are re-queued and re-adjudicated ──────────────
    {
        let hub = boot(&data);
        // a proposal written to the store but never landed (simulates a
        // crash between accept and tick)
        let ts = 2_000;
        let (_, p_raw) = make_obj(&auth_sk, Some(repo), "patch", V::map(vec![
            ("nonce", V::Bytes(b"orphan__".to_vec())),
            ("ops", V::Arr(vec![
                V::Arr(vec![V::Text("mkfile".into()), V::Text("c.txt".into())]),
                V::Arr(vec![V::Text("insert".into()),
                    V::Arr(vec![V::Null, V::Int(0)]),
                    V::Arr(vec![V::Text("S".into())]),
                    V::Arr(vec![V::Bytes(b"third life".to_vec())])])]))]), None, ts);
        let patch = hub.lock().unwrap().store.put(p_raw).unwrap();
        let (_, c_raw) = make_obj(&auth_sk, Some(repo), "change", V::map(vec![
            ("patch", V::Bytes(patch.to_vec())),
            ("footprint", V::Arr(vec![V::Text("c.txt".into())])),
            ("reads", V::Arr(vec![])),
            ("message", V::Text("orphan".into()))]), Some(cap), ts);
        let change = hub.lock().unwrap().store.put(c_raw).unwrap();
        let (_, pr_raw) = make_obj(&auth_sk, Some(repo), "proposal", V::map(vec![
            ("ref", V::Text("trunk".into())),
            ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
            ("status", V::Text("open".into()))]), Some(cap), ts);
        hub.lock().unwrap().store.put(pr_raw).unwrap();
        // crash here (no queue push, no tick) — then reboot:
        drop(hub);
        let hub = boot(&data);
        assert_eq!(hub.lock().unwrap().queue.len(), 1, "orphan proposal requeued");
        weftd::gate_tick(&hub);
        let h = hub.lock().unwrap();
        assert_eq!(h.seq, 2, "orphan landed after reboot: {}", h.rejects.join(","));
        assert!(h.log.last().unwrap().contains(&hexs(&change)));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Sandboxed evidence execution: a recipe that needs the network must FAIL
/// under `unshare -r -n`. Probe-gated: skips where unprivileged user
/// namespaces are unavailable (Windows, restricted CI kernels).
#[test]
fn sandbox_blocks_network_in_evidence() {
    if !weftd::sandbox_available() {
        eprintln!("skip: unshare userns sandbox unavailable on this host");
        return;
    }
    let hub = weftd::new_hub();
    hub.lock().unwrap().sandbox = "unshare".into();
    let (auth_sk, auth_pub) = keygen();
    let gate_pub = hub.lock().unwrap().gate_pub;
    let net_recipe = V::map(vec![
        ("kind", V::Text("test".into())),
        ("image", V::Text("local".into())),
        ("cmd", V::Arr(vec![V::Text("python3".into()), V::Text("-c".into()),
            V::Text("import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=3)".into())]))]);
    let ts = 1_000;
    let (_, gen_raw) = make_obj(&auth_sk, None, "genesis", V::map(vec![
        ("name", V::Text("sandbox-e2e".into())),
        ("authority", V::Arr(vec![V::Bytes(auth_pub.to_vec())])),
        ("quorum", V::Int(1)),
        ("refs", V::map(vec![("trunk", V::map(vec![
            ("gates", V::Arr(vec![V::Bytes(gate_pub.to_vec())])),
            ("threshold", V::Int(1))]))])),
        ("policy_init", V::map(vec![
            ("rules", V::Arr(vec![])),
            ("recipes", V::Arr(vec![net_recipe])),
            ("approvals", V::Int(0)), ("stale_reads", V::Text("warn".into()))])),
        ("config_init", V::map(vec![]))]), None, ts);
    let repo = {
        let mut h = hub.lock().unwrap();
        let gen = h.store.put(gen_raw).unwrap();
        h.repo = Some(gen);
        h.authority = vec![auth_pub.to_vec()];
        h.policy = h.store.get(&gen).get("body").unwrap().get("policy_init").cloned();
        gen
    };
    let (_, cap_raw) = make_obj(&auth_sk, Some(repo), "capability", V::map(vec![
        ("audience", V::Bytes(auth_pub.to_vec())),
        ("parent", V::Null),
        ("scope", V::map(vec![
            ("actions", V::Arr(vec![V::Text("publish_change".into())])),
            ("paths", V::Arr(vec![V::Text("**".into())]))])),
        ("exp", V::Int(i64::MAX / 2))]), None, ts);
    let cap = hub.lock().unwrap().store.put(cap_raw).unwrap();
    land_one_sandbox(&hub, &auth_sk, repo, cap);
    let h = hub.lock().unwrap();
    assert_eq!(h.seq, -1, "network recipe must fail inside the sandbox");
    assert!(h.rejects.iter().any(|r| r.contains("evidence failed")),
            "rejects: {:?}", h.rejects);
}

fn land_one_sandbox(hub: &weftd::Shared, sk: &ed25519_dalek::SigningKey,
                    repo: Oid, cap: Oid) {
    let ts = 1_500;
    let (_, p_raw) = make_obj(sk, Some(repo), "patch", V::map(vec![
        ("nonce", V::Bytes(b"sbx_____".to_vec())),
        ("ops", V::Arr(vec![
            V::Arr(vec![V::Text("mkfile".into()), V::Text("x.txt".into())]),
            V::Arr(vec![V::Text("insert".into()),
                V::Arr(vec![V::Null, V::Int(0)]),
                V::Arr(vec![V::Text("S".into())]),
                V::Arr(vec![V::Bytes(b"x".to_vec())])])]))]), None, ts);
    let patch = hub.lock().unwrap().store.put(p_raw).unwrap();
    let (_, c_raw) = make_obj(sk, Some(repo), "change", V::map(vec![
        ("patch", V::Bytes(patch.to_vec())),
        ("footprint", V::Arr(vec![V::Text("x.txt".into())])),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("sandboxed".into()))]), Some(cap), ts);
    let change = hub.lock().unwrap().store.put(c_raw).unwrap();
    let (_, pr_raw) = make_obj(sk, Some(repo), "proposal", V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
        ("status", V::Text("open".into()))]), Some(cap), ts);
    let prop = hub.lock().unwrap().store.put(pr_raw).unwrap();
    hub.lock().unwrap().queue.push(prop);
    weftd::gate_tick(hub);
}
