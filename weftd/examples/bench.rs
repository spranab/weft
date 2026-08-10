//! Weft benchmark suite — the four numbers that matter for the design-center
//! workload (N agents, continuous certified merging):
//!
//!   B1  object ingest        sign + canonical-decode + verify + store
//!   B2  materialization      RGA engine vs change-set size (the hot path)
//!   B3  gate, disjoint       best case: footprint-disjoint work batches
//!   B4  gate, contended      worst case: same-file work fully serializes
//!
//! Run: cargo run --release -p weftd --example bench

use std::time::Instant;
use weft_core::cbor::V;
use weft_core::*;

const REPO: Oid = [7u8; 32];

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 16
    }
}

fn id_v(oid: Option<&Oid>, ord: i64) -> V {
    V::Arr(vec![oid.map(|o| V::Bytes(o.to_vec())).unwrap_or(V::Null), V::Int(ord)])
}
fn start() -> V {
    V::Arr(vec![V::Text("S".into())])
}

fn publish(store: &mut Store, sk: &ed25519_dalek::SigningKey, typ: &str, body: V) -> Oid {
    let (_, raw) = make_obj(sk, Some(REPO), typ, body, None, 0);
    store.put(raw).unwrap()
}

fn change(store: &mut Store, sk: &ed25519_dalek::SigningKey, ops: Vec<V>, nonce: u64,
          footprint: Vec<&str>) -> Oid {
    let p = publish(store, sk, "patch", V::map(vec![
        ("nonce", V::Bytes(nonce.to_be_bytes().to_vec())),
        ("ops", V::Arr(ops))]));
    publish(store, sk, "change", V::map(vec![
        ("patch", V::Bytes(p.to_vec())),
        ("footprint", V::Arr(footprint.iter().map(|f| V::Text((*f).into())).collect())),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("bench".into()))]))
}

/// Base: F files, L lines each, one SELF-sentinel patch.
fn base(store: &mut Store, sk: &ed25519_dalek::SigningKey, nf: usize, nl: usize)
        -> (Oid, Oid) {
    let mut ops: Vec<V> = (0..nf).map(|f| V::Arr(vec![
        V::Text("mkfile".into()), V::Text(format!("f{f}.txt"))])).collect();
    for f in 0..nf {
        let lines: Vec<V> = (0..nl)
            .map(|j| V::Bytes(format!("file{f} line{j} padding padding padding").into_bytes()))
            .collect();
        ops.push(V::Arr(vec![V::Text("insert".into()), id_v(None, f as i64),
                             start(), V::Arr(lines)]));
    }
    let p = publish(store, sk, "patch", V::map(vec![
        ("nonce", V::Bytes(b"base....".to_vec())), ("ops", V::Arr(ops))]));
    let c = publish(store, sk, "change", V::map(vec![
        ("patch", V::Bytes(p.to_vec())),
        ("footprint", V::Arr((0..nf).map(|f| V::Text(format!("f{f}.txt"))).collect())),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("base".into()))]));
    (p, c)
}

fn b1_ingest(sk: &ed25519_dalek::SigningKey) {
    let mut store = Store::default();
    let n = 2_000;
    let raws: Vec<Vec<u8>> = (0..n).map(|i| {
        make_obj(sk, Some(REPO), "note", V::map(vec![
            ("kind", V::Text("context".into())),
            ("text", V::Text(format!("benchmark note number {i} with some realistic length to it"))),
            ("anchors", V::Arr(vec![]))]), None, i).1
    }).collect();
    let t = Instant::now();
    for raw in raws {
        store.put(raw).unwrap();
    }
    let dt = t.elapsed();
    println!("B1 object ingest      {:>8.0} obj/s   (decode+verify+store, n={n})",
             n as f64 / dt.as_secs_f64());
}

fn b2_materialize(sk: &ed25519_dalek::SigningKey) {
    for k in [100usize, 1_000, 5_000] {
        let mut store = Store::default();
        let (bp, bc) = base(&mut store, sk, 10, 20);
        let mut rng = Lcg(42);
        let mut all = vec![bc];
        for i in 0..k {
            let f = (rng.next() % 10) as i64;
            // file f's line ordinals are 10 + f*20 .. 10 + f*20 + 19
            let anchor_ord = 10 + f * 20 + (rng.next() % 20) as i64;
            all.push(change(&mut store, sk,
                vec![V::Arr(vec![V::Text("insert".into()), id_v(Some(&bp), f),
                                 id_v(Some(&bp), anchor_ord),
                                 V::Arr(vec![V::Bytes(format!("concurrent edit {i}").into_bytes())])])],
                i as u64, vec![]));
        }
        let t = Instant::now();
        let m = materialize(&store, &all).unwrap();
        let dt = t.elapsed();
        let lines: usize = m.line_index.values().map(|v| v.len()).sum();
        println!("B2 materialize {k:>5}   {:>8.1} ms     ({lines} lines, {:.0} changes/s)",
                 dt.as_secs_f64() * 1e3, all.len() as f64 / dt.as_secs_f64());
    }
}

fn gate_run(disjoint: bool, n: usize) -> (f64, i64) {
    let hub = weftd::new_hub();
    let (auth_sk, auth_pub) = keygen();
    {
        let mut h = hub.lock().unwrap();
        let gate_pub = h.gate_pub;
        let (_, gen_raw) = make_obj(&auth_sk, None, "genesis", V::map(vec![
            ("name", V::Text("bench".into())),
            ("authority", V::Arr(vec![V::Bytes(auth_pub.to_vec())])),
            ("quorum", V::Int(1)),
            ("refs", V::map(vec![("trunk", V::map(vec![
                ("gates", V::Arr(vec![V::Bytes(gate_pub.to_vec())])),
                ("threshold", V::Int(1))]))])),
            ("policy_init", V::map(vec![
                ("rules", V::Arr(vec![])), ("recipes", V::Arr(vec![])),
                ("approvals", V::Int(0)), ("stale_reads", V::Text("warn".into()))])),
            ("config_init", V::map(vec![]))]), None, 0);
        let gen = h.store.put(gen_raw).unwrap();
        h.repo = Some(gen);
        h.authority = vec![auth_pub.to_vec()];
        h.policy = h.store.get(&gen).get("body").unwrap().get("policy_init").cloned();
        // authority self-capability
        let (_, cap_raw) = make_obj(&auth_sk, Some(gen), "capability", V::map(vec![
            ("audience", V::Bytes(auth_pub.to_vec())),
            ("parent", V::Null),
            ("scope", V::map(vec![
                ("actions", V::Arr(vec![V::Text("publish_change".into())])),
                ("paths", V::Arr(vec![V::Text("**".into())]))])),
            ("exp", V::Int(i64::MAX))]), None, 0);
        let cap = h.store.put(cap_raw).unwrap();

        // contended case: a shared base file everyone appends to (same
        // footprint → serialized), created up front so appends are clean
        let mut shared: Option<Oid> = None;
        if !disjoint {
            let (_, sp_raw) = make_obj(&auth_sk, Some(gen), "patch", V::map(vec![
                ("nonce", V::Bytes(b"shared..".to_vec())),
                ("ops", V::Arr(vec![
                    V::Arr(vec![V::Text("mkfile".into()), V::Text("w0.txt".into())]),
                    V::Arr(vec![V::Text("insert".into()), id_v(None, 0), start(),
                                V::Arr(vec![V::Bytes(b"seed".to_vec())])])]))]),
                None, 0);
            let sp = h.store.put(sp_raw).unwrap();
            let (_, sc_raw) = make_obj(&auth_sk, Some(gen), "change", V::map(vec![
                ("patch", V::Bytes(sp.to_vec())),
                ("footprint", V::Arr(vec![V::Text("w0.txt".into())])),
                ("reads", V::Arr(vec![])),
                ("message", V::Text("seed".into()))]), Some(cap), 0);
            let sc = h.store.put(sc_raw).unwrap();
            let (_, spr_raw) = make_obj(&auth_sk, Some(gen), "proposal", V::map(vec![
                ("ref", V::Text("trunk".into())),
                ("delta", V::Arr(vec![V::Bytes(sc.to_vec())])),
                ("status", V::Text("open".into()))]), Some(cap), 0);
            let spr = h.store.put(spr_raw).unwrap();
            h.queue.push(spr);
            shared = Some(sp);
        }
        // per-proposal: one change; disjoint = own new file, contended =
        // append to the shared file (same-anchor is an advisory marker, so
        // every landing is clean — this measures pure serialization)
        for i in 0..n {
            let fname = if disjoint { format!("w{i}.txt") } else { "w0.txt".to_string() };
            let ops = if let Some(sp) = shared {
                vec![V::Arr(vec![V::Text("insert".into()),
                                 id_v(Some(&sp), 0), id_v(Some(&sp), 1),
                                 V::Arr(vec![V::Bytes(format!("append {i}").into_bytes())])])]
            } else {
                vec![V::Arr(vec![V::Text("mkfile".into()), V::Text(fname.clone())])]
            };
            let (_, p_raw) = make_obj(&auth_sk, Some(gen), "patch", V::map(vec![
                ("nonce", V::Bytes((i as u64).to_be_bytes().to_vec())),
                ("ops", V::Arr(ops))]), None, 0);
            let p = h.store.put(p_raw).unwrap();
            let (_, c_raw) = make_obj(&auth_sk, Some(gen), "change", V::map(vec![
                ("patch", V::Bytes(p.to_vec())),
                ("footprint", V::Arr(vec![V::Text(fname)])),
                ("reads", V::Arr(vec![])),
                ("message", V::Text(format!("w{i}")))]), Some(cap), 0);
            let c = h.store.put(c_raw).unwrap();
            let (_, pr_raw) = make_obj(&auth_sk, Some(gen), "proposal", V::map(vec![
                ("ref", V::Text("trunk".into())),
                ("delta", V::Arr(vec![V::Bytes(c.to_vec())])),
                ("status", V::Text("open".into()))]), Some(cap), 0);
            let pr = h.store.put(pr_raw).unwrap();
            h.queue.push(pr);
        }
    }
    let t = Instant::now();
    loop {
        weftd::gate_tick(&hub);
        let h = hub.lock().unwrap();
        if h.queue.is_empty() {
            break;
        }
    }
    let dt = t.elapsed().as_secs_f64();
    let seq = hub.lock().unwrap().seq;
    (n as f64 / dt, seq + 1)
}

fn main() {
    println!("weft-bench  ({} logical cores, release={})",
             std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
             !cfg!(debug_assertions));
    let (sk, _) = keygen();
    b1_ingest(&sk);
    b2_materialize(&sk);
    let (rate, landings) = gate_run(true, 500);
    println!("B3 gate disjoint      {rate:>8.0} chg/s   (500 proposals → {landings} landing(s): batching)");
    let (rate, landings) = gate_run(false, 300);
    println!("B4 gate contended     {rate:>8.0} chg/s   (300 same-file appends → {landings} landings: serialized)");
}
