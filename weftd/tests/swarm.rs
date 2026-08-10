//! Full-loop integration test: an in-process weftd gate, three concurrent
//! workers over real HTTP, certified landings, and light-client verification
//! (local re-materialization must match the gate's manifest).

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use weft_core::cbor::V;
use weft_core::*;

const PORT: u16 = 18747;

// ------------------------------------------------- tiny http client --------

fn http(method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", PORT)).expect("connect");
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        body.len());
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("headers") + 4;
    let status: u16 = std::str::from_utf8(&resp[..split]).unwrap()
        .split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, resp[split..].to_vec())
}

fn get_json(path: &str) -> String {
    let (code, body) = http("GET", path, b"");
    assert_eq!(code, 200, "GET {path}: {}", String::from_utf8_lossy(&body));
    String::from_utf8(body).unwrap()
}

/// Minimal JSON scraping (values we produce are simple + hex).
fn jfield<'a>(json: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\":");
    let start = json.find(&pat).unwrap_or_else(|| panic!("{key} in {json}")) + pat.len();
    let rest = &json[start..];
    if let Some(inner) = rest.strip_prefix('"') {
        &inner[..inner.find('"').unwrap()]
    } else {
        let end = rest.find([',', '}', ']']).unwrap();
        &rest[..end]
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// ---------------------------------------------------------- helpers --------

struct Client {
    store: Store,
    repo: Oid,
}

impl Client {
    fn publish(&mut self, sk: &ed25519_dalek::SigningKey, typ: &str, body: V,
               auth: Option<Oid>) -> Oid {
        let (oid, raw) = make_obj(sk, Some(self.repo), typ, body, auth, weftd::now_ms());
        self.store.put(raw.clone()).expect("valid locally");
        let (code, resp) = http("POST", "/obj", &raw);
        assert_eq!(code, 200, "{}", String::from_utf8_lossy(&resp));
        oid
    }
    fn fetch(&mut self, oid: &Oid) {
        if self.store.contains(oid) {
            return;
        }
        let hexoid: String = oid.iter().map(|b| format!("{b:02x}")).collect();
        let (code, raw) = http("GET", &format!("/obj/{hexoid}"), b"");
        assert_eq!(code, 200);
        self.store.put(raw).expect("fetched object verifies");
    }
}

fn id_v(oid: Option<&Oid>, ord: i64) -> V {
    V::Arr(vec![oid.map(|o| V::Bytes(o.to_vec())).unwrap_or(V::Null), V::Int(ord)])
}

#[test]
fn swarm_through_certified_gate() {
    // --- boot the hub in-process --------------------------------------
    let hub = weftd::new_hub();
    let gate_pub = hub.lock().unwrap().gate_pub;
    {
        let hub = hub.clone();
        std::thread::spawn(move || weftd::serve(PORT, hub));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    // --- genesis with inline policy (finding W3) ----------------------
    let (auth_sk, auth_pub) = keygen();
    let recipe_cmd: Vec<V> = if cfg!(windows) {
        ["cmd", "/C", "exit 0"].iter().map(|s| V::Text((*s).into())).collect()
    } else {
        vec![V::Text("true".into())]
    };
    let recipe = V::map(vec![
        ("kind", V::Text("test".into())),
        ("image", V::Text("local".into())),
        ("cmd", V::Arr(recipe_cmd)),
    ]);
    let policy = V::map(vec![
        ("rules", V::Arr(vec![])),
        ("recipes", V::Arr(vec![recipe])),
        ("stale_reads", V::Text("warn".into())),
    ]);
    let (gen, gen_raw) = make_obj(&auth_sk, None, "genesis", V::map(vec![
        ("name", V::Text("swarm-test".into())),
        ("authority", V::Arr(vec![V::Bytes(auth_pub.to_vec())])),
        ("quorum", V::Int(1)),
        ("refs", V::map(vec![("trunk", V::map(vec![
            ("gates", V::Arr(vec![V::Bytes(gate_pub.to_vec())])),
            ("threshold", V::Int(1))]))])),
        ("policy_init", policy),
        ("config_init", V::map(vec![])),
    ]), None, weftd::now_ms());
    let (code, _) = http("POST", "/obj", &gen_raw);
    assert_eq!(code, 200);
    let mut cl = Client { store: Store::default(), repo: gen };
    cl.store.put(gen_raw).unwrap();

    // --- capabilities: authority → orchestrator → workers --------------
    let exp = weftd::now_ms() + 600_000;
    let cap_auth = cl.publish(&auth_sk, "capability", V::map(vec![
        ("audience", V::Bytes(auth_pub.to_vec())),
        ("parent", V::Null),
        ("scope", V::map(vec![
            ("actions", V::Arr(vec![V::Text("publish_change".into())])),
            ("paths", V::Arr(vec![V::Text("**".into())]))])),
        ("exp", V::Int(exp))]), None);
    let (orch_sk, orch_pub) = keygen();
    let cap_orch = cl.publish(&auth_sk, "capability", V::map(vec![
        ("audience", V::Bytes(orch_pub.to_vec())),
        ("parent", V::Null),
        ("scope", V::map(vec![
            ("actions", V::Arr(vec![V::Text("publish_change".into()),
                                    V::Text("delegate".into())])),
            ("paths", V::Arr(vec![V::Text("**".into())]))])),
        ("exp", V::Int(exp))]), None);

    // --- base landing: single self-filling patch (finding W5) ----------
    let base_patch = cl.publish(&auth_sk, "patch", V::map(vec![
        ("nonce", V::Bytes(b"basefill".to_vec())),
        ("ops", V::Arr(vec![
            V::Arr(vec![V::Text("mkfile".into()), V::Text("quotes.txt".into())]),
            V::Arr(vec![V::Text("insert".into()), id_v(None, 0),
                        V::Arr(vec![V::Text("S".into())]),
                        V::Arr(vec![V::Bytes(b"Talk is cheap.".to_vec())])])]))]),
        None);
    let base_change = cl.publish(&auth_sk, "change", V::map(vec![
        ("patch", V::Bytes(base_patch.to_vec())),
        ("footprint", V::Arr(vec![V::Text("quotes.txt".into())])),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("seed".into()))]), Some(cap_auth));
    let prop = cl.publish(&auth_sk, "proposal", V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("delta", V::Arr(vec![V::Bytes(base_change.to_vec())])),
        ("status", V::Text("open".into()))]), Some(cap_auth));
    let (code, resp) = http("POST", "/propose", &cl.store.raw[&prop].clone());
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&resp));
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if jfield(&get_json("/heads"), "seq") != "-1" {
            break;
        }
    }
    assert_ne!(jfield(&get_json("/heads"), "seq"), "-1", "base landing timed out");

    // --- three workers, concurrent, real HTTP ---------------------------
    let models = ["claude-fable-5", "gpt-5.6-sol", "qwen3.8-max"];
    let mut handles = Vec::new();
    for (i, model) in models.iter().enumerate() {
        let cap_orch = cap_orch;
        let orch_sk = orch_sk.clone();
        let repo = gen;
        let model = model.to_string();
        handles.push(std::thread::spawn(move || {
            let (w_sk, w_pub) = keygen();
            let mut cl = Client { store: Store::default(), repo };
            // fetch genesis + orch cap so local store can verify chains
            cl.fetch(&repo);
            cl.fetch(&cap_orch);
            let cap_w = cl.publish(&orch_sk, "capability", V::map(vec![
                ("audience", V::Bytes(w_pub.to_vec())),
                ("parent", V::Bytes(cap_orch.to_vec())),
                ("scope", V::map(vec![
                    ("actions", V::Arr(vec![V::Text("publish_change".into())])),
                    ("paths", V::Arr(vec![V::Text("quotes.txt".into())]))])),
                ("exp", V::Int(weftd::now_ms() + 300_000))]), None);
            let ws = get_json("/workspace");
            // the file-ID of quotes.txt, from the workspace's "fid" field
            let fid_sec = &ws[ws.find("\"fid\":[\"").expect("fid") + 8..];
            let fid_oid: Oid = from_hex(&fid_sec[..64]).try_into().unwrap();
            let fid_ord: i64 = fid_sec[66..fid_sec.find(']').unwrap()].parse().unwrap();
            // anchor on the LAST line id (format ["<hex>",<ord>])
            let lid_sec = ws.rsplit("[\"").next().unwrap();
            let anchor: Oid = from_hex(&lid_sec[..64]).try_into().unwrap();
            let anchor_ord: i64 = lid_sec[66..lid_sec.find(']').unwrap()].parse().unwrap();
            let patch = cl.publish(&w_sk, "patch", V::map(vec![
                ("nonce", V::Bytes(model.as_bytes().to_vec())),
                ("ops", V::Arr(vec![V::Arr(vec![
                    V::Text("insert".into()),
                    id_v(Some(&fid_oid), fid_ord),
                    id_v(Some(&anchor), anchor_ord),
                    V::Arr(vec![V::Bytes(format!("quote from {model}").into_bytes())])])]))]),
                None);
            let change = cl.publish(&w_sk, "change", V::map(vec![
                ("patch", V::Bytes(patch.to_vec())),
                ("footprint", V::Arr(vec![V::Text("quotes.txt".into())])),
                ("reads", V::Arr(vec![])),
                ("message", V::Text(format!("append {i}"))),
                ("provenance", V::map(vec![("model", V::Text(model.clone()))]))]),
                Some(cap_w));
            let prop = cl.publish(&w_sk, "proposal", V::map(vec![
                ("ref", V::Text("trunk".into())),
                ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
                ("status", V::Text("open".into()))]), Some(cap_w));
            let raw = cl.store.raw[&prop].clone();
            let (code, _) = http("POST", "/propose", &raw);
            assert_eq!(code, 200);
            let hexc: String = change.iter().map(|b| format!("{b:02x}")).collect();
            for _ in 0..200 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if get_json("/log").contains(&hexc) {
                    return true;
                }
            }
            false
        }));
    }
    let landed = handles.into_iter()
        .map(|h| h.join().expect("worker thread")).filter(|ok| *ok).count();
    assert_eq!(landed, 3, "all three workers must land");

    // --- final content has all three quotes -----------------------------
    let ws = get_json("/workspace");
    for model in models {
        assert!(ws.contains(&format!("quote from {model}")), "missing {model}");
    }

    // --- light-client verification (RFC §7.4) ---------------------------
    let heads = get_json("/heads");
    let landing: Oid = from_hex(jfield(&heads, "landing")).try_into().unwrap();
    let mut cl = Client { store: Store::default(), repo: gen };
    cl.fetch(&landing);
    let man_oid = as_oid(cl.store.body(&landing).get("manifest").unwrap());
    cl.fetch(&man_oid);
    let st = as_oid(cl.store.body(&landing).get("target_state").unwrap());
    let mut todo = vec![st];
    while let Some(s) = todo.pop() {
        cl.fetch(&s);
        let body = cl.store.body(&s).clone();
        for c in body.get("add").and_then(V::arr).unwrap_or(&[]) {
            let c = as_oid(c);
            cl.fetch(&c);
            let p = as_oid(cl.store.body(&c).get("patch").unwrap());
            cl.fetch(&p);
        }
        if let Some(b) = body.get("base") {
            if !matches!(b, V::Null) {
                todo.push(as_oid(b));
            }
        }
    }
    let target: Vec<Oid> = state_set(&cl.store, &st).into_iter().collect();
    let closure: BTreeSet<Oid> = target.iter().copied().collect();
    assert!(closure_ok(&cl.store, &closure));
    let mat = materialize(&cl.store, &target).unwrap();
    let man = cl.store.body(&man_oid);
    for k in ["tree_root", "file_map_root", "conflict_root", "clean"] {
        assert_eq!(mat.manifest.get(k), man.get(k),
                   "light client mismatch on {k}");
    }
}
