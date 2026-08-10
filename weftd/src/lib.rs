//! weftd — the Weft reference hub (prototype tier): in-memory object store,
//! a trunk gate running the RFC §7 loop (batch footprint-disjoint proposals,
//! fix the target state, re-materialize, run the §7.3 checklist, execute the
//! policy-pinned evidence recipes in a scratch dir, certify a landing), and
//! a plain HTTP surface. Single-node, threshold-1 certificates; sync frames
//! and multi-gate quorums are the next milestone.

use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use weft_core::cbor::V;
use weft_core::*;

pub struct Hub {
    pub store: Store,
    pub repo: Option<Oid>,
    pub authority: Vec<Vec<u8>>,
    pub policy: Option<V>,
    pub head: Option<Oid>,
    pub head_state: Option<Oid>,
    pub seq: i64,
    pub queue: Vec<Oid>,
    pub log: Vec<String>,    // pre-rendered JSON entries
    pub rejects: Vec<String>,
    pub gate_sk: SigningKey,
    pub gate_pub: [u8; 32],
}

pub type Shared = Arc<Mutex<Hub>>;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn jesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn new_hub() -> Shared {
    let (gate_sk, gate_pub) = keygen();
    Arc::new(Mutex::new(Hub {
        store: Store::default(),
        repo: None,
        authority: vec![],
        policy: None,
        head: None,
        head_state: None,
        seq: -1,
        queue: vec![],
        log: vec![],
        rejects: vec![],
        gate_sk,
        gate_pub,
    }))
}

// ------------------------------------------------------------ gate ---------

pub fn gate_tick(shared: &Shared) {
    // drain + batch by disjoint footprints (RFC §7.5)
    let batch: Vec<(Oid, Vec<Oid>)> = {
        let mut hub = shared.lock().unwrap();
        if hub.repo.is_none() || hub.queue.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut hub.queue);
        let mut taken = Vec::new();
        let mut fps: BTreeSet<String> = BTreeSet::new();
        let mut requeue = Vec::new();
        for prop in pending {
            let delta: Vec<Oid> = hub.store.body(&prop)
                .get("delta").and_then(V::arr).unwrap_or(&[])
                .iter().map(as_oid).collect();
            let mine: BTreeSet<String> = delta.iter().flat_map(|c| {
                hub.store.body(c).get("footprint").and_then(V::arr).unwrap_or(&[])
                    .iter().filter_map(|p| p.text().map(String::from))
                    .collect::<Vec<_>>()
            }).collect();
            if mine.is_disjoint(&fps) {
                fps.extend(mine);
                taken.push((prop, delta));
            } else {
                requeue.push(prop);
            }
        }
        hub.queue = requeue;
        taken
    };
    if !batch.is_empty() {
        land(shared, batch);
    }
}

fn land(shared: &Shared, batch: Vec<(Oid, Vec<Oid>)>) {
    let mut hub = shared.lock().unwrap();
    let hub = &mut *hub;
    let repo = hub.repo.unwrap();
    let ts = now_ms();
    let delta: Vec<Oid> = batch.iter().flat_map(|(_, d)| d.iter().copied()).collect();
    let sk = hub.gate_sk.clone();
    let st = make_state(&sk, repo, hub.head_state, &delta, &mut hub.store, ts);
    let target: Vec<Oid> = state_set(&hub.store, &st).into_iter().collect();
    let mat = match materialize(&hub.store, &target) {
        Ok(m) => m,
        Err(e) => {
            hub.rejects.push(format!("{{\"error\":\"{}\"}}", jesc(&e)));
            return;
        }
    };
    let (man, man_raw) = make_obj(&sk, Some(repo), "manifest", mat.manifest.clone(), None, ts);
    hub.store.put(man_raw).expect("manifest stores");
    let seq = hub.seq + 1;
    let policy = hub.policy.clone().expect("policy after genesis");
    let stale = policy.get("stale_reads").and_then(V::text).unwrap_or("reject").to_string();
    let body = V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("seq", V::Int(seq)),
        ("prev", hub.head.map(|h| V::Bytes(h.to_vec())).unwrap_or(V::Null)),
        ("base_state", hub.head_state.map(|s| V::Bytes(s.to_vec())).unwrap_or(V::Null)),
        ("delta", V::Arr(delta.iter().map(|c| V::Bytes(c.to_vec())).collect())),
        ("target_state", V::Bytes(st.to_vec())),
        ("manifest", V::Bytes(man.to_vec())),
        ("proposals", V::Arr(batch.iter().map(|(p, _)| V::Bytes(p.to_vec())).collect())),
    ]);
    let chk = check_landing(&hub.store, &body, &hub.authority, ts, &stale);
    if !chk.errors.is_empty() {
        let msg = chk.errors.iter().map(|e| format!("\"{}\"", jesc(e)))
            .collect::<Vec<_>>().join(",");
        hub.rejects.push(format!("{{\"seq_attempt\":{seq},\"errors\":[{msg}]}}"));
        return;
    }
    // evidence execution: pinned recipes in a scratch dir (RFC §12.5 minimums
    // for the prototype: fresh dir per run, no inherited stdin, timeout via
    // process wait — full sandboxing is the real daemon's job)
    let mut ev_oids = Vec::new();
    for recipe in policy.get("recipes").and_then(V::arr).unwrap_or(&[]) {
        let dir = std::env::temp_dir().join(format!("weft-gate-{}-{}", std::process::id(), seq));
        let _ = std::fs::remove_dir_all(&dir);
        for (path, content) in &mat.tree {
            let fp = dir.join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = fp.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(fp, content).expect("write tree file");
        }
        let cmd: Vec<String> = recipe.get("cmd").and_then(V::arr).unwrap_or(&[])
            .iter().filter_map(|x| x.text().map(String::from)).collect();
        let status = std::process::Command::new(&cmd[0]).args(&cmd[1..])
            .current_dir(&dir).stdin(std::process::Stdio::null()).status();
        let pass = matches!(status, Ok(s) if s.success());
        let _ = std::fs::remove_dir_all(&dir);
        let ev_body = V::map(vec![
            ("manifest", V::Bytes(man.to_vec())),
            ("recipe", recipe.clone()),
            ("results", V::Arr(vec![V::map(vec![
                ("status", V::Text(if pass { "pass" } else { "fail" }.into()))])])),
        ]);
        let (ev, ev_raw) = make_obj(&sk, Some(repo), "evidence", ev_body, None, ts);
        hub.store.put(ev_raw).expect("evidence stores");
        ev_oids.push(ev);
        if !pass {
            hub.rejects.push(format!("{{\"seq_attempt\":{seq},\"errors\":[\"evidence failed\"]}}"));
            return;
        }
    }
    let mut fields = vec![("evidence",
        V::Arr(ev_oids.iter().map(|e| V::Bytes(e.to_vec())).collect()))];
    if let V::Map(m) = &body {
        for (k, v) in m {
            fields.push((match k.text().unwrap() {
                "ref" => "ref", "seq" => "seq", "prev" => "prev",
                "base_state" => "base_state", "delta" => "delta",
                "target_state" => "target_state", "manifest" => "manifest",
                "proposals" => "proposals", other => other,
            }, v.clone()));
        }
    }
    let final_body = V::map(fields.into_iter().collect());
    let (lnd, lnd_raw) = make_obj(&sk, Some(repo), "landing", final_body, None, ts);
    hub.store.put(lnd_raw).expect("landing stores");
    let cert_body = V::map(vec![
        ("subject", V::Bytes(lnd.to_vec())),
        ("signatures", V::Arr(vec![V::Arr(vec![
            V::Bytes(hub.gate_pub.to_vec()), V::Bytes(vec![])])])),
    ]);
    let (_, cert_raw) = make_obj(&sk, Some(repo), "certificate", cert_body, None, ts);
    hub.store.put(cert_raw).expect("certificate stores");
    hub.head = Some(lnd);
    hub.head_state = Some(st);
    hub.seq = seq;
    let changes_json: Vec<String> = delta.iter().map(|c| {
        let b = hub.store.body(c);
        let model = b.get("provenance").and_then(|p| p.get("model"))
            .and_then(V::text).unwrap_or("none");
        let msg = b.get("message").and_then(V::text).unwrap_or("");
        format!("{{\"oid\":\"{}\",\"model\":\"{}\",\"message\":\"{}\"}}",
                hex(c), jesc(model), jesc(msg))
    }).collect();
    let warns: Vec<String> = chk.warnings.iter()
        .map(|w| format!("\"{}\"", jesc(w))).collect();
    hub.log.push(format!(
        "{{\"seq\":{seq},\"landing\":\"{}\",\"markers\":{},\"warnings\":[{}],\"changes\":[{}]}}",
        hex(&lnd), mat.markers.len(), warns.join(","), changes_json.join(",")));
}

// ------------------------------------------------------------ http ---------

pub fn serve(port: u16, shared: Shared) {
    {
        let s = shared.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            gate_tick(&s);
        });
    }
    let server = tiny_http::Server::http(("127.0.0.1", port)).expect("bind");
    for mut req in server.incoming_requests() {
        let url = req.url().to_string();
        let method = req.method().to_string();
        let mut body = Vec::new();
        let _ = req.as_reader().read_to_end(&mut body);
        let (code, payload, ctype) = route(&shared, &method, &url, body);
        let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype.as_bytes()).unwrap();
        let _ = req.respond(tiny_http::Response::from_data(payload)
            .with_status_code(code).with_header(header));
    }
}

fn route(shared: &Shared, method: &str, url: &str, body: Vec<u8>)
         -> (u16, Vec<u8>, String) {
    let json = "application/json".to_string();
    let mut hub = shared.lock().unwrap();
    match (method, url) {
        ("GET", "/gatekey") => {
            (200, format!("{{\"pub\":\"{}\"}}", hex(&hub.gate_pub)).into_bytes(), json)
        }
        ("GET", "/heads") => {
            let l = hub.head.map(|h| format!("\"{}\"", hex(&h))).unwrap_or("null".into());
            let s = hub.head_state.map(|h| format!("\"{}\"", hex(&h))).unwrap_or("null".into());
            (200, format!("{{\"seq\":{},\"landing\":{l},\"state\":{s}}}", hub.seq).into_bytes(), json)
        }
        ("GET", "/log") => {
            (200, format!("{{\"log\":[{}],\"rejects\":[{}],\"queued\":{}}}",
                          hub.log.join(","), hub.rejects.join(","),
                          hub.queue.len()).into_bytes(), json)
        }
        ("GET", "/workspace") => {
            let Some(hs) = hub.head_state else {
                return (200, b"{\"seq\":-1,\"files\":{}}".to_vec(), json);
            };
            let target: Vec<Oid> = state_set(&hub.store, &hs).into_iter().collect();
            let mat = materialize(&hub.store, &target).expect("head materializes");
            let mut files = Vec::new();
            for (path, content) in &mat.tree {
                let fid = mat.file_map.iter()
                    .find(|(_, p)| p.as_deref() == Some(path.as_str()))
                    .map(|(f, _)| f).expect("fid for path");
                let lids: Vec<String> = mat.line_index[path].iter()
                    .map(|(o, n)| format!("[\"{}\",{}]", hex(o), n)).collect();
                files.push(format!(
                    "\"{}\":{{\"content\":\"{}\",\"digest\":\"{}\",\"fid\":[\"{}\",{}],\"line_ids\":[{}]}}",
                    jesc(path), jesc(&String::from_utf8_lossy(content)),
                    hex(&h(content)), hex(&fid.0), fid.1, lids.join(",")));
            }
            (200, format!("{{\"seq\":{},\"files\":{{{}}}}}", hub.seq,
                          files.join(",")).into_bytes(), json)
        }
        ("GET", _) if url.starts_with("/obj/") => {
            let Ok(oid_bytes) = (0..url.len() - 5).step_by(2)
                .map(|i| u8::from_str_radix(&url[5 + i..5 + i + 2], 16))
                .collect::<Result<Vec<u8>, _>>() else {
                return (400, b"{\"error\":\"bad hex\"}".to_vec(), json);
            };
            let Ok(oid): Result<Oid, _> = oid_bytes.try_into() else {
                return (400, b"{\"error\":\"bad oid length\"}".to_vec(), json);
            };
            if !hub.store.contains(&oid) {
                return (404, b"{\"error\":\"unknown oid\"}".to_vec(), json);
            }
            (200, hub.store.raw[&oid].clone(), "application/cbor".into())
        }
        ("POST", "/obj") => match hub.store.put(body) {
            Ok(oid) => {
                let env = hub.store.get(&oid);
                if env.get("type").and_then(V::text) == Some("genesis") {
                    if !matches!(env.get("repo"), Some(V::Null)) {
                        return (400, b"{\"error\":\"genesis must have repo null\"}".to_vec(), json);
                    }
                    let b = env.get("body").unwrap().clone();
                    let gates: Vec<Vec<u8>> = b.get("refs").and_then(|r| r.get("trunk"))
                        .and_then(|t| t.get("gates")).and_then(V::arr).unwrap_or(&[])
                        .iter().filter_map(|g| g.bytes().map(|x| x.to_vec())).collect();
                    if !gates.iter().any(|g| g[..] == hub.gate_pub[..]) {
                        return (400, b"{\"error\":\"this gate not in genesis\"}".to_vec(), json);
                    }
                    hub.authority = b.get("authority").and_then(V::arr).unwrap_or(&[])
                        .iter().filter_map(|k| k.bytes().map(|x| x.to_vec())).collect();
                    hub.policy = b.get("policy_init").cloned();
                    hub.repo = Some(oid);
                }
                (200, format!("{{\"oid\":\"{}\"}}", hex(&oid)).into_bytes(), json)
            }
            Err(e) => (400, format!("{{\"error\":\"{}\"}}", jesc(&e.to_string())).into_bytes(), json),
        },
        ("POST", "/propose") => match hub.store.put(body) {
            Ok(oid) => {
                if hub.store.get(&oid).get("type").and_then(V::text) != Some("proposal") {
                    return (400, b"{\"error\":\"not a proposal\"}".to_vec(), json);
                }
                hub.queue.push(oid);
                (200, format!("{{\"queued\":\"{}\"}}", hex(&oid)).into_bytes(), json)
            }
            Err(e) => (400, format!("{{\"error\":\"{}\"}}", jesc(&e.to_string())).into_bytes(), json),
        },
        _ => (404, b"{\"error\":\"no route\"}".to_vec(), json),
    }
}
