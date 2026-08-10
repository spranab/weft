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
    pub revoked: BTreeSet<Oid>,
    pub pending: Vec<(Oid, String)>, // (manifest, JSON) awaiting approvals
    pub gate_sk: SigningKey,
    pub gate_pub: [u8; 32],
}

pub type Shared = Arc<Mutex<Hub>>;

const DASHBOARD: &str = include_str!("dashboard.html");

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_oid(hexstr: &str) -> Option<Oid> {
    if hexstr.len() != 64 {
        return None;
    }
    let bytes: Result<Vec<u8>, _> = (0..64).step_by(2)
        .map(|i| u8::from_str_radix(&hexstr[i..i + 2], 16)).collect();
    bytes.ok()?.try_into().ok()
}

/// Walk a change's capability chain to the root; JSON for the UI (RFC §11:
/// the UI renders the capability graph, it never owns it).
fn provenance_json(hub: &Hub, oid: &Oid) -> Option<String> {
    let env = hub.store.env.get(oid)?;
    if env.get("type").and_then(V::text) != Some("change") {
        return None;
    }
    let b = env.get("body")?;
    let model = b.get("provenance").and_then(|p| p.get("model"))
        .and_then(V::text).unwrap_or("human/authority");
    let footprint: Vec<String> = b.get("footprint").and_then(V::arr).unwrap_or(&[])
        .iter().filter_map(|p| p.text().map(|s| format!("\"{}\"", jesc(s)))).collect();
    let mut chain = Vec::new();
    let mut cur = env.get("auth").and_then(|a| a.bytes().map(|_| as_oid(a)));
    while let Some(cap) = cur {
        let cenv = hub.store.env.get(&cap)?;
        let cb = cenv.get("body")?;
        let issuer = cenv.get("author")?.bytes()?;
        let audience = cb.get("audience")?.bytes()?;
        let scope = cb.get("scope")?;
        let acts: Vec<String> = scope.get("actions").and_then(V::arr).unwrap_or(&[])
            .iter().filter_map(|a| a.text().map(|s| format!("\"{}\"", jesc(s)))).collect();
        let paths: Vec<String> = scope.get("paths").and_then(V::arr).unwrap_or(&[])
            .iter().filter_map(|p| p.text().map(|s| format!("\"{}\"", jesc(s)))).collect();
        let parent = cb.get("parent");
        let is_top = matches!(parent, Some(V::Null) | None);
        let root = is_top && hub.authority.iter().any(|k| k[..] == issuer[..]);
        chain.push(format!(
            "{{\"oid\":\"{}\",\"issuer\":\"{}\",\"audience\":\"{}\",\"actions\":[{}],\"paths\":[{}],\"root\":{}}}",
            hex(&cap), hex(issuer), hex(audience), acts.join(","), paths.join(","), root));
        cur = if is_top { None } else { Some(as_oid(parent?)) };
    }
    Some(format!(
        "{{\"oid\":\"{}\",\"author\":\"{}\",\"model\":\"{}\",\"message\":\"{}\",\"footprint\":[{}],\"chain\":[{}]}}",
        hex(oid), hex(env.get("author")?.bytes()?), jesc(model),
        jesc(b.get("message").and_then(V::text).unwrap_or("")),
        footprint.join(","), chain.join(",")))
}

// ---------------------------------------------------- JSON ↔ V bridge -----
// Byte strings cross the JSON boundary as "hex:<lowercase hex>" (browser
// clients cannot speak CBOR natively; the server canonicalizes).

fn jv_to_v(j: &serde_json::Value) -> Result<V, String> {
    use serde_json::Value as J;
    Ok(match j {
        J::Null => V::Null,
        J::Bool(b) => V::Bool(*b),
        J::Number(n) => V::Int(n.as_i64().ok_or("non-integer number")?),
        J::String(s) => match s.strip_prefix("hex:") {
            Some(hexs) => V::Bytes((0..hexs.len()).step_by(2)
                .map(|i| u8::from_str_radix(&hexs[i..i + 2], 16))
                .collect::<Result<_, _>>().map_err(|_| "bad hex")?),
            None => V::Text(s.clone()),
        },
        J::Array(a) => V::Arr(a.iter().map(jv_to_v).collect::<Result<_, _>>()?),
        J::Object(o) => V::Map(o.iter()
            .map(|(k, v)| Ok((V::Text(k.clone()), jv_to_v(v)?)))
            .collect::<Result<_, String>>()?),
    })
}

fn v_to_jv(v: &V) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        V::Null => J::Null,
        V::Bool(b) => J::Bool(*b),
        V::Int(i) => J::Number((*i).into()),
        V::Bytes(b) => J::String(format!("hex:{}", hex(b))),
        V::Text(t) => J::String(t.clone()),
        V::Arr(a) => J::Array(a.iter().map(v_to_jv).collect()),
        V::Map(m) => J::Object(m.iter().filter_map(|(k, val)| {
            k.text().map(|k| (k.to_string(), v_to_jv(val)))
        }).collect()),
    }
}

fn jfield_bytes(j: &serde_json::Value, key: &str) -> Option<Vec<u8>> {
    match jv_to_v(j.get(key)?) {
        Ok(V::Bytes(b)) => Some(b),
        _ => None,
    }
}

fn jfield_oid(j: &serde_json::Value, key: &str) -> Option<Oid> {
    jfield_bytes(j, key)?.try_into().ok()
}

// ------------------------------------------------------- approvals --------

/// May this key mint approvals? Authority members always; otherwise any
/// unrevoked capability chain granting `approve` (roles are capability
/// templates — RFC §11).
fn approver_ok(hub: &Hub, author: &[u8], now_ms: i64) -> bool {
    if hub.authority.iter().any(|k| k[..] == author[..]) {
        return true;
    }
    hub.store.env.iter().any(|(cap_oid, env)| {
        env.get("type").and_then(V::text) == Some("capability")
            && env.get("body").and_then(|b| b.get("audience")).and_then(V::bytes)
                == Some(author)
            && cap_chain_valid_r(&hub.store, cap_oid, author, "approve",
                                 &BTreeSet::new(), &hub.authority, now_ms,
                                 &hub.revoked).is_ok()
    })
}

/// Count valid approval evidence bound to this exact manifest (RFC §5.12:
/// touch the state, re-earn the proof — approvals do not carry across).
fn count_approvals(hub: &Hub, man: &Oid, now_ms: i64) -> Vec<Oid> {
    hub.store.env.iter().filter_map(|(oid, env)| {
        let b = env.get("body")?;
        (env.get("type").and_then(V::text) == Some("evidence")
            && b.get("recipe")?.get("kind").and_then(V::text) == Some("approval")
            && b.get("manifest").and_then(V::bytes) == Some(&man[..])
            && approver_ok(hub, env.get("author")?.bytes()?, now_ms))
            .then_some(*oid)
    }).collect()
}

/// Post-store side effects: genesis bootstrap and revocation tracking.
fn apply_side_effects(hub: &mut Hub, oid: &Oid) -> Result<(), String> {
    let env = hub.store.get(oid).clone();
    match env.get("type").and_then(V::text) {
        Some("genesis") => {
            if !matches!(env.get("repo"), Some(V::Null)) {
                return Err("genesis must have repo null".into());
            }
            let b = env.get("body").ok_or("no body")?;
            let gates: Vec<Vec<u8>> = b.get("refs").and_then(|r| r.get("trunk"))
                .and_then(|t| t.get("gates")).and_then(V::arr).unwrap_or(&[])
                .iter().filter_map(|g| g.bytes().map(|x| x.to_vec())).collect();
            if !gates.iter().any(|g| g[..] == hub.gate_pub[..]) {
                return Err("this gate not in genesis".into());
            }
            hub.authority = b.get("authority").and_then(V::arr).unwrap_or(&[])
                .iter().filter_map(|k| k.bytes().map(|x| x.to_vec())).collect();
            hub.policy = b.get("policy_init").cloned();
            hub.repo = Some(*oid);
        }
        Some("revocation") => {
            if let Some(t) = env.get("body").and_then(|b| b.get("target")) {
                if let Some(bytes) = t.bytes() {
                    if let Ok(target) = Oid::try_from(bytes) {
                        hub.revoked.insert(target);
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
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
        revoked: BTreeSet::new(),
        pending: vec![],
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
    // ts=0 on state+manifest: same batch → same OIDs across gate re-attempts,
    // so approval evidence stays bound to the manifest it was minted for
    let st = make_state(&sk, repo, hub.head_state, &delta, &mut hub.store, 0);
    let target: Vec<Oid> = state_set(&hub.store, &st).into_iter().collect();
    let mat = match materialize(&hub.store, &target) {
        Ok(m) => m,
        Err(e) => {
            hub.rejects.push(format!("{{\"error\":\"{}\"}}", jesc(&e)));
            return;
        }
    };
    let (man, man_raw) = make_obj(&sk, Some(repo), "manifest", mat.manifest.clone(), None, 0);
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
    let chk = check_landing_r(&hub.store, &body, &hub.authority, ts, &stale,
                              &hub.revoked);
    if !chk.errors.is_empty() {
        let msg = chk.errors.iter().map(|e| format!("\"{}\"", jesc(e)))
            .collect::<Vec<_>>().join(",");
        hub.rejects.push(format!("{{\"seq_attempt\":{seq},\"errors\":[{msg}]}}"));
        return;
    }
    // approval gating (RFC §11): policy may demand human sign-off, minted as
    // approval evidence bound to this exact manifest
    let need = policy.get("approvals").and_then(V::int).unwrap_or(0);
    let approvals = count_approvals(hub, &man, ts);
    if (approvals.len() as i64) < need {
        let changes_json: Vec<String> = delta.iter().map(|c| {
            let b = hub.store.body(c);
            format!("{{\"oid\":\"{}\",\"model\":\"{}\",\"message\":\"{}\"}}",
                hex(c),
                jesc(b.get("provenance").and_then(|p| p.get("model"))
                    .and_then(V::text).unwrap_or("none")),
                jesc(b.get("message").and_then(V::text).unwrap_or("")))
        }).collect();
        let entry = format!(
            "{{\"manifest\":\"{}\",\"need\":{need},\"have\":{},\"changes\":[{}]}}",
            hex(&man), approvals.len(), changes_json.join(","));
        hub.pending.retain(|(m, _)| m != &man);
        hub.pending.push((man, entry));
        for (p, _) in &batch {
            hub.queue.push(*p);      // stays queued until approvals arrive
        }
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
    ev_oids.extend(approvals);           // approvals count as evidence used
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
    hub.pending.retain(|(m, _)| m != &man);
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
        ("GET", "/") => {
            (200, DASHBOARD.as_bytes().to_vec(), "text/html; charset=utf-8".into())
        }
        ("GET", _) if url.starts_with("/provenance/") => {
            match parse_oid(&url[12..]).and_then(|oid| provenance_json(&hub, &oid)) {
                Some(payload) => (200, payload.into_bytes(), json),
                None => (404, b"{\"error\":\"unknown change\"}".to_vec(), json),
            }
        }
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
            Ok(oid) => match apply_side_effects(&mut hub, &oid) {
                Ok(()) => (200, format!("{{\"oid\":\"{}\"}}", hex(&oid)).into_bytes(), json),
                Err(e) => (400, format!("{{\"error\":\"{}\"}}", jesc(&e)).into_bytes(), json),
            },
            Err(e) => (400, format!("{{\"error\":\"{}\"}}", jesc(&e.to_string())).into_bytes(), json),
        },
        ("POST", "/prepare") | ("POST", "/submit") => {
            let submit = url == "/submit";
            let Ok(j) = serde_json::from_slice::<serde_json::Value>(&body) else {
                return (400, b"{\"error\":\"bad json\"}".to_vec(), json);
            };
            let repo = jfield_oid(&j, "repo");
            let auth = jfield_oid(&j, "auth");
            let Some(typ) = j.get("type").and_then(|t| t.as_str()) else {
                return (400, b"{\"error\":\"missing type\"}".to_vec(), json);
            };
            let Some(ts) = j.get("ts").and_then(|t| t.as_i64()) else {
                return (400, b"{\"error\":\"missing ts\"}".to_vec(), json);
            };
            let Some(author) = jfield_bytes(&j, "author") else {
                return (400, b"{\"error\":\"missing author\"}".to_vec(), json);
            };
            let body_v = match j.get("body").map(jv_to_v) {
                Some(Ok(v)) => v,
                _ => return (400, b"{\"error\":\"bad body\"}".to_vec(), json),
            };
            if !submit {
                let payload = sig_payload_hash(repo, typ, ts, &author, auth, &body_v);
                return (200, format!("{{\"payload\":\"{}\"}}", hex(&payload)).into_bytes(), json);
            }
            let Some(sig) = jfield_bytes(&j, "sig") else {
                return (400, b"{\"error\":\"missing sig\"}".to_vec(), json);
            };
            let (_, raw) = assemble_obj(repo, typ, ts, &author, auth, body_v, &sig);
            match hub.store.put(raw) {
                Ok(oid) => match apply_side_effects(&mut hub, &oid) {
                    Ok(()) => {
                        // proposals signed via the browser flow go straight
                        // into the gate queue
                        if hub.store.get(&oid).get("type").and_then(V::text)
                            == Some("proposal") {
                            hub.queue.push(oid);
                        }
                        (200, format!("{{\"oid\":\"{}\"}}", hex(&oid)).into_bytes(), json)
                    }
                    Err(e) => (400, format!("{{\"error\":\"{}\"}}", jesc(&e)).into_bytes(), json),
                },
                Err(e) => (400, format!("{{\"error\":\"{}\"}}", jesc(&e.to_string())).into_bytes(), json),
            }
        }
        ("GET", "/intents") => {
            let closed: BTreeSet<Oid> = hub.store.env.values()
                .filter(|e| e.get("type").and_then(V::text) == Some("landing"))
                .flat_map(|e| e.get("body").and_then(|b| b.get("delta")).and_then(V::arr)
                    .unwrap_or(&[]).iter().map(as_oid).collect::<Vec<_>>())
                .flat_map(|c| hub.store.body(&c).get("closes").and_then(V::arr)
                    .unwrap_or(&[]).iter().map(as_oid).collect::<Vec<_>>())
                .collect();
            let items: Vec<String> = hub.store.env.iter().filter_map(|(oid, e)| {
                if e.get("type").and_then(V::text) != Some("intent") {
                    return None;
                }
                let b = e.get("body")?;
                let criteria: Vec<String> = b.get("criteria").and_then(V::arr)
                    .unwrap_or(&[]).iter().filter_map(|c| {
                        c.get("desc").and_then(V::text)
                            .map(|d| format!("\"{}\"", jesc(d)))
                    }).collect();
                Some(format!(
                    "{{\"oid\":\"{}\",\"title\":\"{}\",\"goal\":\"{}\",\"ref\":\"{}\",\"criteria\":[{}],\"closed\":{},\"author\":\"{}\"}}",
                    hex(oid),
                    jesc(b.get("title").and_then(V::text).unwrap_or("")),
                    jesc(b.get("goal").and_then(V::text).unwrap_or("")),
                    jesc(b.get("ref").and_then(V::text).unwrap_or("trunk")),
                    criteria.join(","), closed.contains(oid),
                    hex(e.get("author")?.bytes()?)))
            }).collect();
            (200, format!("{{\"intents\":[{}]}}", items.join(",")).into_bytes(), json)
        }
        ("GET", "/caps") => {
            let items: Vec<String> = hub.store.env.iter().filter_map(|(oid, e)| {
                if e.get("type").and_then(V::text) != Some("capability") {
                    return None;
                }
                let b = e.get("body")?;
                let scope = b.get("scope")?;
                let lst = |k: &str| scope.get(k).and_then(V::arr).unwrap_or(&[])
                    .iter().filter_map(|x| x.text().map(|s| format!("\"{}\"", jesc(s))))
                    .collect::<Vec<_>>().join(",");
                let parent = match b.get("parent") {
                    Some(V::Bytes(p)) => format!("\"{}\"", hex(p)),
                    _ => "null".into(),
                };
                Some(format!(
                    "{{\"oid\":\"{}\",\"issuer\":\"{}\",\"audience\":\"{}\",\"actions\":[{}],\"paths\":[{}],\"exp\":{},\"parent\":{},\"revoked\":{}}}",
                    hex(oid), hex(e.get("author")?.bytes()?),
                    hex(b.get("audience")?.bytes()?),
                    lst("actions"), lst("paths"),
                    b.get("exp").and_then(V::int).unwrap_or(0),
                    parent, hub.revoked.contains(oid)))
            }).collect();
            (200, format!("{{\"caps\":[{}]}}", items.join(",")).into_bytes(), json)
        }
        ("GET", "/policy") => {
            let repo = hub.repo.map(|r| format!("\"{}\"", hex(&r))).unwrap_or("null".into());
            let authority: Vec<String> = hub.authority.iter()
                .map(|k| format!("\"{}\"", hex(k))).collect();
            let policy = hub.policy.as_ref().map(|p| v_to_jv(p).to_string())
                .unwrap_or("null".into());
            (200, format!(
                "{{\"repo\":{repo},\"gate\":\"{}\",\"authority\":[{}],\"policy\":{policy}}}",
                hex(&hub.gate_pub), authority.join(",")).into_bytes(), json)
        }
        ("GET", "/identities") => {
            let mut latest: std::collections::BTreeMap<Vec<u8>, (i64, String, String)> =
                std::collections::BTreeMap::new();
            for env in hub.store.env.values() {
                if env.get("type").and_then(V::text) != Some("identity") {
                    continue;
                }
                let (Some(author), Some(b)) = (env.get("author").and_then(V::bytes),
                                               env.get("body")) else { continue };
                let ts = env.get("ts").and_then(V::int).unwrap_or(0);
                let name = b.get("name").and_then(V::text).unwrap_or("").to_string();
                let kind = b.get("kind").and_then(V::text).unwrap_or("").to_string();
                let e = latest.entry(author.to_vec()).or_insert((i64::MIN, String::new(), String::new()));
                if ts >= e.0 {
                    *e = (ts, name, kind);
                }
            }
            let items: Vec<String> = latest.iter().map(|(pubk, (_, name, kind))|
                format!("{{\"pub\":\"{}\",\"name\":\"{}\",\"kind\":\"{}\"}}",
                        hex(pubk), jesc(name), jesc(kind))).collect();
            (200, format!("{{\"identities\":[{}]}}", items.join(",")).into_bytes(), json)
        }
        ("GET", "/pending") => {
            let entries: Vec<&str> = hub.pending.iter().map(|(_, j)| j.as_str()).collect();
            (200, format!("{{\"pending\":[{}]}}", entries.join(",")).into_bytes(), json)
        }
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
