//! The thesis demo: 50 agents, 100 tasks, one repository, no branches, no
//! pull requests. Disjoint work commutes into batched certified landings;
//! stale reasoning, planted bugs, and revoked credentials are caught by the
//! gate — not by a human reading diffs.
//!
//! Run: cargo run --release -p weftd --example swarm

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value as J};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const PORT: u16 = 18750;
const AGENTS: usize = 50;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn http(method: &str, path: &str, body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", PORT)).expect("connect");
    s.write_all(format!(
        "{method} {path} HTTP/1.0\r\nHost: l\r\nContent-Length: {}\r\n\r\n",
        body.len()).as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let code = std::str::from_utf8(&resp[..split]).unwrap()
        .split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, String::from_utf8_lossy(&resp[split..]).into_owned())
}

fn get(path: &str) -> J {
    serde_json::from_str(&http("GET", path, b"").1).expect("json")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

/// /prepare → sign → /submit (the same flow browsers and MCP agents use).
fn publish(sk: &SigningKey, repo: Option<&str>, typ: &str, auth: Option<&str>,
           body: J) -> Result<String, String> {
    let mut env = json!({
        "repo": repo.map(|r| format!("hex:{r}")), "type": typ, "ts": now(),
        "author": format!("hex:{}", hex(&sk.verifying_key().to_bytes())),
        "auth": auth.map(|a| format!("hex:{a}")), "body": body});
    let (code, resp) = http("POST", "/prepare", env.to_string().as_bytes());
    if code != 200 {
        return Err(resp);
    }
    let p: J = serde_json::from_str(&resp).unwrap();
    let payload: Vec<u8> = {
        let s = p["payload"].as_str().unwrap();
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    env["sig"] = json!(format!("hex:{}", hex(&sk.sign(&payload).to_bytes())));
    let (code, resp) = http("POST", "/submit", env.to_string().as_bytes());
    if code != 200 {
        return Err(resp);
    }
    Ok(serde_json::from_str::<J>(&resp).unwrap()["oid"].as_str().unwrap().into())
}

struct Task {
    kind: &'static str,   // feature | append | stale | refactor | bug | revoked
    n: usize,
}

#[allow(clippy::too_many_arguments)]
fn run_task(t: &Task, repo: &str, orch_sk: &SigningKey, orch_cap: &str,
            auth_sk: &SigningKey, base_ws: &J, submitted: &AtomicUsize) {
    let (w_sk, w_pub) = weft_core::keygen();
    let cap = publish(orch_sk, Some(repo), "capability", None, json!({
        "audience": format!("hex:{}", hex(&w_pub)),
        "parent": format!("hex:{orch_cap}"),
        "scope": {"actions": ["publish_change", "propose"], "paths": ["**"]},
        "exp": now() + 600_000,
        "meta": {"reason": format!("swarm {} #{}", t.kind, t.n)}})).unwrap();
    if t.kind == "revoked" {
        publish(auth_sk, Some(repo), "revocation", None, json!({
            "target": format!("hex:{cap}"), "reason": "credential rotation"}))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    if t.kind == "stale" {
        // long reasoning on OLD observations: wait until mod1.txt has
        // actually been refactored underneath us, then submit anyway
        let old = base_ws["files"]["mod1.txt"]["digest"].as_str().unwrap();
        for _ in 0..120 {
            if get("/workspace")["files"]["mod1.txt"]["digest"].as_str()
                != Some(old) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    }
    let (ops, footprint, reads): (Vec<J>, Vec<String>, Vec<J>) = match t.kind {
        "feature" | "revoked" => {
            let path = format!("features/task{}.txt", t.n);
            (vec![json!(["mkfile", path]),
                  json!(["insert", [J::Null, 0], ["S"],
                         [format!("hex:{}", hex(format!("feature {} implemented", t.n).as_bytes())),
                          format!("hex:{}", hex(b"reviewed by: the gate"))]])],
             vec![path], vec![])
        }
        "append" => {
            let f = &base_ws["files"]["mod0.txt"];
            let fid = f["fid"].as_array().unwrap();
            let last = f["line_ids"].as_array().unwrap().last().unwrap()
                .as_array().unwrap();
            (vec![json!(["insert",
                         [format!("hex:{}", fid[0].as_str().unwrap()), fid[1]],
                         [format!("hex:{}", last[0].as_str().unwrap()), last[1]],
                         [format!("hex:{}", hex(format!("appended by agent {}", t.n).as_bytes()))]])],
             vec!["mod0.txt".into()], vec![])
        }
        "refactor" => {
            let f = &base_ws["files"]["mod1.txt"];
            let fid = f["fid"].as_array().unwrap();
            let first = f["line_ids"].as_array().unwrap()[0].as_array().unwrap();
            (vec![json!(["delete",
                         [format!("hex:{}", fid[0].as_str().unwrap()), fid[1]],
                         [[format!("hex:{}", first[0].as_str().unwrap()), first[1]]]]),
                  json!(["insert",
                         [format!("hex:{}", fid[0].as_str().unwrap()), fid[1]],
                         ["S"],
                         [format!("hex:{}", hex(b"refactored api surface"))]])],
             vec!["mod1.txt".into()], vec![])
        }
        "stale" => {
            let path = format!("features/stale{}.txt", t.n);
            let old_digest = base_ws["files"]["mod1.txt"]["digest"].as_str()
                .unwrap().to_string();
            (vec![json!(["mkfile", path]),
                  json!(["insert", [J::Null, 0], ["S"],
                         [format!("hex:{}", hex(b"built against mod1 assumptions"))]])],
             vec![path],
             vec![json!(["mod1.txt", format!("hex:{old_digest}")])])
        }
        "bug" => {
            let path = format!("features/task{}.txt", t.n);
            (vec![json!(["mkfile", path]),
                  json!(["insert", [J::Null, 0], ["S"],
                         [format!("hex:{}", hex(b"INJECTED_BUG deliberately broken"))]])],
             vec![path], vec![])
        }
        _ => unreachable!(),
    };
    let patch = publish(&w_sk, Some(repo), "patch",
        None, json!({"nonce": format!("hex:{:016x}", t.n), "ops": ops})).unwrap();
    let model = ["claude-fable-5", "gpt-5.6-sol", "qwen3.8-max"][t.n % 3];
    let change = publish(&w_sk, Some(repo), "change", Some(&cap), json!({
        "patch": format!("hex:{patch}"), "footprint": footprint, "reads": reads,
        "message": format!("{} #{}", t.kind, t.n),
        "provenance": {"model": model}})).unwrap();
    let _ = publish(&w_sk, Some(repo), "proposal", Some(&cap), json!({
        "ref": "trunk", "delta": [format!("hex:{change}")], "status": "open"}));
    submitted.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    let hub = weftd::new_hub();
    let gate_pub = hex(&hub.lock().unwrap().gate_pub);
    {
        let hub = hub.clone();
        std::thread::spawn(move || weftd::serve(PORT, hub));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    let py = if cfg!(windows) { "python" } else { "python3" };
    let check = "import glob,sys;bad=[f for f in glob.glob('**/*.txt',recursive=True) \
                 if 'INJECTED_BUG' in open(f,encoding='utf-8',errors='ignore').read()];\
                 sys.exit(1 if bad else 0)";
    let (auth_sk, auth_pub) = weft_core::keygen();
    let repo = publish(&auth_sk, None, "genesis", None, json!({
        "name": "swarm-demo", "authority": [format!("hex:{}", hex(&auth_pub))],
        "quorum": 1,
        "refs": {"trunk": {"gates": [format!("hex:{gate_pub}")], "threshold": 1}},
        "policy_init": {"rules": [], "approvals": 0, "stale_reads": "reject",
                         "recipes": [{"kind": "test", "image": "local",
                                      "cmd": [py, "-c", check]}]},
        "config_init": {}})).unwrap();
    let auth_cap = publish(&auth_sk, Some(&repo), "capability", None, json!({
        "audience": format!("hex:{}", hex(&auth_pub)), "parent": null,
        "scope": {"actions": ["publish_change", "propose", "delegate"], "paths": ["**"]},
        "exp": now() + 600_000})).unwrap();
    let (orch_sk, orch_pub) = weft_core::keygen();
    let orch_cap = publish(&auth_sk, Some(&repo), "capability", None, json!({
        "audience": format!("hex:{}", hex(&orch_pub)), "parent": null,
        "scope": {"actions": ["publish_change", "propose", "delegate"], "paths": ["**"]},
        "exp": now() + 600_000})).unwrap();

    // base: 10 modules, 12 lines each, one SELF-sentinel patch
    let mut ops = vec![];
    for f in 0..10 {
        ops.push(json!(["mkfile", format!("mod{f}.txt")]));
    }
    for f in 0..10 {
        let lines: Vec<String> = (0..12)
            .map(|j| format!("hex:{}", hex(format!("mod{f} line{j}").as_bytes())))
            .collect();
        ops.push(json!(["insert", [J::Null, f], ["S"], lines]));
    }
    let bp = publish(&auth_sk, Some(&repo), "patch", None,
        json!({"nonce": "hex:0000000000000bad", "ops": ops})).unwrap();
    let bc = publish(&auth_sk, Some(&repo), "change", Some(&auth_cap), json!({
        "patch": format!("hex:{bp}"),
        "footprint": (0..10).map(|f| format!("mod{f}.txt")).collect::<Vec<_>>(),
        "reads": [], "message": "scaffold 10 modules"})).unwrap();
    publish(&auth_sk, Some(&repo), "proposal", Some(&auth_cap), json!({
        "ref": "trunk", "delta": [format!("hex:{bc}")], "status": "open"})).unwrap();
    while get("/heads")["seq"].as_i64() != Some(0) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let base_ws = get("/workspace");

    // ---- the workload: 100 tasks --------------------------------------------
    let mut tasks: Vec<Task> = Vec::new();
    for n in 0..70 {
        tasks.push(Task { kind: "feature", n });
    }
    for n in 70..80 {
        tasks.push(Task { kind: "append", n });
    }
    for n in 81..89 {
        tasks.push(Task { kind: "stale", n });
    }
    for n in 89..97 {
        tasks.push(Task { kind: "bug", n });
    }
    for n in 97..100 {
        tasks.push(Task { kind: "revoked", n });
    }
    // workers pop from the END: the refactor must run FIRST so the stale
    // readers' observations genuinely go stale underneath them
    tasks.push(Task { kind: "refactor", n: 80 });
    let total = tasks.len();
    println!("weft swarm demo — {AGENTS} agents · {total} tasks · 1 repository · no branches · no PRs\n");

    let t0 = Instant::now();
    let queue = Arc::new(Mutex::new(tasks));
    let submitted = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];
    for _ in 0..AGENTS {
        let queue = queue.clone();
        let submitted = submitted.clone();
        let (repo, orch_cap, auth_cap_) = (repo.clone(), orch_cap.clone(), auth_cap.clone());
        let _ = auth_cap_;
        let orch_sk = orch_sk.clone();
        let auth_sk = auth_sk.clone();
        let base_ws = base_ws.clone();
        handles.push(std::thread::spawn(move || loop {
            let task = queue.lock().unwrap().pop();
            let Some(task) = task else { break };
            run_task(&task, &repo, &orch_sk, &orch_cap, &auth_sk, &base_ws,
                     &submitted);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    // drain: wait until the gate queue is empty and stays empty
    let mut idle = 0;
    while idle < 8 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let l = get("/log");
        idle = if l["queued"].as_i64() == Some(0) { idle + 1 } else { 0 };
    }
    let dt = t0.elapsed().as_secs_f64();

    // ---- scoreboard ---------------------------------------------------------
    let log = get("/log");
    let landings = log["log"].as_array().unwrap();
    let landed: usize = landings.iter()
        .map(|e| e["changes"].as_array().unwrap().len()).sum();
    let markers: i64 = landings.last()
        .and_then(|e| e["markers"].as_i64()).unwrap_or(0);
    let biggest = landings.iter()
        .map(|e| e["changes"].as_array().unwrap().len()).max().unwrap_or(0);
    let rejects = log["rejects"].as_array().unwrap();
    let count = |needle: &str| rejects.iter()
        .filter(|r| r.to_string().contains(needle)).count();
    let stale = count("stale read");
    let bisections = count("bisecting");
    let bugs = count("evidence failed") - bisections;
    let revoked = count("revoked");

    if std::env::var("SWARM_DEBUG").is_ok() {
        let refac_landed = landings.iter().any(|e| e["changes"].as_array().unwrap()
            .iter().any(|c| c["message"].as_str().unwrap_or("").starts_with("refactor")));
        eprintln!("DBG refactor landed: {refac_landed}");
        eprintln!("DBG mod1.txt now: {:?}",
                  get("/workspace")["files"]["mod1.txt"]["content"]);
        eprintln!("DBG rejects: {}", log["rejects"]);
    }
    println!("  ✓ {landed} changes landed across {} certified landings ({dt:.1}s wall)",
             landings.len());
    println!("  ✓ largest batch: {biggest} independent changes in ONE landing (commutation)");
    println!("  ✓ {markers} same-anchor races converged deterministically (order markers)");
    println!("  ✗ {stale} stale-read changes rejected — reasoning was invalidated by concurrent work");
    println!("  ✗ {bugs} planted bugs rejected by evidence ({bisections} batch bisections isolated them)");
    println!("  ✗ {revoked} revoked-credential attempts refused at certification");
    println!("\n  every landed line answers: which model, under whose authority, based on");
    println!("  what observations, proven by which evidence — try /provenance on any change");
    println!("\n  the same workload on git: 100 branches, 100 PRs, and a human week.");
    let ok = landed + stale + bugs + revoked >= total;
    std::process::exit(if ok { 0 } else { 1 });
}
