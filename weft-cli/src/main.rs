//! weft — the human porcelain and git bridge (RFC-0001 §10).
//!
//!   weft init   [--git <dir>]          bootstrap a repo on the hub (this key
//!                                      becomes the authority); optionally
//!                                      import the git HEAD tree
//!   weft clone  <url> [dir]            git clone + init --git
//!   weft status                        heads, queue, pending approvals
//!   weft export --git <dir> [--branch weft-export]
//!                                      write landed history as conventional
//!                                      git commits with provenance trailers
//!
//! Ownership rule (RFC §10): while Weft owns the work, the export branch is a
//! read-only mirror — deterministic, so independent exporters agree.
//! Flags: --hub http://127.0.0.1:8747   --key .weft-cli.key
//! v1 limits: text files only (binaries skipped with a warning); files are
//! normalized to a trailing newline; export rebuilds the branch from the
//! import base each run (idempotent, deterministic).

use ed25519_dalek::SigningKey;
use serde_json::Value as J;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use weft_core::cbor::V;
use weft_core::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

struct Cli {
    host: String,
    port: u16,
    sk: SigningKey,
    repo: Option<Oid>,
}

impl Cli {
    fn http(&self, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let mut s = TcpStream::connect((self.host.as_str(), self.port))
            .unwrap_or_else(|e| die(&format!(
                "hub unreachable at {}:{} ({e}) — start it: cargo run --release -p weftd",
                self.host, self.port)));
        s.write_all(format!("{method} {path} HTTP/1.0\r\nHost: l\r\nContent-Length: {}\r\n\r\n",
                            body.len()).as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).unwrap();
        let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let code = std::str::from_utf8(&resp[..split]).unwrap()
            .split_whitespace().nth(1).unwrap().parse().unwrap();
        (code, resp[split..].to_vec())
    }
    fn get(&self, path: &str) -> J {
        let (code, body) = self.http("GET", path, b"");
        if code != 200 {
            die(&format!("GET {path} → {code}"));
        }
        serde_json::from_slice(&body).unwrap()
    }
    fn publish(&self, typ: &str, body: V, auth: Option<Oid>) -> Oid {
        let (oid, raw) = make_obj(&self.sk, self.repo, typ, body, auth, now());
        let (code, resp) = self.http("POST", "/obj", &raw);
        if code != 200 {
            die(&format!("publish {typ}: {}", String::from_utf8_lossy(&resp)));
        }
        oid
    }
    fn propose(&self, delta: &[Oid], auth: Oid) -> Oid {
        let (oid, raw) = make_obj(&self.sk, self.repo, "proposal", V::map(vec![
            ("ref", V::Text("trunk".into())),
            ("delta", V::Arr(delta.iter().map(|c| V::Bytes(c.to_vec())).collect())),
            ("status", V::Text("open".into()))]), Some(auth), now());
        let (code, resp) = self.http("POST", "/propose", &raw);
        if code != 200 {
            die(&format!("propose: {}", String::from_utf8_lossy(&resp)));
        }
        oid
    }
    /// Light-client closure fetch into a local store.
    fn fetch(&self, store: &mut Store, oid: &Oid) {
        if store.contains(oid) {
            return;
        }
        let (code, raw) = self.http("GET", &format!("/obj/{}", hex(oid)), b"");
        if code != 200 {
            die(&format!("object {} missing on hub", hex(oid)));
        }
        store.put(raw).unwrap_or_else(|e| die(&format!("bad object from hub: {e}")));
    }
}

fn die(msg: &str) -> ! {
    eprintln!("weft: {msg}");
    std::process::exit(1)
}

fn git(dir: &str, args: &[&str]) -> String {
    let out = Command::new("git").arg("-C").arg(dir)
        .args(["-c", "core.autocrlf=false"]).args(args)
        .output().unwrap_or_else(|e| die(&format!("git: {e}")));
    if !out.status.success() {
        die(&format!("git {} failed: {}", args.join(" "),
                     String::from_utf8_lossy(&out.stderr)));
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn load_key(path: &str) -> SigningKey {
    if let Ok(seed_hex) = std::fs::read_to_string(path) {
        let seed: Vec<u8> = (0..seed_hex.trim().len()).step_by(2)
            .filter_map(|i| u8::from_str_radix(&seed_hex.trim()[i..i + 2], 16).ok())
            .collect();
        if let Ok(seed) = <[u8; 32]>::try_from(seed.as_slice()) {
            return SigningKey::from_bytes(&seed);
        }
    }
    let (sk, _) = keygen();
    std::fs::write(path, hex(&sk.to_bytes())).unwrap_or_else(|e| die(&e.to_string()));
    eprintln!("weft: new key written to {path}");
    sk
}

// ------------------------------------------------------------- import ------

fn import_git(cli: &Cli, dir: &str, cap: Oid) {
    let sha = git(dir, &["rev-parse", "HEAD"]);
    let mut ops: Vec<V> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut ord: i64 = 0;
    let mut fids: Vec<(String, i64)> = Vec::new();
    for path in git(dir, &["ls-files"]).lines() {
        let full = std::path::Path::new(dir).join(path);
        let Ok(bytes) = std::fs::read(&full) else { continue };
        if bytes.contains(&0) || String::from_utf8(bytes.clone()).is_err() {
            eprintln!("weft: skipping binary file {path} (v1 imports text only)");
            continue;
        }
        ops.push(V::Arr(vec![V::Text("mkfile".into()), V::Text(path.replace('\\', "/"))]));
        fids.push((path.to_string(), ord));
        paths.push(path.replace('\\', "/"));
        ord += 1;
    }
    for (path, fid_ord) in &fids {
        let full = std::path::Path::new(dir).join(path);
        let text = std::fs::read_to_string(&full).unwrap();
        let lines: Vec<V> = text.lines()
            .map(|l| V::Bytes(l.as_bytes().to_vec())).collect();
        if lines.is_empty() {
            continue;
        }
        ops.push(V::Arr(vec![V::Text("insert".into()),
            V::Arr(vec![V::Null, V::Int(*fid_ord)]),
            V::Arr(vec![V::Text("S".into())]), V::Arr(lines)]));
    }
    let patch = cli.publish("patch", V::map(vec![
        ("nonce", V::Bytes(sha.as_bytes()[..8.min(sha.len())].to_vec())),
        ("ops", V::Arr(ops))]), None);
    let change = cli.publish("change", V::map(vec![
        ("patch", V::Bytes(patch.to_vec())),
        ("footprint", V::Arr(paths.iter().map(|p| V::Text(p.clone())).collect())),
        ("reads", V::Arr(vec![])),
        ("message", V::Text(format!("git-import {sha}"))),
        ("provenance", V::map(vec![("model", V::Null)]))]), Some(cap));
    cli.propose(&[change], cap);
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(150));
        if cli.get("/log").to_string().contains(&hex(&change)) {
            break;
        }
    }
    cli.publish("note", V::map(vec![
        ("kind", V::Text("context".into())),
        ("text", V::Text(format!("git-import {sha}"))),
        ("anchors", V::Arr(vec![]))]), None);
    println!("imported {} files from git HEAD {sha}", fids.len());
}

// ------------------------------------------------------------- export ------

fn export_git(cli: &Cli, dir: &str, branch: &str) {
    let notes = cli.get("/notes");
    let base_sha = notes["notes"].as_array().and_then(|ns| ns.iter()
        .filter_map(|n| n["text"].as_str())
        .find_map(|t| t.strip_prefix("git-import ").map(String::from)));
    let log = cli.get("/log");
    let landings = log["log"].as_array().cloned().unwrap_or_default();
    if landings.is_empty() {
        die("nothing landed yet");
    }
    // light-client: pull the full closure and verify the head manifest
    let mut store = Store::default();
    let head_hex = landings.last().unwrap()["landing"].as_str().unwrap();
    let head: Oid = {
        let b: Vec<u8> = (0..64).step_by(2)
            .map(|i| u8::from_str_radix(&head_hex[i..i + 2], 16).unwrap()).collect();
        b.try_into().unwrap()
    };
    cli.fetch(&mut store, &head);
    let mut landing_ts: std::collections::BTreeMap<String, i64> = Default::default();
    for e in &landings {
        let lhex = e["landing"].as_str().unwrap();
        let l: Oid = {
            let b: Vec<u8> = (0..64).step_by(2)
                .map(|i| u8::from_str_radix(&lhex[i..i + 2], 16).unwrap()).collect();
            b.try_into().unwrap()
        };
        cli.fetch(&mut store, &l);
        landing_ts.insert(lhex.into(), store.get(&l).get("ts").and_then(V::int).unwrap_or(0));
    }
    let st = as_oid(store.get(&head).get("body").unwrap().get("target_state").unwrap());
    let mut todo = vec![st];
    while let Some(s) = todo.pop() {
        cli.fetch(&mut store, &s);
        let body = store.body(&s).clone();
        for c in body.get("add").and_then(V::arr).unwrap_or(&[]) {
            let c = as_oid(c);
            cli.fetch(&mut store, &c);
            let p = as_oid(store.body(&c).get("patch").unwrap());
            cli.fetch(&mut store, &p);
        }
        if let Some(b) = body.get("base") {
            if !matches!(b, V::Null) {
                todo.push(as_oid(b));
            }
        }
    }

    // rebuild the export branch from the import base (idempotent)
    let original = git(dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    match &base_sha {
        Some(sha) => {
            git(dir, &["checkout", "-q", "-B", branch, sha]);
        }
        None => {
            git(dir, &["checkout", "-q", "--orphan", branch]);
            let _ = Command::new("git").args(["-C", dir, "rm", "-rfq", "--cached", "."]).output();
        }
    }

    let mut landed: Vec<Oid> = Vec::new();
    let mut exported = 0usize;
    for e in &landings {
        let lhex = e["landing"].as_str().unwrap();
        let seq = e["seq"].as_i64().unwrap_or(0);
        let ts = landing_ts.get(lhex).copied().unwrap_or(0) / 1000;
        for ch in e["changes"].as_array().unwrap() {
            let chex = ch["oid"].as_str().unwrap();
            let c: Oid = {
                let b: Vec<u8> = (0..64).step_by(2)
                    .map(|i| u8::from_str_radix(&chex[i..i + 2], 16).unwrap()).collect();
                b.try_into().unwrap()
            };
            landed.push(c);
            let env = store.get(&c);
            let body = env.get("body").unwrap();
            let msg = body.get("message").and_then(V::text).unwrap_or("weft change");
            if msg.starts_with("git-import ") {
                continue; // the base commit already IS this content
            }
            let mat = materialize(&store, &landed)
                .unwrap_or_else(|e| die(&format!("materialize: {e}")));
            // sync worktree to the materialized tree
            let _ = Command::new("git").args(["-C", dir, "rm", "-rq", "--cached", "."]).output();
            for f in git(dir, &["ls-files", "--others", "--cached"]).lines() {
                let _ = std::fs::remove_file(std::path::Path::new(dir).join(f));
            }
            for (path, content) in &mat.tree {
                let full = std::path::Path::new(dir).join(path);
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(full, content).unwrap();
            }
            git(dir, &["add", "-A"]);
            let model = body.get("provenance").and_then(|p| p.get("model"))
                .and_then(V::text).unwrap_or("human");
            let author_key = hex(env.get("author").unwrap().bytes().unwrap());
            let full_msg = format!(
                "{msg}\n\nWeft-Change: {chex}\nWeft-Landing: {lhex} (seq {seq})\nWeft-Model: {model}\nWeft-Author-Key: {author_key}");
            let date = format!("{ts} +0000");
            let out = Command::new("git")
                .args(["-C", dir, "-c", "user.name=weft-bridge",
                       "-c", "user.email=bridge@weft.invalid",
                       "commit", "-q", "--allow-empty", "-m", &full_msg])
                .env("GIT_AUTHOR_DATE", &date).env("GIT_COMMITTER_DATE", &date)
                .output().unwrap();
            if !out.status.success() {
                die(&format!("git commit: {}", String::from_utf8_lossy(&out.stderr)));
            }
            exported += 1;
        }
    }
    let tip = git(dir, &["rev-parse", "HEAD"]);
    if original != "HEAD" {
        git(dir, &["checkout", "-q", &original]);
    }
    println!("exported {exported} commits to branch {branch} (tip {tip})");
}

// --------------------------------------------------------------- main ------

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str, default: &str| -> String {
        args.iter().position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
            .unwrap_or(default.into())
    };
    let hub = flag("--hub", "http://127.0.0.1:8747");
    let hostport = hub.trim_start_matches("http://").trim_end_matches('/');
    let (host, port) = hostport.split_once(':').unwrap_or((hostport, "8747"));
    let sk = load_key(&flag("--key", ".weft-cli.key"));
    let mut cli = Cli { host: host.into(), port: port.parse().unwrap_or(8747),
                        sk, repo: None };
    let policy = cli.get("/policy");
    cli.repo = policy["repo"].as_str().map(|r| {
        let b: Vec<u8> = (0..64).step_by(2)
            .map(|i| u8::from_str_radix(&r[i..i + 2], 16).unwrap()).collect();
        b.try_into().unwrap()
    });

    match args.first().map(String::as_str) {
        Some("init") => {
            if cli.repo.is_some() {
                die("hub already has a repository");
            }
            let gate = policy["gate"].as_str().unwrap_or_else(|| die("no gate key"));
            let gate_bytes: Vec<u8> = (0..64).step_by(2)
                .map(|i| u8::from_str_radix(&gate[i..i + 2], 16).unwrap()).collect();
            let me = cli.sk.verifying_key().to_bytes();
            let (gen, gen_raw) = make_obj(&cli.sk, None, "genesis", V::map(vec![
                ("name", V::Text(flag("--name", "weft-repo"))),
                ("authority", V::Arr(vec![V::Bytes(me.to_vec())])),
                ("quorum", V::Int(1)),
                ("refs", V::map(vec![("trunk", V::map(vec![
                    ("gates", V::Arr(vec![V::Bytes(gate_bytes)])),
                    ("threshold", V::Int(1))]))])),
                ("policy_init", V::map(vec![
                    ("rules", V::Arr(vec![])), ("recipes", V::Arr(vec![])),
                    ("approvals", V::Int(0)),
                    ("stale_reads", V::Text("warn".into()))])),
                ("config_init", V::map(vec![]))]), None, now());
            let (code, resp) = cli.http("POST", "/obj", &gen_raw);
            if code != 200 {
                die(&String::from_utf8_lossy(&resp));
            }
            cli.repo = Some(gen);
            let cap = cli.publish("capability", V::map(vec![
                ("audience", V::Bytes(me.to_vec())),
                ("parent", V::Null),
                ("scope", V::map(vec![
                    ("actions", V::Arr(vec![V::Text("publish_change".into()),
                                            V::Text("propose".into())])),
                    ("paths", V::Arr(vec![V::Text("**".into())]))])),
                ("exp", V::Int(now() + 30 * 24 * 3_600_000))]), None);
            println!("repo {} — you are the authority", hex(&gen));
            let gitdir = flag("--git", "");
            if !gitdir.is_empty() {
                import_git(&cli, &gitdir, cap);
            }
        }
        Some("clone") => {
            let url = args.get(1).unwrap_or_else(|| die("usage: weft clone <url> [dir]"));
            let dir = args.get(2).cloned().unwrap_or_else(|| {
                url.rsplit('/').next().unwrap().trim_end_matches(".git").to_string()
            });
            let out = Command::new("git").args(["clone", "-q", url, &dir]).output().unwrap();
            if !out.status.success() {
                die(&String::from_utf8_lossy(&out.stderr));
            }
            let exe = std::env::current_exe().unwrap();
            let st = Command::new(exe)
                .args(["init", "--git", &dir, "--hub", &hub,
                       "--key", &flag("--key", ".weft-cli.key"),
                       "--name", &dir]).status().unwrap();
            std::process::exit(st.code().unwrap_or(1));
        }
        Some("status") => {
            let (h, l, p) = (cli.get("/heads"), cli.get("/log"), cli.get("/pending"));
            println!("repo    {}", policy["repo"].as_str().unwrap_or("(none — run weft init)"));
            println!("trunk   seq {}", h["seq"]);
            println!("queued  {}   pending approvals {}", l["queued"],
                     p["pending"].as_array().map(|a| a.len()).unwrap_or(0));
        }
        Some("export") => {
            if cli.repo.is_none() {
                die("hub has no repository");
            }
            let dir = flag("--git", "");
            if dir.is_empty() {
                die("usage: weft export --git <dir> [--branch weft-export]");
            }
            export_git(&cli, &dir, &flag("--branch", "weft-export"));
        }
        _ => {
            eprintln!("weft — the execution ledger for autonomous coding agents");
            eprintln!("usage: weft init [--git <dir>] | clone <url> [dir] | status | export --git <dir> [--branch <b>]");
            eprintln!("flags: --hub http://127.0.0.1:8747  --key .weft-cli.key");
        }
    }
}
