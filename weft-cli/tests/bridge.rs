//! Round-trip bridge e2e: git repo → weft init --git (import lands through
//! the gate) → an agent lands a change → weft export writes conventional
//! commits with provenance trailers → content matches, and a second export
//! is byte-identical (deterministic mirror).

use std::process::Command;
use ed25519_dalek::Signer;
use weft_core::cbor::V;
use weft_core::*;
use std::io::{Read, Write as IoWrite};
use std::net::TcpStream;

const PORT: u16 = 18751;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn http(method: &str, path: &str, body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", PORT)).unwrap();
    s.write_all(format!("{method} {path} HTTP/1.0\r\nHost: l\r\nContent-Length: {}\r\n\r\n",
                        body.len()).as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    (std::str::from_utf8(&resp[..split]).unwrap().split_whitespace()
        .nth(1).unwrap().parse().unwrap(),
     String::from_utf8_lossy(&resp[split..]).into_owned())
}

fn git(dir: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new("git").arg("-C").arg(dir)
        .args(["-c", "core.autocrlf=false", "-c", "user.name=t",
               "-c", "user.email=t@t"]).args(args).output().unwrap();
    assert!(out.status.success(), "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn weft(cwd: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_weft")).current_dir(cwd)
        .args(args).args(["--hub", &format!("http://127.0.0.1:{PORT}")])
        .output().unwrap();
    assert!(out.status.success(), "weft {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn git_roundtrip_through_the_gate() {
    // --- hub + seed git repo -----------------------------------------------
    let hub = weftd::new_hub();
    {
        let hub = hub.clone();
        std::thread::spawn(move || weftd::serve(PORT, hub));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    let tmp = std::env::temp_dir().join(format!("weft-bridge-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let repo_dir = tmp.join("proj");
    std::fs::create_dir_all(repo_dir.join("src")).unwrap();
    std::fs::write(repo_dir.join("src/main.txt"), "hello\nworld\n").unwrap();
    std::fs::write(repo_dir.join("README.md"), "# proj\n").unwrap();
    git(&repo_dir, &["init", "-q", "-b", "main"]);
    git(&repo_dir, &["add", "-A"]);
    git(&repo_dir, &["commit", "-qm", "seed"]);
    let base_sha = git(&repo_dir, &["rev-parse", "HEAD"]);

    // --- weft init --git: import lands through the gate --------------------
    let out = weft(&tmp, &["init", "--git", repo_dir.to_str().unwrap(),
                           "--name", "bridge-e2e"]);
    assert!(out.contains("imported 2 files"), "{out}");
    let ws = http("GET", "/workspace", b"").1;
    assert!(ws.contains("hello\\nworld") && ws.contains("# proj"), "{ws}");

    // --- an agent lands a change (direct object publish, gate-certified) ---
    let policy: serde_json::Value =
        serde_json::from_str(&http("GET", "/policy", b"").1).unwrap();
    let repo: Oid = {
        let r = policy["repo"].as_str().unwrap();
        let b: Vec<u8> = (0..64).step_by(2)
            .map(|i| u8::from_str_radix(&r[i..i + 2], 16).unwrap()).collect();
        b.try_into().unwrap()
    };
    // the CLI key is the authority; agents would get delegations — here we
    // reuse the CLI key file directly as the "agent" for brevity
    let seed_hex = std::fs::read_to_string(tmp.join(".weft-cli.key")).unwrap();
    let seed: Vec<u8> = (0..64).step_by(2)
        .map(|i| u8::from_str_radix(&seed_hex.trim()[i..i + 2], 16).unwrap()).collect();
    let sk = ed25519_dalek::SigningKey::from_bytes(
        &<[u8; 32]>::try_from(seed.as_slice()).unwrap());
    let _ = sk.sign(b"warm");
    let publish = |typ: &str, body: V, auth: Option<Oid>| -> Oid {
        let (oid, raw) = make_obj(&sk, Some(repo), typ, body, auth,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64);
        let (code, r) = http("POST", "/obj", &raw);
        assert_eq!(code, 200, "{r}");
        oid
    };
    let cap = publish("capability", V::map(vec![
        ("audience", V::Bytes(sk.verifying_key().to_bytes().to_vec())),
        ("parent", V::Null),
        ("scope", V::map(vec![
            ("actions", V::Arr(vec![V::Text("publish_change".into())])),
            ("paths", V::Arr(vec![V::Text("**".into())]))])),
        ("exp", V::Int(i64::MAX / 2))]), None);
    // append to src/main.txt: anchor on its last line via /workspace ids
    let wsj: serde_json::Value = serde_json::from_str(&ws).unwrap();
    let f = &wsj["files"]["src/main.txt"];
    let fid = f["fid"].as_array().unwrap();
    let last = f["line_ids"].as_array().unwrap().last().unwrap().as_array().unwrap();
    let from_hex = |s: &str| -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let patch = publish("patch", V::map(vec![
        ("nonce", V::Bytes(b"agent001".to_vec())),
        ("ops", V::Arr(vec![V::Arr(vec![
            V::Text("insert".into()),
            V::Arr(vec![V::Bytes(from_hex(fid[0].as_str().unwrap())),
                        V::Int(fid[1].as_i64().unwrap())]),
            V::Arr(vec![V::Bytes(from_hex(last[0].as_str().unwrap())),
                        V::Int(last[1].as_i64().unwrap())]),
            V::Arr(vec![V::Bytes(b"and the swarm".to_vec())])])]))]), None);
    let change = publish("change", V::map(vec![
        ("patch", V::Bytes(patch.to_vec())),
        ("footprint", V::Arr(vec![V::Text("src/main.txt".into())])),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("agent appends a line".into())),
        ("provenance", V::map(vec![("model", V::Text("claude-fable-5".into()))]))]),
        Some(cap));
    let (oid, raw) = make_obj(&sk, Some(repo), "proposal", V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
        ("status", V::Text("open".into()))]), Some(cap), 12345);
    let _ = oid;
    assert_eq!(http("POST", "/propose", &raw).0, 200);
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if http("GET", "/log", b"").1.contains(&hex(&change)) {
            break;
        }
    }

    // --- export: conventional commits with provenance trailers -------------
    let out = weft(&tmp, &["export", "--git", repo_dir.to_str().unwrap()]);
    assert!(out.contains("exported 1 commits"), "{out}");
    let log = git(&repo_dir, &["log", "--format=%H %s", "weft-export"]);
    assert!(log.contains("agent appends a line"), "{log}");
    let full = git(&repo_dir, &["log", "-1", "--format=%B", "weft-export"]);
    assert!(full.contains("Weft-Change:") && full.contains("Weft-Model: claude-fable-5"),
            "{full}");
    let content = git(&repo_dir, &["show", "weft-export:src/main.txt"]);
    assert_eq!(content, "hello\nworld\nand the swarm");
    // export branch parents onto the ORIGINAL git commit
    let parent = git(&repo_dir, &["rev-parse", "weft-export~1"]);
    assert_eq!(parent, base_sha, "export chains onto the import base");
    // original branch untouched
    assert_eq!(git(&repo_dir, &["rev-parse", "--abbrev-ref", "HEAD"]), "main");

    // --- determinism: second export rebuilds to the identical sha ----------
    let tip1 = git(&repo_dir, &["rev-parse", "weft-export"]);
    weft(&tmp, &["export", "--git", repo_dir.to_str().unwrap()]);
    let tip2 = git(&repo_dir, &["rev-parse", "weft-export"]);
    assert_eq!(tip1, tip2, "export must be deterministic");

    let _ = std::fs::remove_dir_all(&tmp);
}
