//! The human-in-the-loop e2e, driven exactly the way the browser UI works:
//! /prepare → sign externally (key never touches the server) → /submit.
//! Covers: genesis bootstrap, role delegation, approval-gated landing
//! (policy approvals:1), and revoked-capability rejection.

use std::io::{Read, Write};
use std::net::TcpStream;
use weft_core::keygen;
use ed25519_dalek::Signer;

const PORT: u16 = 18748;

fn http(method: &str, path: &str, body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", PORT)).expect("connect");
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        body.len());
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let status: u16 = std::str::from_utf8(&resp[..split]).unwrap()
        .split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, String::from_utf8_lossy(&resp[split..]).into_owned())
}

fn jfield<'a>(json: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\":");
    let start = json.find(&pat).unwrap_or_else(|| panic!("{key} in {json}")) + pat.len();
    let rest = &json[start..];
    if let Some(inner) = rest.strip_prefix('"') {
        &inner[..inner.find('"').unwrap()]
    } else {
        &rest[..rest.find([',', '}', ']']).unwrap()]
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The browser flow: /prepare → Ed25519-sign the 32-byte payload → /submit.
fn publish(sk: &ed25519_dalek::SigningKey, repo: Option<&str>, typ: &str,
           auth: Option<&str>, body_json: &str) -> Result<String, String> {
    let author = hex(&sk.verifying_key().to_bytes());
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let repo_j = repo.map(|r| format!("\"hex:{r}\"")).unwrap_or("null".into());
    let auth_j = auth.map(|a| format!("\"hex:{a}\"")).unwrap_or("null".into());
    let base = format!(
        "\"repo\":{repo_j},\"type\":\"{typ}\",\"ts\":{ts},\"author\":\"hex:{author}\",\"auth\":{auth_j},\"body\":{body_json}");
    let (code, resp) = http("POST", "/prepare", format!("{{{base}}}").as_bytes());
    assert_eq!(code, 200, "prepare: {resp}");
    let payload = from_hex(jfield(&resp, "payload"));
    let sig = hex(&sk.sign(&payload).to_bytes());
    let (code, resp) = http("POST", "/submit",
        format!("{{{base},\"sig\":\"hex:{sig}\"}}").as_bytes());
    if code == 200 {
        Ok(jfield(&resp, "oid").to_string())
    } else {
        Err(resp)
    }
}

fn wait_until(mut pred: impl FnMut() -> bool, what: &str) {
    for _ in 0..150 {
        if pred() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("timeout waiting for {what}");
}

#[test]
fn approval_gated_landing_and_revocation() {
    let hub = weftd::new_hub();
    let gate_pub = hex(&hub.lock().unwrap().gate_pub);
    {
        let hub = hub.clone();
        std::thread::spawn(move || weftd::serve(PORT, hub));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    // --- browser "Create repository": genesis with THIS key as authority ---
    let (auth_sk, auth_pub) = keygen();
    let repo = publish(&auth_sk, None, "genesis", None, &format!(
        r#"{{"name":"ui-e2e","authority":["hex:{}"],"quorum":1,"refs":{{"trunk":{{"gates":["hex:{gate_pub}"],"threshold":1}}}},"policy_init":{{"rules":[],"recipes":[],"approvals":1,"stale_reads":"warn"}},"config_init":{{}}}}"#,
        hex(&auth_pub))).expect("genesis");
    assert_eq!(jfield(&http("GET", "/policy", b"").1, "repo"), repo);

    // --- self-capability (Maintainer template) -----------------------------
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() + 600_000;
    let cap = publish(&auth_sk, Some(&repo), "capability", None, &format!(
        r#"{{"audience":"hex:{}","parent":null,"scope":{{"actions":["publish_change","propose","approve","delegate"],"paths":["**"]}},"exp":{exp},"meta":{{"reason":"Maintainer"}}}}"#,
        hex(&auth_pub))).expect("cap");

    // --- seed change via SELF-sentinel patch, then propose -----------------
    let patch = publish(&auth_sk, Some(&repo), "patch", None,
        r#"{"nonce":"hex:e2e0e2e0e2e0e2e0","ops":[["mkfile","a.txt"],["insert",[null,0],["S"],["hex:68656c6c6f2077656674"]]]}"#)
        .expect("patch");
    let change = publish(&auth_sk, Some(&repo), "change", Some(&cap), &format!(
        r#"{{"patch":"hex:{patch}","footprint":["a.txt"],"reads":[],"message":"seed via browser flow"}}"#))
        .expect("change");
    publish(&auth_sk, Some(&repo), "proposal", Some(&cap), &format!(
        r#"{{"ref":"trunk","delta":["hex:{change}"],"status":"open"}}"#))
        .expect("proposal");

    // --- gate parks it: pending approval (approvals:1, none yet) -----------
    wait_until(|| http("GET", "/pending", b"").1.contains("\"need\":1"),
               "pending approval entry");
    assert_eq!(jfield(&http("GET", "/heads", b"").1, "seq"), "-1",
               "must NOT land before approval");
    let pending = http("GET", "/pending", b"").1;
    let manifest = jfield(&pending, "manifest").to_string();

    // --- the [Approve & sign] button ---------------------------------------
    publish(&auth_sk, Some(&repo), "evidence", None, &format!(
        r#"{{"manifest":"hex:{manifest}","recipe":{{"kind":"approval"}},"results":[{{"status":"pass"}}]}}"#))
        .expect("approval");
    wait_until(|| jfield(&http("GET", "/heads", b"").1, "seq") == "0",
               "landing after approval");
    assert!(http("GET", "/workspace", b"").1.contains("hello weft"));
    assert!(http("GET", "/pending", b"").1.contains("\"pending\":[]"));

    // --- identity: publish a name, resolve it via /identities ---------------
    publish(&auth_sk, Some(&repo), "identity", None,
            r#"{"kind":"human","name":"pranab"}"#).expect("identity");
    let ids = http("GET", "/identities", b"").1;
    assert!(ids.contains("\"name\":\"pranab\"")
            && ids.contains(&hex(&auth_pub)), "identity listed: {ids}");

    // --- role lifecycle: delegate a Contributor, revoke, watch it bounce ---
    let (con_sk, con_pub) = keygen();
    let cap_c = publish(&auth_sk, Some(&repo), "capability", None, &format!(
        r#"{{"audience":"hex:{}","parent":"hex:{cap}","scope":{{"actions":["publish_change","propose"],"paths":["a.txt"]}},"exp":{exp},"meta":{{"reason":"Contributor"}}}}"#,
        hex(&con_pub))).expect("contrib cap");
    publish(&auth_sk, Some(&repo), "revocation", None, &format!(
        r#"{{"target":"hex:{cap_c}","reason":"offboarded"}}"#)).expect("revocation");
    wait_until(|| http("GET", "/caps", b"").1.contains("\"revoked\":true"),
               "cap shows revoked");

    let patch2 = publish(&con_sk, Some(&repo), "patch", None, &format!(
        r#"{{"nonce":"hex:c0c0c0c0c0c0c0c0","ops":[["insert",["hex:{patch}",0],["hex:{patch}",1],["hex:6861636b"]]]}}"#))
        .expect("patch2");
    let change2 = publish(&con_sk, Some(&repo), "change", Some(&cap_c), &format!(
        r#"{{"patch":"hex:{patch2}","footprint":["a.txt"],"reads":[],"message":"revoked key tries anyway"}}"#))
        .expect("change2");
    publish(&con_sk, Some(&repo), "proposal", Some(&cap_c), &format!(
        r#"{{"ref":"trunk","delta":["hex:{change2}"],"status":"open"}}"#))
        .expect("proposal2");
    wait_until(|| http("GET", "/log", b"").1.contains("revoked"),
               "gate rejects revoked capability");
    assert_eq!(jfield(&http("GET", "/heads", b"").1, "seq"), "0",
               "revoked work must not land");
}
