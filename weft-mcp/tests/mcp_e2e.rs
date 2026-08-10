//! Dogfood proof: a real MCP client session against weft-mcp (spawned as a
//! child process, newline-delimited JSON-RPC on stdio) driving a live weftd
//! gate — initialize → tools/list → intent_create → change_submit → landed.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use ed25519_dalek::Signer;
use weft_core::keygen;

const PORT: u16 = 18749;

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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn publish(sk: &ed25519_dalek::SigningKey, repo: Option<&str>, typ: &str,
           body_json: &str) -> String {
    let author = hex(&sk.verifying_key().to_bytes());
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let repo_j = repo.map(|r| format!("\"hex:{r}\"")).unwrap_or("null".into());
    let base = format!(
        "\"repo\":{repo_j},\"type\":\"{typ}\",\"ts\":{ts},\"author\":\"hex:{author}\",\"auth\":null,\"body\":{body_json}");
    let (code, resp) = http("POST", "/prepare", format!("{{{base}}}").as_bytes());
    assert_eq!(code, 200, "{resp}");
    let payload_hex = resp.split("\"payload\":\"").nth(1).unwrap()
        .split('"').next().unwrap();
    let payload: Vec<u8> = (0..payload_hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&payload_hex[i..i + 2], 16).unwrap()).collect();
    let sig = hex(&sk.sign(&payload).to_bytes());
    let (code, resp) = http("POST", "/submit",
        format!("{{{base},\"sig\":\"hex:{sig}\"}}").as_bytes());
    assert_eq!(code, 200, "{resp}");
    resp.split("\"oid\":\"").nth(1).unwrap().split('"').next().unwrap().into()
}

struct Mcp {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    next_id: i64,
}

impl Mcp {
    fn call(&mut self, method: &str, params: &str) -> String {
        self.next_id += 1;
        let id = self.next_id;
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin,
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}")
            .unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        assert!(line.contains(&format!("\"id\":{id}")), "response for {id}: {line}");
        line
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[test]
fn mcp_session_lands_a_change() {
    // --- live gate ---------------------------------------------------------
    let hub = weftd::new_hub();
    let gate_pub = hex(&hub.lock().unwrap().gate_pub);
    {
        let hub = hub.clone();
        std::thread::spawn(move || weftd::serve(PORT, hub));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    // --- human bootstraps: genesis (approvals:0 for this test) -------------
    let (auth_sk, auth_pub) = keygen();
    let repo = publish(&auth_sk, None, "genesis", &format!(
        r#"{{"name":"mcp-e2e","authority":["hex:{}"],"quorum":1,"refs":{{"trunk":{{"gates":["hex:{gate_pub}"],"threshold":1}}}},"policy_init":{{"rules":[],"recipes":[],"approvals":0,"stale_reads":"warn"}},"config_init":{{}}}}"#,
        hex(&auth_pub)));

    // --- spawn weft-mcp with its own key file ------------------------------
    let keyfile = std::env::temp_dir().join(format!("weft-mcp-e2e-{}.key", std::process::id()));
    let _ = std::fs::remove_file(&keyfile);
    let mut child = Command::new(env!("CARGO_BIN_EXE_weft-mcp"))
        .env("WEFT_HUB", format!("http://127.0.0.1:{PORT}"))
        .env("WEFT_KEY", &keyfile)
        .env("WEFT_MODEL", "claude-fable-5")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().expect("spawn weft-mcp");
    let reader = BufReader::new(child.stdout.take().unwrap());
    let mut mcp = Mcp { child, reader, next_id: 0 };

    let init = mcp.call("initialize",
        r#"{"protocolVersion":"2025-06-18","capabilities":{}}"#);
    assert!(init.contains("weft-mcp"));
    let tools = mcp.call("tools/list", "{}");
    for t in ["change_submit", "intent_create", "workspace", "provenance", "approve"] {
        assert!(tools.contains(t), "tool {t} advertised");
    }

    // --- agent has NO capability yet: change_submit must refuse helpfully ---
    std::thread::sleep(std::time::Duration::from_millis(200));
    let agent_pub = std::fs::read_to_string(&keyfile).ok()
        .map(|seed_hex| {
            let seed: Vec<u8> = (0..64).step_by(2)
                .map(|i| u8::from_str_radix(&seed_hex.trim()[i..i + 2], 16).unwrap())
                .collect();
            let sk = ed25519_dalek::SigningKey::from_bytes(
                &<[u8; 32]>::try_from(seed.as_slice()).unwrap());
            hex(&sk.verifying_key().to_bytes())
        }).expect("agent key file written");
    let denied = mcp.call("tools/call", &format!(
        r#"{{"name":"change_submit","arguments":{{"message":"x","edits":[{{"path":"a.txt","create":true,"lines":["hi"]}}]}}}}"#));
    assert!(denied.contains("no live capability"), "helpful refusal: {denied}");

    // --- human mints a Contributor capability for the agent key ------------
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() + 600_000;
    publish(&auth_sk, Some(&repo), "capability", &format!(
        r#"{{"audience":"hex:{agent_pub}","parent":null,"scope":{{"actions":["publish_change","propose"],"paths":["**"]}},"exp":{exp},"meta":{{"reason":"Contributor (mcp e2e)"}}}}"#));

    // --- the dogfood loop: intent → change_submit → landed ------------------
    let intent = mcp.call("tools/call",
        r#"{"name":"intent_create","arguments":{"title":"seed the repo","goal":"create README","criteria":[]}}"#);
    let intent_oid = intent.split("\\\"intent\\\":\\\"").nth(1)
        .map(|s| s.split('\\').next().unwrap().to_string())
        .unwrap_or_else(|| panic!("intent oid in response: {intent}"));
    let landed = mcp.call("tools/call", &format!(
        r##"{{"name":"change_submit","arguments":{{"message":"add README","intent":"{intent_oid}","edits":[{{"path":"README.md","create":true,"lines":["# woven by mcp","first line landed through the weft-mcp door"]}}]}}}}"##));
    assert!(landed.contains("\\\"outcome\\\":\\\"landed\\\""), "landed: {landed}");

    // --- follow-up edit against existing line ids --------------------------
    let landed2 = mcp.call("tools/call",
        r#"{"name":"change_submit","arguments":{"message":"append","edits":[{"path":"README.md","insert_after":2,"lines":["third line via position mapping"]}]}}"#);
    assert!(landed2.contains("\\\"outcome\\\":\\\"landed\\\""), "landed2: {landed2}");

    // --- workspace shows all three lines; intent is closed ------------------
    let ws = mcp.call("tools/call", r#"{"name":"workspace","arguments":{}}"#);
    assert!(ws.contains("woven by mcp") && ws.contains("third line"));
    let intents = mcp.call("tools/call", r#"{"name":"intent_list","arguments":{}}"#);
    assert!(intents.contains("\\\"closed\\\":true"), "intent closed: {intents}");

    // --- provenance walks to the human's authority root ---------------------
    let (_, log) = http("GET", "/log", b"");
    let chg = log.split("\"oid\":\"").nth(1).unwrap().split('"').next().unwrap();
    let prov = mcp.call("tools/call", &format!(
        r#"{{"name":"provenance","arguments":{{"change":"{chg}"}}}}"#));
    assert!(prov.contains("\\\"root\\\":true"), "prov: {prov}");

    let _ = std::fs::remove_file(&keyfile);
}
