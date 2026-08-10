//! The public-instance mode: --demo seeds a living scenario through the real
//! gate; --readonly turns every POST route away.

use std::io::{Read, Write};
use std::net::TcpStream;

const PORT: u16 = 18752;

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

#[test]
fn demo_seeds_and_readonly_rejects() {
    let hub = weftd::new_hub();
    weftd::seed_demo(&hub);
    hub.lock().unwrap().readonly = true;
    {
        let hub = hub.clone();
        std::thread::spawn(move || weftd::serve(PORT, hub));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    // seeded state: landings from three models, a stale-read and a revoked
    // rejection, an intent, an identity, the tour note
    let log = http("GET", "/log", b"").1;
    assert!(log.contains("claude-fable-5") && log.contains("gpt-5.6-sol")
            && log.contains("qwen3.8-max"), "{log}");
    assert!(log.contains("stale read"), "stale rejection recorded: {log}");
    assert!(log.contains("revoked"), "revocation rejection recorded: {log}");
    let heads = http("GET", "/heads", b"").1;
    assert!(!heads.contains("\"seq\":-1"), "landings exist: {heads}");
    let intents = http("GET", "/intents", b"").1;
    assert!(intents.contains("exponential backoff"), "{intents}");
    assert!(intents.contains("\"closed\":true"), "claude's intent closed: {intents}");
    assert!(http("GET", "/identities", b"").1.contains("pranab"));
    let notes = http("GET", "/notes", b"").1;
    assert!(notes.contains("READ-ONLY") && notes.contains("weft-demo"), "{notes}");
    assert!(notes.contains("git-import"), "bridge note present: {notes}");
    // the story's woven content is in the head workspace
    let ws = http("GET", "/workspace", b"").1;
    assert!(ws.contains("expo_backoff") && ws.contains("Choosing a backoff"), "{ws}");
    assert!(http("GET", "/", b"").1.contains("governance"));

    // readonly: every POST turned away
    for path in ["/obj", "/propose", "/prepare", "/submit"] {
        let (code, body) = http("POST", path, b"{}");
        assert_eq!(code, 403, "{path}: {body}");
        assert!(body.contains("read-only"), "{body}");
    }
}
