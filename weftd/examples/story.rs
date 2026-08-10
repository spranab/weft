//! The bridge-demo story: run three model-agents against a hub that has
//! imported spranab/weft-demo, land narrative work through the gate, and
//! leave one stale-read bounce and one revoked-credential bounce on the
//! record. Afterwards `weft export` turns the landings into the public
//! weft-export branch.
//!
//! Env: STORY_HUB (default http://127.0.0.1:8748)
//!      STORY_KEY (authority seed file written by `weft init`)

use ed25519_dalek::SigningKey;
use serde_json::Value as J;
use std::io::{Read, Write};
use std::net::TcpStream;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

struct Hub(String, u16);
impl Hub {
    fn http(&self, method: &str, path: &str, body: &[u8]) -> (u16, String) {
        let mut s = TcpStream::connect((self.0.as_str(), self.1)).expect("hub");
        s.write_all(format!(
            "{method} {path} HTTP/1.0\r\nHost: l\r\nContent-Length: {}\r\n\r\n",
            body.len()).as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut r = Vec::new();
        s.read_to_end(&mut r).unwrap();
        let sp = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        (std::str::from_utf8(&r[..sp]).unwrap().split_whitespace()
            .nth(1).unwrap().parse().unwrap(),
         String::from_utf8_lossy(&r[sp..]).into_owned())
    }
    fn get(&self, p: &str) -> J {
        serde_json::from_str(&self.http("GET", p, b"").1).unwrap()
    }
}

fn main() {
    use weft_core::cbor::V;
    use weft_core::{make_obj, Oid};

    let hub_url = std::env::var("STORY_HUB").unwrap_or("http://127.0.0.1:8748".into());
    let hp = hub_url.trim_start_matches("http://").trim_end_matches('/');
    let (h, p) = hp.split_once(':').unwrap_or((hp, "8748"));
    let hub = Hub(h.into(), p.parse().unwrap());
    let keyfile = std::env::var("STORY_KEY").unwrap_or(".weft-cli.key".into());
    let seed = unhex(std::fs::read_to_string(&keyfile).expect("key file").trim());
    let auth_sk = SigningKey::from_bytes(&<[u8; 32]>::try_from(seed.as_slice()).unwrap());
    let auth_pub = auth_sk.verifying_key().to_bytes();

    let repo_hex = hub.get("/policy")["repo"].as_str().expect("repo").to_string();
    let repo: Oid = unhex(&repo_hex).try_into().unwrap();

    let publish = |sk: &SigningKey, typ: &str, body: V, auth: Option<Oid>| -> Oid {
        let (oid, raw) = make_obj(sk, Some(repo), typ, body, auth, now());
        let (code, resp) = hub.http("POST", "/obj", &raw);
        assert_eq!(code, 200, "publish {typ}: {resp}");
        oid
    };
    let propose = |sk: &SigningKey, change: Oid, auth: Oid| {
        let (_, raw) = make_obj(sk, Some(repo), "proposal", V::map(vec![
            ("ref", V::Text("trunk".into())),
            ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
            ("status", V::Text("open".into()))]), Some(auth), now());
        let (code, resp) = hub.http("POST", "/propose", &raw);
        assert_eq!(code, 200, "{resp}");
    };
    let wait_landed = |change: &Oid| -> bool {
        for _ in 0..80 {
            std::thread::sleep(std::time::Duration::from_millis(150));
            if hub.get("/log").to_string().contains(&hex(change)) {
                return true;
            }
        }
        false
    };
    let bytes_arr = |xs: &[&str]| V::Arr(xs.iter()
        .map(|x| V::Bytes(x.as_bytes().to_vec())).collect());
    let fid_of = |ws: &J, path: &str| -> V {
        let f = ws["files"][path]["fid"].as_array().expect(path);
        V::Arr(vec![V::Bytes(unhex(f[0].as_str().unwrap())),
                    V::Int(f[1].as_i64().unwrap())])
    };
    let lid = |ws: &J, path: &str, n: usize| -> V {
        let l = ws["files"][path]["line_ids"].as_array().expect(path)[n]
            .as_array().unwrap();
        V::Arr(vec![V::Bytes(unhex(l[0].as_str().unwrap())),
                    V::Int(l[1].as_i64().unwrap())])
    };
    let last_lid = |ws: &J, path: &str| -> V {
        let n = ws["files"][path]["line_ids"].as_array().expect(path).len();
        lid(ws, path, n - 1)
    };

    // ── authority capability + delegations ─────────────────────────────
    let cap_auth = publish(&auth_sk, "capability", V::map(vec![
        ("audience", V::Bytes(auth_pub.to_vec())),
        ("parent", V::Null),
        ("scope", V::map(vec![
            ("actions", V::Arr(vec![V::Text("publish_change".into()),
                                    V::Text("propose".into()),
                                    V::Text("instruct".into())])),
            ("paths", V::Arr(vec![V::Text("**".into())]))])),
        ("exp", V::Int(now() + 86_400_000))]), None);
    let _ = cap_auth;
    publish(&auth_sk, "identity", V::map(vec![
        ("kind", V::Text("human".into())), ("name", V::Text("pranab".into()))]), None);

    let worker = |model: &str| -> (SigningKey, Oid) {
        let (sk, pk) = weft_core::keygen();
        let cap = publish(&auth_sk, "capability", V::map(vec![
            ("audience", V::Bytes(pk.to_vec())),
            ("parent", V::Null),
            ("scope", V::map(vec![
                ("actions", V::Arr(vec![V::Text("publish_change".into()),
                                        V::Text("propose".into())])),
                ("paths", V::Arr(vec![V::Text("**".into())]))])),
            ("exp", V::Int(now() + 86_400_000)),
            ("meta", V::map(vec![("reason",
                V::Text(format!("Contributor ({model})")))]))]), None);
        (sk, cap)
    };
    let (claude_sk, claude_cap) = worker("claude-fable-5");
    let (gpt_sk, gpt_cap) = worker("gpt-5.6-sol");
    let (qwen_sk, qwen_cap) = worker("qwen3.8-max");

    // ── intents ─────────────────────────────────────────────────────────
    let intent = |title: &str, goal: &str| publish(&auth_sk, "intent", V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("title", V::Text(title.into())),
        ("goal", V::Text(goal.into())),
        ("constraints", V::Arr(vec![])),
        ("criteria", V::Arr(vec![])),
        ("priority", V::Int(60))]), None);
    let i1 = intent("add exponential backoff with jitter",
                    "replace constant-only backoff; keep the public API");
    let i2 = intent("document retry usage",
                    "README should show attempts + backoff choices");
    let i3 = intent("test backoff bounds",
                    "exponential delays must respect the cap");

    let ws0 = hub.get("/workspace");
    let backoff = "src/retryx/backoff.py";
    let old_backoff_digest = ws0["files"][backoff]["digest"].as_str().unwrap().to_string();

    let change = |sk: &SigningKey, cap: Oid, model: &str, msg: &str,
                      intent_oid: Option<Oid>, footprint: Vec<&str>,
                      reads: V, ops: Vec<V>| -> Oid {
        let patch = publish(sk, "patch", V::map(vec![
            ("nonce", V::Bytes(now().to_be_bytes().to_vec())),
            ("ops", V::Arr(ops))]), None);
        let mut body = vec![
            ("patch", V::Bytes(patch.to_vec())),
            ("footprint", V::Arr(footprint.iter().map(|f| V::Text((*f).into())).collect())),
            ("reads", reads),
            ("message", V::Text(msg.into())),
            ("provenance", V::map(vec![("model", V::Text(model.into()))]))];
        if let Some(i) = intent_oid {
            body.push(("intent", V::Bytes(i.to_vec())));
            body.push(("closes", V::Arr(vec![V::Bytes(i.to_vec())])));
        }
        let c = publish(sk, "change", V::map(body), Some(cap));
        propose(sk, c, cap);
        c
    };

    // claude: replace the docstring (mid-file delete works — finding W9) and
    // add exponential backoff below the constant one
    let c1 = change(&claude_sk, claude_cap, "claude-fable-5",
        "backoff: add exponential + jitter", Some(i1), vec![backoff],
        V::Arr(vec![]), vec![
            V::Arr(vec![V::Text("delete".into()), fid_of(&ws0, backoff),
                        V::Arr(vec![lid(&ws0, backoff, 4)])]),
            V::Arr(vec![V::Text("insert".into()), fid_of(&ws0, backoff),
                        lid(&ws0, backoff, 3),
                        bytes_arr(&["    \"\"\"Sleep a fixed delay between attempts (see expo_backoff).\"\"\""])]),
            V::Arr(vec![V::Text("insert".into()), fid_of(&ws0, backoff),
                        last_lid(&ws0, backoff), bytes_arr(&[
                "", "",
                "def expo_backoff(attempt, base=0.25, cap=8.0):",
                "    \"\"\"Exponential backoff with full jitter, capped.\"\"\"",
                "    import random",
                "    delay = min(cap, base * (2 ** attempt))",
                "    time.sleep(random.uniform(0, delay))"])])]);
    assert!(wait_landed(&c1), "claude change must land");
    println!("✓ claude landed: exponential backoff (closes intent {})", &hex(&i1)[..8]);

    // gpt + qwen: disjoint, submitted together — they batch
    let ws1 = hub.get("/workspace");
    let c2 = change(&gpt_sk, gpt_cap, "gpt-5.6-sol",
        "README: document attempts + backoff", Some(i2), vec!["README.md"],
        V::Arr(vec![]), vec![
            V::Arr(vec![V::Text("insert".into()), fid_of(&ws1, "README.md"),
                        last_lid(&ws1, "README.md"), bytes_arr(&[
                "", "## Choosing a backoff", "",
                "```python",
                "from retryx.backoff import expo_backoff",
                "retry(fetch, attempts=5, backoff=expo_backoff)",
                "```"])])]);
    let c3 = change(&qwen_sk, qwen_cap, "qwen3.8-max",
        "tests: expo_backoff respects the cap", Some(i3),
        vec!["tests/test_retry.py"], V::Arr(vec![]), vec![
            V::Arr(vec![V::Text("insert".into()), fid_of(&ws1, "tests/test_retry.py"),
                        last_lid(&ws1, "tests/test_retry.py"), bytes_arr(&[
                "", "",
                "def test_expo_backoff_is_capped(monkeypatch):",
                "    from retryx import backoff as b",
                "    slept = []",
                "    monkeypatch.setattr(b.time, 'sleep', slept.append)",
                "    b.expo_backoff(attempt=30, base=0.25, cap=8.0)",
                "    assert 0 <= slept[0] <= 8.0"])])]);
    assert!(wait_landed(&c2) && wait_landed(&c3), "gpt+qwen must land");
    println!("✓ gpt + qwen landed (disjoint — batched by the gate)");

    // stale read: reasoned against the OLD backoff.py, touches __init__.py
    let (stale_sk, stale_cap) = worker("claude-fable-5");
    let c4 = change(&stale_sk, stale_cap, "claude-fable-5",
        "expose expo_backoff as default (stale reasoning)", None,
        vec!["src/retryx/__init__.py"],
        V::Arr(vec![V::Arr(vec![V::Text(backoff.into()),
                                V::Bytes(unhex(&old_backoff_digest))])]),
        vec![V::Arr(vec![V::Text("insert".into()),
                         fid_of(&ws1, "src/retryx/__init__.py"),
                         last_lid(&ws1, "src/retryx/__init__.py"),
                         bytes_arr(&["# assumes constant_backoff is the only strategy"])])]);
    std::thread::sleep(std::time::Duration::from_millis(800));
    let rejected = hub.get("/log")["rejects"].to_string().contains(&hex(&c4)[..16]);
    let landed = hub.get("/log").to_string().contains(&hex(&c4));
    println!("{} stale-read change {}", if rejected || !landed { "✗" } else { "?" },
             if rejected { "rejected (read-set went stale)" } else { "state" });

    // revoked credential
    let (late_sk, late_cap) = worker("gpt-5.6-sol");
    publish(&auth_sk, "revocation", V::map(vec![
        ("target", V::Bytes(late_cap.to_vec())),
        ("reason", V::Text("rotation drill".into()))]), None);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let ws2 = hub.get("/workspace");
    let _c5 = change(&late_sk, late_cap, "gpt-5.6-sol",
        "post-revocation attempt", None, vec!["README.md"], V::Arr(vec![]),
        vec![V::Arr(vec![V::Text("insert".into()), fid_of(&ws2, "README.md"),
                         last_lid(&ws2, "README.md"),
                         bytes_arr(&["(this line should never land)"])])]);
    std::thread::sleep(std::time::Duration::from_millis(800));
    let revoked_hit = hub.get("/log")["rejects"].to_string().contains("revoked");
    println!("{} revoked-credential attempt {}", if revoked_hit { "✗" } else { "?" },
             if revoked_hit { "refused at certification" } else { "state unknown" });

    let heads = hub.get("/heads");
    println!("\nstory complete — trunk seq {}, ready for `weft export`", heads["seq"]);
}
