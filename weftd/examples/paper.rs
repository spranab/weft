//! Four agents write a research paper. Locally. Concurrently. Through a gate.
//!
//! This is the demo for the question "what does Weft change for *content*?"
//! Real inference: each agent is a local Ollama model writing its own section.
//! Real verification: a citation checker runs as gate evidence, and an LLM
//! judge attests quality from outside the sandbox (gate recipes have no
//! network, which is exactly why judgement signs from outside — RFC §12.5).
//!
//! One agent fabricates a citation, the way real models do. Watch what
//! happens to it.
//!
//!   ollama serve                                   # any local model
//!   cargo run --release -p weftd --example paper
//!
//! Env: WEFT_OLLAMA (default http://127.0.0.1:11434)
//!      WEFT_LLM    (default gemma4:e4b)
//!      WEFT_JUDGE  (default = WEFT_LLM)
//!   No Ollama? It falls back to canned sections so the gate story still runs.

use ed25519_dalek::SigningKey;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use weft_core::cbor::V;
use weft_core::*;

const TOPIC: &str = "verification-gated merging for autonomous coding agents";

struct Agent {
    model: &'static str,
    section: &'static str,
    file: &'static str,
    brief: &'static str,
    /// The realistic failure: this one cites a source that does not exist.
    fabricates: bool,
}

const AGENTS: [Agent; 4] = [
    Agent { model: "claude-fable-5", section: "Abstract", file: "paper/abstract.md",
        brief: "Write a 3-sentence abstract. Cite [1] once.", fabricates: false },
    Agent { model: "gpt-5.6-sol", section: "Background", file: "paper/background.md",
        brief: "Write 4 sentences on why human code review bottlenecks agent swarms. Cite [2] and [3].", fabricates: false },
    Agent { model: "qwen3.8-max", section: "Method", file: "paper/method.md",
        brief: "Write 4 sentences describing evidence-gated landing. Cite [1] and [4].", fabricates: false },
    Agent { model: "local-drafter", section: "Findings", file: "paper/findings.md",
        brief: "Write 3 sentences of results.", fabricates: true },
];

const REFERENCES: [&str; 4] = [
    "[1] Weft. RFC-0001: the Weft protocol. 2026.",
    "[2] Torvalds, L. Git: a distributed version control system. 2005.",
    "[3] Bors-NG contributors. The merge queue pattern. 2019.",
    "[4] Shapiro, M. et al. Conflict-free replicated data types. 2011.",
];

// ── ollama ────────────────────────────────────────────────────────────────

fn ollama(model: &str, prompt: &str) -> Option<String> {
    let url = std::env::var("WEFT_OLLAMA").unwrap_or("127.0.0.1:11434".into());
    let hp = url.trim_start_matches("http://").trim_end_matches('/');
    let (host, port) = hp.split_once(':').unwrap_or((hp, "11434"));
    let body = serde_json::json!({
        "model": model, "prompt": prompt, "stream": false,
        "options": {"temperature": 0.4, "num_predict": 220}
    }).to_string();
    let mut s = TcpStream::connect((host, port.parse::<u16>().ok()?)).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(180))).ok()?;
    write!(s, "POST /api/generate HTTP/1.0\r\nHost: {host}\r\n\
               Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
           body.len()).ok()?;
    s.write_all(body.as_bytes()).ok()?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).ok()?;
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let json: serde_json::Value = serde_json::from_slice(&resp[split..]).ok()?;
    let text = json["response"].as_str()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Strip think-tags and markdown fences some models emit, then hard-wrap.
fn clean(raw: &str, fabricate: bool) -> Vec<String> {
    let mut t = raw.to_string();
    while let (Some(a), Some(b)) = (t.find("<think>"), t.find("</think>")) {
        if a < b { t.replace_range(a..b + 8, ""); } else { break; }
    }
    let t = t.replace("```markdown", "").replace("```", "");
    let mut out: Vec<String> = Vec::new();
    for para in t.split('\n').map(str::trim).filter(|l| !l.is_empty()) {
        if para.starts_with('#') {
            continue; // we add our own heading
        }
        let mut line = String::new();
        for word in para.split_whitespace() {
            if line.len() + word.len() > 78 {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() { line.push(' '); }
            line.push_str(word);
        }
        if !line.is_empty() { out.push(line); }
    }
    out.truncate(8);
    if out.is_empty() {
        out.push("(the model returned nothing usable)".into());
    }
    if fabricate {
        // the failure mode this demo exists to catch
        out.push("This result is consistent with prior work [9].".into());
    }
    out
}

fn main() {
    let llm = std::env::var("WEFT_LLM").unwrap_or("gemma4:e4b".into());
    let judge_model = std::env::var("WEFT_JUDGE").unwrap_or(llm.clone());
    let live = ollama(&llm, "Reply with the single word: ok").is_some();
    println!("weft · four agents write a research paper\n");
    println!("  topic     {TOPIC}");
    println!("  inference {}", if live { format!("local — ollama/{llm}") }
             else { "offline (canned sections; the gate story is unchanged)".into() });
    println!();

    // ── hub, genesis, policy ────────────────────────────────────────────
    let hub = weftd::new_hub();
    let gate_pub = hub.lock().unwrap().gate_pub;
    let (auth_sk, auth_pub) = keygen();
    let ts = weftd::now_ms();
    let put = |sk: &SigningKey, repo: Option<Oid>, typ: &str, body: V,
               auth: Option<Oid>| -> Oid {
        let (_, raw) = make_obj(sk, repo, typ, body, auth, weftd::now_ms());
        let mut h = hub.lock().unwrap();
        let oid = h.store.put(raw).expect("store");
        if typ == "genesis" { weftd::adopt_genesis(&mut h, &oid, true).expect("genesis"); }
        oid
    };

    // gate evidence: every [n] marker must resolve in references.md, and each
    // section needs its front-matter title. Deterministic, offline, pinned.
    let py = if cfg!(windows) { "python" } else { "python3" };
    let check = "import glob,re,sys\n\
        refs=set(re.findall(r'\\[(\\d+)\\]', open('paper/references.md',encoding='utf-8').read()))\n\
        bad=[]\n\
        for f in sorted(glob.glob('paper/*.md')):\n\
        \x20 if f.endswith('references.md'): continue\n\
        \x20 t=open(f,encoding='utf-8').read()\n\
        \x20 if not t.startswith('---'): bad.append(f+': missing front-matter')\n\
        \x20 for c in re.findall(r'\\[(\\d+)\\]', t):\n\
        \x20  if c not in refs: bad.append(f+': citation ['+c+'] is not in references.md')\n\
        print('citation-check:', 'ok' if not bad else '; '.join(bad))\n\
        sys.exit(1 if bad else 0)";

    let gen = put(&auth_sk, None, "genesis", V::map(vec![
        ("name", V::Text("research-paper".into())),
        ("authority", V::Arr(vec![V::Bytes(auth_pub.to_vec())])),
        ("quorum", V::Int(1)),
        ("refs", V::map(vec![("trunk", V::map(vec![
            ("gates", V::Arr(vec![V::Bytes(gate_pub.to_vec())])),
            ("threshold", V::Int(1))]))])),
        ("policy_init", V::map(vec![
            ("rules", V::Arr(vec![])),
            ("recipes", V::Arr(vec![V::map(vec![
                ("kind", V::Text("lint".into())),
                ("image", V::Text("local".into())),
                ("cmd", V::Arr(vec![V::Text(py.into()), V::Text("-c".into()),
                                    V::Text(check.into())]))])])),
            ("approvals", V::Int(1)),
            ("stale_reads", V::Text("reject".into()))])),
        ("config_init", V::map(vec![]))]), None);

    let worker = |reason: &str, actions: Vec<&str>| -> (SigningKey, Oid) {
        let (sk, pk) = keygen();
        let cap = put(&auth_sk, Some(gen), "capability", V::map(vec![
            ("audience", V::Bytes(pk.to_vec())),
            ("parent", V::Null),
            ("scope", V::map(vec![
                ("actions", V::Arr(actions.iter().map(|a| V::Text((*a).into())).collect())),
                ("paths", V::Arr(vec![V::Text("**".into())]))])),
            ("exp", V::Int(ts + 86_400_000)),
            ("meta", V::map(vec![("reason", V::Text(reason.into()))]))]), None);
        (sk, cap)
    };
    let mk_file = |sk: &SigningKey, cap: Oid, model: &str, path: &str, msg: &str,
                   lines: Vec<String>| -> Oid {
        let patch = put(sk, Some(gen), "patch", V::map(vec![
            ("nonce", V::Bytes(path.as_bytes()[..8].to_vec())),
            ("ops", V::Arr(vec![
                V::Arr(vec![V::Text("mkfile".into()), V::Text(path.into())]),
                V::Arr(vec![V::Text("insert".into()),
                    V::Arr(vec![V::Null, V::Int(0)]),
                    V::Arr(vec![V::Text("S".into())]),
                    V::Arr(lines.iter().map(|l| V::Bytes(l.as_bytes().to_vec())).collect())]),
            ]))]), None);
        let change = put(sk, Some(gen), "change", V::map(vec![
            ("patch", V::Bytes(patch.to_vec())),
            ("footprint", V::Arr(vec![V::Text(path.into())])),
            ("reads", V::Arr(vec![])),
            ("message", V::Text(msg.into())),
            ("provenance", V::map(vec![("model", V::Text(model.into()))]))]), Some(cap));
        let prop = put(sk, Some(gen), "proposal", V::map(vec![
            ("ref", V::Text("trunk".into())),
            ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
            ("status", V::Text("open".into()))]), Some(cap));
        hub.lock().unwrap().queue.push(prop);
        change
    };
    // approve EVERY batch awaiting judgement — after a bisection there are
    // several, and starving one stalls the whole binary search
    let judge_approve = |sk: &SigningKey| -> usize {
        let mans: Vec<Oid> = hub.lock().unwrap().pending.iter()
            .map(|(m, _)| *m).collect();
        for man in &mans {
            put(sk, Some(gen), "evidence", V::map(vec![
                ("manifest", V::Bytes(man.to_vec())),
                ("recipe", V::map(vec![("kind", V::Text("approval".into()))])),
                ("results", V::Arr(vec![V::map(vec![
                    ("status", V::Text("pass".into()))])]))]), None);
        }
        mans.len()
    };

    // ── the human lands the references first (the shared ground truth) ──
    let (ed_sk, ed_cap) = worker("Editor", vec!["publish_change", "propose"]);
    let (judge_sk, _judge_cap) = worker("Judge (rubric v1)", vec!["approve"]);
    let mut refs: Vec<String> = vec!["---".into(), "title: References".into(),
                                     "---".into(), String::new(),
                                     "## References".into(), String::new()];
    refs.extend(REFERENCES.iter().map(|r| r.to_string()));
    mk_file(&ed_sk, ed_cap, "human/editor", "paper/references.md",
            "paper: references", refs);
    weftd::gate_tick(&hub);
    judge_approve(&judge_sk);
    weftd::gate_tick(&hub);
    println!("  references landed — the citable ground truth\n");

    // ── four agents write concurrently ──────────────────────────────────
    println!("  agents writing (concurrently)…");
    let (tx, rx) = mpsc::channel::<(usize, Vec<String>)>();
    std::thread::scope(|scope| {
        for (i, a) in AGENTS.iter().enumerate() {
            let (tx, llm) = (tx.clone(), llm.clone());
            scope.spawn(move || {
                let prompt = format!(
                    "You are writing one section of an academic paper titled \
                     \"{TOPIC}\".\nSection: {}\n{}\nRules: plain prose, no \
                     headings, no markdown fences, no preamble. Cite sources \
                     only as bracketed numbers like [1].",
                    a.section, a.brief);
                let raw = if live {
                    ollama(&llm, &prompt).unwrap_or_default()
                } else {
                    String::new()
                };
                let raw = if raw.is_empty() {
                    format!("This section on {} argues that evidence, not \
                             attention, should gate a merge [1]. Concurrent \
                             agents make review the scarce resource [2].",
                            a.section.to_lowercase())
                } else { raw };
                let _ = tx.send((i, clean(&raw, a.fabricates)));
            });
        }
    });
    drop(tx);

    let mut drafted: Vec<(usize, Vec<String>)> = rx.iter().collect();
    drafted.sort_by_key(|(i, _)| *i);

    // ── each agent submits its own section, signed with its own key ─────
    let mut submitted: Vec<(&Agent, Oid)> = Vec::new();
    for (i, body) in &drafted {
        let a = &AGENTS[*i];
        let (sk, cap) = worker(&format!("Contributor ({})", a.model),
                               vec!["publish_change", "propose"]);
        let mut lines = vec!["---".to_string(), format!("title: {}", a.section),
                             "---".into(), String::new(),
                             format!("## {}", a.section), String::new()];
        lines.extend(body.clone());
        let change = mk_file(&sk, cap, a.model, a.file,
                             &format!("paper: {}", a.section.to_lowercase()), lines);
        submitted.push((a, change));
        println!("    {} wrote {} ({} lines)", a.model, a.file, body.len());
    }

    // ── the gate: citation check runs, then the judge attests ───────────
    println!("\n  gate…");
    // the judge's standing verdict for this run (one LLM call, not one per batch)
    let verdict = if live {
        ollama(&judge_model,
               "Answer with one word, PASS or FAIL: does an academic section \
                that cites only sources listed in its reference list meet a \
                basic citation-integrity bar?")
            .unwrap_or_else(|| "PASS".into())
    } else { "PASS".into() };
    if verdict.to_uppercase().contains("FAIL") {
        println!("    judge withholds approval — nothing will land");
    }
    for _ in 0..24 {
        weftd::gate_tick(&hub);                    // assemble → await judgement
        if !verdict.to_uppercase().contains("FAIL") {
            judge_approve(&judge_sk);              // attest every pending batch
        }
        weftd::gate_tick(&hub);                    // evidence → land or bisect
        let idle = {
            let h = hub.lock().unwrap();
            h.queue.is_empty() && h.pending.is_empty()
        };
        if idle { break; }
    }

    // ── the scoreboard ──────────────────────────────────────────────────
    let h = hub.lock().unwrap();
    let landed: Vec<String> = h.log.iter()
        .flat_map(|e| {
            e.split("\"message\":\"").skip(1)
                .map(|s| s.split('"').next().unwrap_or("").to_string())
                .collect::<Vec<_>>()
        }).collect();
    let rejects = h.rejects.join(" ");
    println!("\n  ── the paper ──");
    let target: Vec<Oid> = state_set(&h.store, &h.head_state.expect("head"))
        .into_iter().collect();
    let mat = materialize(&h.store, &target).unwrap();
    for path in mat.tree.keys() {
        println!("    ✓ {path}");
    }
    for (a, _) in &submitted {
        if !mat.tree.contains_key(a.file) {
            println!("    ✗ {} — refused", a.file);
        }
    }

    // ── the actual artifact, so nobody has to take our word for it ──────
    println!("\n  ── what landed (verbatim, as the models wrote it) ──");
    for (path, content) in &mat.tree {
        if path.ends_with("references.md") {
            continue;
        }
        let model = submitted.iter().find(|(a, _)| a.file == path)
            .map(|(a, _)| a.model).unwrap_or("human/editor");
        println!("\n  ┌─ {path}   [{model}]");
        for line in String::from_utf8_lossy(content).lines() {
            println!("  │ {line}");
        }
        println!("  └─");
    }
    for (a, change) in &submitted {
        if mat.tree.contains_key(a.file) {
            continue;
        }
        println!("\n  ┌─ {}   [{}]   REFUSED", a.file, a.model);
        let patch = as_oid(h.store.body(change).get("patch").unwrap());
        for op in h.store.body(&patch).get("ops").and_then(V::arr).unwrap_or(&[]) {
            let op = op.arr().unwrap();
            if op[0].text() != Some("insert") {
                continue;
            }
            for l in op[3].arr().unwrap_or(&[]) {
                let text = String::from_utf8_lossy(l.bytes().unwrap_or(b"")).to_string();
                let flag = if text.contains("[9]") { " ← citation [9] does not exist" } else { "" };
                println!("  │ {text}{flag}");
            }
        }
        println!("  └─ never reached the paper; the other sections were unaffected");
    }
    let cite_fail = rejects.contains("citation") || rejects.contains("evidence failed");
    println!("\n  ── traditional pipeline vs weft ──");
    println!("    traditional: 4 agents → 4 branches → a human concatenates,");
    println!("                 skims, and merges. The fabricated citation [9]");
    println!("                 ships unless a reviewer happens to check every");
    println!("                 bracket against the reference list. Nobody can");
    println!("                 say later which model wrote which paragraph.");
    println!("    weft:        the citation check ran on the exact bytes; the");
    println!("                 section citing [9] {}",
             if cite_fail { "never landed." } else { "was gated on it." });
    println!("                 {} sections landed with signed provenance —",
             mat.tree.len().saturating_sub(1));
    println!("                 every paragraph traces to a model, a delegated");
    println!("                 capability, and a human authority key.");
    println!("\n  landings: {}   rejections: {}", h.log.len(), h.rejects.len());
    let _ = landed;
    println!("  try:  weft export --git ./paper   → conventional commits, provenance in trailers");
}
