//! Generality probe: **the artifact is not code.**
//!
//! Three agents write a handbook concurrently. The gate runs deterministic
//! checks (front-matter schema, no TODO markers, internal links resolve) as
//! executable evidence, and a *judge* agent — holding an `approve`
//! capability, signing with its own key — attests quality from OUTSIDE the
//! sandbox, which is where subjective evaluation belongs: gate-executed
//! recipes have no network, so an LLM judge is an independent attestor, not
//! a recipe. In a real deployment `judge_verdict()` is a model call against a
//! rubric; here it is deterministic so the example is reproducible.
//!
//! Run: cargo run --release -p weftd --example docs

use ed25519_dalek::SigningKey;
use weft_core::cbor::V;
use weft_core::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Stand-in for an LLM judge: a rubric over the prose. Real deployments swap
/// this for a model call — the point is WHERE it runs (an attestor with its
/// own key), not how it decides.
fn judge_verdict(text: &str) -> (bool, String) {
    let words = text.split_whitespace().count();
    if words < 25 {
        return (false, format!("too thin ({words} words) — rubric wants ≥25"));
    }
    if !text.contains("## ") {
        return (false, "no section structure".into());
    }
    (true, format!("clear, structured, {words} words"))
}

fn main() {
    let hub = weftd::new_hub();
    let gate_pub = hub.lock().unwrap().gate_pub;
    let (auth_sk, auth_pub) = keygen();
    let ts = weftd::now_ms();

    let put = |sk: &SigningKey, repo: Option<Oid>, typ: &str, body: V,
               auth: Option<Oid>| -> Oid {
        let (_, raw) = make_obj(sk, repo, typ, body, auth, weftd::now_ms());
        let mut h = hub.lock().unwrap();
        let oid = h.store.put(raw).expect("store");
        if typ == "genesis" {
            weftd::adopt_genesis(&mut h, &oid, true).expect("genesis");
        }
        oid
    };

    // deterministic, gate-executed evidence: schema + hygiene, no network
    let py = if cfg!(windows) { "python" } else { "python3" };
    let check = "import glob,sys,re\n\
        bad=[]\n\
        for f in glob.glob('handbook/*.md'):\n\
        \x20 t=open(f,encoding='utf-8').read()\n\
        \x20 if not t.startswith('---\\ntitle:'): bad.append(f+': missing front-matter title')\n\
        \x20 if 'TODO' in t: bad.append(f+': contains TODO')\n\
        \x20 for link in re.findall(r'\\]\\((handbook/[^)]+)\\)', t):\n\
        \x20  if link not in glob.glob('handbook/*.md'): bad.append(f+': dead link '+link)\n\
        print('doc-check:', 'ok' if not bad else bad)\n\
        sys.exit(1 if bad else 0)";

    let gen = put(&auth_sk, None, "genesis", V::map(vec![
        ("name", V::Text("agent-handbook".into())),
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
            // a judge verdict is required for every landing
            ("approvals", V::Int(1)),
            ("stale_reads", V::Text("reject".into()))])),
        ("config_init", V::map(vec![]))]), None);

    let worker = |model: &str, actions: Vec<&str>| -> (SigningKey, Oid) {
        let (sk, pk) = keygen();
        let cap = put(&auth_sk, Some(gen), "capability", V::map(vec![
            ("audience", V::Bytes(pk.to_vec())),
            ("parent", V::Null),
            ("scope", V::map(vec![
                ("actions", V::Arr(actions.iter()
                    .map(|a| V::Text((*a).into())).collect())),
                ("paths", V::Arr(vec![V::Text("**".into())]))])),
            ("exp", V::Int(ts + 86_400_000)),
            ("meta", V::map(vec![("reason", V::Text(model.into()))]))]), None);
        (sk, cap)
    };
    let writers = [
        ("claude-fable-5", "handbook/onboarding.md", "Onboarding",
         "New agents receive a scoped capability, never an account. Read your\nlease, open a workspace, and submit changes by line number. The gate\ndecides; nobody reviews your diff by hand."),
        ("gpt-5.6-sol", "handbook/evidence.md", "Evidence",
         "Evidence is a signed claim bound to exact materialized bytes. Recipes\nare pinned by digest so a worker cannot quietly swap the checker.\nDeterministic checks run in the gate; judgement comes from attestors."),
        ("qwen3.8-max", "handbook/revocation.md", "Revocation",
         "Capabilities expire by default and can be revoked at any moment.\nRevocation gates future certification only — already-certified history\nstays valid, so the ledger never rots when a key is rotated."),
    ];

    let mut proposed: Vec<(&str, Oid)> = Vec::new();
    for (model, path, title, body) in writers {
        let (sk, cap) = worker(model, vec!["publish_change", "propose"]);
        let mut lines = vec![
            V::Bytes(b"---".to_vec()),
            V::Bytes(format!("title: {title}").into_bytes()),
            V::Bytes(b"---".to_vec()),
            V::Bytes(b"".to_vec()),
            V::Bytes(format!("## {title}").into_bytes()),
            V::Bytes(b"".to_vec()),
        ];
        lines.extend(body.lines().map(|l| V::Bytes(l.as_bytes().to_vec())));
        let patch = put(&sk, Some(gen), "patch", V::map(vec![
            ("nonce", V::Bytes(path.as_bytes()[..8].to_vec())),
            ("ops", V::Arr(vec![
                V::Arr(vec![V::Text("mkfile".into()), V::Text(path.into())]),
                V::Arr(vec![V::Text("insert".into()),
                    V::Arr(vec![V::Null, V::Int(0)]),
                    V::Arr(vec![V::Text("S".into())]), V::Arr(lines)])]))]), None);
        let change = put(&sk, Some(gen), "change", V::map(vec![
            ("patch", V::Bytes(patch.to_vec())),
            ("footprint", V::Arr(vec![V::Text(path.into())])),
            ("reads", V::Arr(vec![])),
            ("message", V::Text(format!("handbook: {title}"))),
            ("provenance", V::map(vec![("model", V::Text(model.into()))]))]),
            Some(cap));
        let prop = put(&sk, Some(gen), "proposal", V::map(vec![
            ("ref", V::Text("trunk".into())),
            ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
            ("status", V::Text("open".into()))]), Some(cap));
        hub.lock().unwrap().queue.push(prop);
        proposed.push((path, change));
    }

    println!("agent handbook — the artifact is prose, not code\n");
    weftd::gate_tick(&hub);   // deterministic checks pass; awaits a judge
    let pending = hub.lock().unwrap().pending.len();
    println!("gate: doc-checks passed, {pending} batch awaiting a judge verdict");

    // ── the judge: its own key, its own trust root, outside the sandbox ──
    let (judge_sk, judge_cap) = worker("judge (rubric v1)", vec!["approve"]);
    let _ = judge_cap;
    // the judge attests THIS manifest — the exact bytes the gate assembled
    let manifest = hub.lock().unwrap().pending.first()
        .map(|(m, _)| *m).expect("a pending batch awaiting judgement");
    // judge each proposed section, then attest the batch
    let mut verdicts = Vec::new();
    for (path, _) in &proposed {
        let text = writers.iter().find(|(_, p, _, _)| p == path)
            .map(|(_, _, t, b)| format!("## {t}\n{b}")).unwrap();
        verdicts.push((*path, judge_verdict(&text)));
    }
    for (path, (ok, why)) in &verdicts {
        println!("  judge {path}: {} — {why}", if *ok { "PASS" } else { "FAIL" });
    }
    if verdicts.iter().all(|(_, (ok, _))| *ok) {
        put(&judge_sk, Some(gen), "evidence", V::map(vec![
            ("manifest", V::Bytes(manifest.to_vec())),
            ("recipe", V::map(vec![("kind", V::Text("approval".into()))])),
            ("results", V::Arr(vec![V::map(vec![
                ("status", V::Text("pass".into()))])]))]), None);
    }
    weftd::gate_tick(&hub);
    let seq = hub.lock().unwrap().seq;
    println!("\n✓ landed seq {seq}: three handbook sections, one certified landing");

    // ── a section that fails the deterministic check bounces ─────────────
    let (sk, cap) = worker("claude-fable-5", vec!["publish_change", "propose"]);
    let patch = put(&sk, Some(gen), "patch", V::map(vec![
        ("nonce", V::Bytes(b"todo0000".to_vec())),
        ("ops", V::Arr(vec![
            V::Arr(vec![V::Text("mkfile".into()), V::Text("handbook/policy.md".into())]),
            V::Arr(vec![V::Text("insert".into()),
                V::Arr(vec![V::Null, V::Int(0)]),
                V::Arr(vec![V::Text("S".into())]),
                V::Arr(vec![
                    V::Bytes(b"---".to_vec()),
                    V::Bytes(b"title: Policy".to_vec()),
                    V::Bytes(b"---".to_vec()),
                    V::Bytes(b"## Policy".to_vec()),
                    V::Bytes(b"TODO: write this section".to_vec())])])]))]), None);
    let change = put(&sk, Some(gen), "change", V::map(vec![
        ("patch", V::Bytes(patch.to_vec())),
        ("footprint", V::Arr(vec![V::Text("handbook/policy.md".into())])),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("handbook: Policy (unfinished)".into())),
        ("provenance", V::map(vec![("model", V::Text("claude-fable-5".into()))]))]),
        Some(cap));
    let prop = put(&sk, Some(gen), "proposal", V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
        ("status", V::Text("open".into()))]), Some(cap));
    hub.lock().unwrap().queue.push(prop);
    // give it an (over-eager) judge verdict so ONLY the doc-check can stop it
    weftd::gate_tick(&hub);
    {
        let h = hub.lock().unwrap();
        let man = h.pending.first().map(|(m, _)| *m);
        drop(h);
        if let Some(man) = man {
            put(&judge_sk, Some(gen), "evidence", V::map(vec![
                ("manifest", V::Bytes(man.to_vec())),
                ("recipe", V::map(vec![("kind", V::Text("approval".into()))])),
                ("results", V::Arr(vec![V::map(vec![
                    ("status", V::Text("pass".into()))])]))]), None);
            weftd::gate_tick(&hub);
        }
    }
    let h = hub.lock().unwrap();
    let stopped = h.seq == seq;
    println!("✗ unfinished section {} — the judge said yes; the deterministic\n  doc-check said no, and the gate is an AND",
             if stopped { "refused" } else { "LANDED (unexpected)" });
    println!("\nrejects: {}", h.rejects.len());
    println!("\nnothing in the protocol is code-shaped: the artifact is Markdown,\nthe evidence is a doc linter, the judgement is an attestor's signature.");
    println!("gate key {} · judge key {}", &hex(&gate_pub)[..8],
             &hex(&judge_sk.verifying_key().to_bytes())[..8]);
}
