//! Same agents, same work, two pipelines — and the artifacts to compare.
//!
//! For three workloads (a spreadsheet, a code module, a document) this runs
//! the identical set of agent contributions twice:
//!
//!   without-weft/  everything the agents produced, merged in arrival order,
//!                  the way a naive pipeline does it
//!   with-weft/     only what a verification gate let land
//!   gate.log       what the gate refused, and why
//!
//! Then it runs the SAME validator over both directories, so the difference
//! isn't a claim — it's an exit code. Artifacts are written to disk for
//! browsing.
//!
//!   cargo run --release -p weftd --example showcase [outdir]

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use weft_core::cbor::V;
use weft_core::*;

struct Contribution {
    model: &'static str,
    file: &'static str,
    lines: &'static [&'static str],
    /// the flawed one — realistic mistakes, not strawmen
    flawed: bool,
    why: &'static str,
}

struct Scenario {
    dir: &'static str,
    title: &'static str,
    /// files the human/editor lands first
    base: &'static [(&'static str, &'static [&'static str])],
    contributions: &'static [Contribution],
    /// the validator, run by the gate AND (afterwards) over both outputs
    checker: &'static str,
    checker_desc: &'static str,
}

// ── 1. a spreadsheet: four regions appended to one CSV ────────────────────
const SALES: Scenario = Scenario {
    dir: "sales-report",
    title: "Spreadsheet — four agents append regional sales to one CSV",
    base: &[("sales.csv", &["region,quarter,units,revenue_usd"])],
    contributions: &[
        Contribution { model: "claude-fable-5", file: "sales.csv", flawed: false,
            why: "",
            lines: &["north,2026-Q2,1840,412300.00", "north,2026-Q3,1912,437820.50"] },
        Contribution { model: "gpt-5.6-sol", file: "sales.csv", flawed: false,
            why: "",
            lines: &["south,2026-Q2,1120,268900.00", "south,2026-Q3,1204,291450.75"] },
        Contribution { model: "qwen3.8-max", file: "sales.csv", flawed: false,
            why: "",
            lines: &["west,2026-Q2,2310,588120.25", "west,2026-Q3,2402,617300.00"] },
        // the realistic failure: a different date format and a non-numeric cell
        Contribution { model: "local-drafter", file: "sales.csv", flawed: true,
            why: "Q2 2026 is not the agreed quarter format, and revenue is not a number",
            lines: &["east,Q2 2026,1450,approx 350k", "east,2026-Q3,1502,371200.00"] },
    ],
    checker_desc: "column count, quarter format YYYY-Qn, numeric units and revenue",
    checker: "import csv,sys,re\n\
        bad=[]\n\
        rows=list(csv.reader(open('sales.csv',encoding='utf-8')))\n\
        hdr=rows[0]\n\
        for i,r in enumerate(rows[1:],2):\n\
        \x20 if len(r)!=len(hdr): bad.append(f'row {i}: expected {len(hdr)} columns, got {len(r)}'); continue\n\
        \x20 if not re.fullmatch(r'\\d{4}-Q[1-4]', r[1]): bad.append(f'row {i}: quarter {r[1]!r} is not YYYY-Qn')\n\
        \x20 if not re.fullmatch(r'\\d+', r[2]): bad.append(f'row {i}: units {r[2]!r} is not an integer')\n\
        \x20 try: float(r[3])\n\
        \x20 except ValueError: bad.append(f'row {i}: revenue {r[3]!r} is not a number')\n\
        print('csv-check:', 'ok - '+str(len(rows)-1)+' rows' if not bad else '; '.join(bad))\n\
        sys.exit(1 if bad else 0)",
};

// ── 2. code: three agents extend a Python module ──────────────────────────
const CODE: Scenario = Scenario {
    dir: "api-client",
    title: "Code — three agents extend a client module (it must still import and pass tests)",
    base: &[
        ("client.py", &["\"\"\"Tiny HTTP client helpers.\"\"\"", "",
                        "BASE = \"https://api.example.com\"", "",
                        "",
                        "def build_url(path):",
                        "    return BASE.rstrip(\"/\") + \"/\" + path.lstrip(\"/\")", ""]),
        ("test_client.py", &["from client import build_url", "", "",
                             "def test_build_url():", "    assert build_url(\"/users\") == \"https://api.example.com/users\""]),
    ],
    contributions: &[
        Contribution { model: "claude-fable-5", file: "client.py", flawed: false, why: "",
            lines: &["def join_headers(**kw):",
                     "    return {k.replace(\"_\", \"-\").title(): str(v) for k, v in kw.items()}", ""] },
        Contribution { model: "gpt-5.6-sol", file: "client.py", flawed: false, why: "",
            lines: &["def with_query(url, **params):",
                     "    if not params:", "        return url",
                     "    q = \"&\".join(f\"{k}={v}\" for k, v in sorted(params.items()))",
                     "    return f\"{url}?{q}\"", ""] },
        // the realistic failure: a plausible-looking function that doesn't parse
        Contribution { model: "local-drafter", file: "client.py", flawed: true,
            why: "unbalanced parenthesis — the module no longer imports, so every test fails",
            lines: &["def retry(fn, attempts=3):",
                     "    for i in range(attempts):",
                     "        try:", "            return fn()",
                     "        except Exception:", "            continue",
                     "    raise RuntimeError(\"giving up after {} attempts\".format(attempts)",
                     ""] },
    ],
    checker_desc: "the module compiles and the test suite passes",
    checker: "import py_compile,subprocess,sys\n\
        try:\n\
        \x20 py_compile.compile('client.py', doraise=True)\n\
        except Exception as e:\n\
        \x20 print('code-check: client.py does not compile -', str(e).split('(')[0].strip()); sys.exit(1)\n\
        r=subprocess.run([sys.executable,'-c','import client; assert client.build_url(\"/users\")==\"https://api.example.com/users\"; print(\"code-check: ok - imports and tests pass\")'],capture_output=True,text=True)\n\
        print(r.stdout.strip() or ('code-check: '+r.stderr.strip().splitlines()[-1]))\n\
        sys.exit(r.returncode)",
};

// ── 3. a document: three agents write a policy brief ──────────────────────
const BRIEF: Scenario = Scenario {
    dir: "policy-brief",
    title: "Document — three agents write a brief; every claim must cite a listed source",
    base: &[
        ("sources.md", &["# Sources", "", "[1] Internal incident review, 2026-05.",
                         "[2] Platform SLO report, 2026-Q2.", "[3] Vendor security attestation, 2026-04."]),
        ("brief.md", &["# Incident response brief", ""]),
    ],
    contributions: &[
        Contribution { model: "claude-fable-5", file: "brief.md", flawed: false, why: "",
            lines: &["## Summary", "",
                     "Three of the four Q2 incidents began as configuration drift [1].",
                     "Detection time improved after the SLO review [2].", ""] },
        Contribution { model: "gpt-5.6-sol", file: "brief.md", flawed: false, why: "",
            lines: &["## Vendor exposure", "",
                     "The vendor's controls were attested in April [3]; no gaps",
                     "were material to the incidents reviewed here [1].", ""] },
        // the realistic failure: a confident claim with a source that doesn't exist
        Contribution { model: "local-drafter", file: "brief.md", flawed: true,
            why: "cites [7], which is not in sources.md — a fabricated reference",
            lines: &["## Recommendation", "",
                     "Industry benchmarks show a 40% reduction in mean time to",
                     "recovery after adopting this control [7].", ""] },
    ],
    checker_desc: "every bracketed citation resolves in sources.md",
    checker: "import re,sys\n\
        refs=set(re.findall(r'\\[(\\d+)\\]', open('sources.md',encoding='utf-8').read()))\n\
        bad=[c for c in re.findall(r'\\[(\\d+)\\]', open('brief.md',encoding='utf-8').read()) if c not in refs]\n\
        print('cite-check:', 'ok - all citations resolve' if not bad else 'fabricated citation(s): '+', '.join('['+c+']' for c in sorted(set(bad))))\n\
        sys.exit(1 if bad else 0)",
};

fn write_tree(dir: &Path, files: &[(String, Vec<u8>)]) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("mkdir");
    for (path, content) in files {
        let p = dir.join(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(p, content).expect("write");
    }
}

fn run_checker(dir: &Path, checker: &str) -> (bool, String) {
    let py = if cfg!(windows) { "python" } else { "python3" };
    let out = std::process::Command::new(py).args(["-c", checker])
        .current_dir(dir).output().expect("python");
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let text = if text.is_empty() {
        String::from_utf8_lossy(&out.stderr).trim().to_string()
    } else { text };
    (out.status.success(), text)
}

fn run_scenario(sc: &Scenario, out: &Path) -> (String, bool, bool) {
    let hub = weftd::new_hub();
    let gate_pub = hub.lock().unwrap().gate_pub;
    let (auth_sk, auth_pub) = keygen();
    let ts = weftd::now_ms();
    let py = if cfg!(windows) { "python" } else { "python3" };
    let put = |sk: &SigningKey, repo: Option<Oid>, typ: &str, body: V, auth: Option<Oid>| -> Oid {
        let (_, raw) = make_obj(sk, repo, typ, body, auth, weftd::now_ms());
        let mut h = hub.lock().unwrap();
        let oid = h.store.put(raw).expect("store");
        if typ == "genesis" { weftd::adopt_genesis(&mut h, &oid, true).expect("genesis"); }
        oid
    };
    let gen = put(&auth_sk, None, "genesis", V::map(vec![
        ("name", V::Text(sc.dir.into())),
        ("authority", V::Arr(vec![V::Bytes(auth_pub.to_vec())])),
        ("quorum", V::Int(1)),
        ("refs", V::map(vec![("trunk", V::map(vec![
            ("gates", V::Arr(vec![V::Bytes(gate_pub.to_vec())])),
            ("threshold", V::Int(1))]))])),
        ("policy_init", V::map(vec![
            ("rules", V::Arr(vec![])),
            ("recipes", V::Arr(vec![V::map(vec![
                ("kind", V::Text("test".into())),
                ("image", V::Text("local".into())),
                ("cmd", V::Arr(vec![V::Text(py.into()), V::Text("-c".into()),
                                    V::Text(sc.checker.into())]))])])),
            ("approvals", V::Int(0)),
            ("stale_reads", V::Text("warn".into()))])),
        ("config_init", V::map(vec![]))]), None);
    let worker = |reason: &str| -> (SigningKey, Oid) {
        let (sk, pk) = keygen();
        let cap = put(&auth_sk, Some(gen), "capability", V::map(vec![
            ("audience", V::Bytes(pk.to_vec())),
            ("parent", V::Null),
            ("scope", V::map(vec![
                ("actions", V::Arr(vec![V::Text("publish_change".into()),
                                        V::Text("propose".into())])),
                ("paths", V::Arr(vec![V::Text("**".into())]))])),
            ("exp", V::Int(ts + 86_400_000)),
            ("meta", V::map(vec![("reason", V::Text(reason.into()))]))]), None);
        (sk, cap)
    };
    let snapshot = || {
        let h = hub.lock().unwrap();
        let st = h.head_state.unwrap_or_else(|| panic!(
            "scenario '{}': the scaffold itself failed the checker — fix the base              files or the checker before comparing pipelines. rejects: {:?}",
            sc.dir, h.rejects));
        let target: Vec<Oid> = state_set(&h.store, &st).into_iter().collect();
        materialize(&h.store, &target).expect("materialize")
    };

    // base files, landed by the editor
    let (ed_sk, ed_cap) = worker("Editor");
    // SELF ordinals count every identity a patch creates, in op order — so
    // all the mkfiles must come first, or the second file's insert addresses
    // a line of the first one.
    let mut ops: Vec<V> = sc.base.iter()
        .map(|(path, _)| V::Arr(vec![V::Text("mkfile".into()), V::Text((*path).into())]))
        .collect();
    for (i, (_, lines)) in sc.base.iter().enumerate() {
        ops.push(V::Arr(vec![V::Text("insert".into()),
            V::Arr(vec![V::Null, V::Int(i as i64)]),
            V::Arr(vec![V::Text("S".into())]),
            V::Arr(lines.iter().map(|l| V::Bytes(l.as_bytes().to_vec())).collect())]));
    }
    let patch = put(&ed_sk, Some(gen), "patch", V::map(vec![
        ("nonce", V::Bytes(b"basebase".to_vec())), ("ops", V::Arr(ops))]), None);
    let change = put(&ed_sk, Some(gen), "change", V::map(vec![
        ("patch", V::Bytes(patch.to_vec())),
        ("footprint", V::Arr(sc.base.iter().map(|(p, _)| V::Text((*p).into())).collect())),
        ("reads", V::Arr(vec![])),
        ("message", V::Text("scaffold".into()))]), Some(ed_cap));
    let prop = put(&ed_sk, Some(gen), "proposal", V::map(vec![
        ("ref", V::Text("trunk".into())),
        ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
        ("status", V::Text("open".into()))]), Some(ed_cap));
    hub.lock().unwrap().queue.push(prop);
    weftd::gate_tick(&hub);

    // each contribution, appended to the end of its file
    for (n, c) in sc.contributions.iter().enumerate() {
        let m = snapshot();
        let (f, _) = m.file_map.iter()
            .find(|(_, p)| p.as_deref() == Some(c.file)).expect("file");
        let last = *m.line_index[c.file].last().expect("lines");
        let (sk, cap) = worker(&format!("Contributor ({})", c.model));
        let patch = put(&sk, Some(gen), "patch", V::map(vec![
            ("nonce", V::Bytes(format!("contr{n:03}").into_bytes())),
            ("ops", V::Arr(vec![V::Arr(vec![V::Text("insert".into()),
                V::Arr(vec![V::Bytes(f.0.to_vec()), V::Int(f.1)]),
                V::Arr(vec![V::Bytes(last.0.to_vec()), V::Int(last.1)]),
                V::Arr(c.lines.iter().map(|l| V::Bytes(l.as_bytes().to_vec())).collect())])]))]), None);
        let change = put(&sk, Some(gen), "change", V::map(vec![
            ("patch", V::Bytes(patch.to_vec())),
            ("footprint", V::Arr(vec![V::Text(c.file.into())])),
            ("reads", V::Arr(vec![])),
            ("message", V::Text(format!("{} contributes to {}", c.model, c.file))),
            ("provenance", V::map(vec![("model", V::Text(c.model.into()))]))]), Some(cap));
        let prop = put(&sk, Some(gen), "proposal", V::map(vec![
            ("ref", V::Text("trunk".into())),
            ("delta", V::Arr(vec![V::Bytes(change.to_vec())])),
            ("status", V::Text("open".into()))]), Some(cap));
        hub.lock().unwrap().queue.push(prop);
        for _ in 0..6 {
            weftd::gate_tick(&hub);
            if hub.lock().unwrap().queue.is_empty() { break; }
        }
    }

    // ── artifacts ───────────────────────────────────────────────────────
    let base_dir = out.join(sc.dir);
    let m = snapshot();
    let with: Vec<(String, Vec<u8>)> = m.tree.iter()
        .map(|(p, c)| (p.clone(), c.clone())).collect();
    write_tree(&base_dir.join("with-weft"), &with);

    // the naive pipeline: base + EVERY contribution, in arrival order
    let mut naive: Vec<(String, Vec<u8>)> = sc.base.iter()
        .map(|(p, lines)| ((*p).to_string(),
             lines.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n").into_bytes()))
        .collect();
    for c in sc.contributions {
        if let Some((_, buf)) = naive.iter_mut().find(|(p, _)| p == c.file) {
            buf.push(b'\n');
            buf.extend(c.lines.join("\n").as_bytes());
        }
    }
    for (_, buf) in naive.iter_mut() { buf.push(b'\n'); }
    write_tree(&base_dir.join("without-weft"), &naive);

    // ── the same validator over both ────────────────────────────────────
    let (with_ok, with_msg) = run_checker(&base_dir.join("with-weft"), sc.checker);
    let (naive_ok, naive_msg) = run_checker(&base_dir.join("without-weft"), sc.checker);
    for d in ["with-weft", "without-weft"] {   // the checker may leave bytecode
        let _ = std::fs::remove_dir_all(base_dir.join(d).join("__pycache__"));
    }

    let h = hub.lock().unwrap();
    let mut log = String::new();
    log.push_str(&format!("# {}\n#\n# checker: {}\n\n", sc.title, sc.checker_desc));
    log.push_str("## what the gate did\n\n");
    for e in &h.log {
        let seq = e.split("\"seq\":").nth(1).and_then(|s| s.split(',').next()).unwrap_or("?");
        let msgs: Vec<&str> = e.split("\"message\":\"").skip(1)
            .filter_map(|s| s.split('"').next()).collect();
        log.push_str(&format!("LANDED  seq {seq}  {}\n", msgs.join(" · ")));
    }
    for r in &h.rejects {
        log.push_str(&format!("REFUSED {r}\n"));
    }
    log.push_str(&format!("\n## the same checker, run over each output\n\n\
        without-weft/  {}  {naive_msg}\nwith-weft/     {}  {with_msg}\n",
        if naive_ok { "PASS" } else { "FAIL" }, if with_ok { "PASS" } else { "FAIL" }));
    for c in sc.contributions.iter().filter(|c| c.flawed) {
        log.push_str(&format!("\n# the flawed contribution came from {} — {}\n", c.model, c.why));
    }
    std::fs::write(base_dir.join("gate.log"), &log).expect("write log");
    (log, naive_ok, with_ok)
}

fn main() {
    let out: PathBuf = std::env::args().nth(1)
        .unwrap_or_else(|| "docs/showcase".into()).into();
    println!("weft · same agents, same work, two pipelines\n");
    let mut rows = Vec::new();
    for sc in [&SALES, &CODE, &BRIEF] {
        let (_, naive_ok, with_ok) = run_scenario(sc, &out);
        println!("  {}", sc.title);
        println!("     without weft: {}   with weft: {}",
                 if naive_ok { "PASS" } else { "FAIL — the flaw shipped" },
                 if with_ok { "PASS" } else { "FAIL" });
        println!("     artifacts: {}/{}/{{without-weft,with-weft}}/ + gate.log\n",
                 out.display(), sc.dir);
        rows.push((sc.title, naive_ok, with_ok));
    }
    let shipped = rows.iter().filter(|(_, n, _)| !n).count();
    let clean = rows.iter().filter(|(_, _, w)| *w).count();
    println!("  ── summary ──");
    println!("  {shipped}/{} unguarded outputs failed their own validator", rows.len());
    println!("  {clean}/{} gated outputs passed it", rows.len());
    println!("\n  The agents were identical in both columns. The only difference");
    println!("  is whether anything checked before the work became the artifact.");
}
