fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port: u16 = args.iter().find_map(|a| a.parse().ok()).unwrap_or(8747);
    let flag = |name: &str| args.iter().position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned());

    let hub = match flag("--data") {
        Some(path) => {
            let (hub, replayed) = weftd::new_hub_persistent(std::path::Path::new(&path))
                .unwrap_or_else(|e| { eprintln!("weftd: cannot open {path}: {e}"); std::process::exit(1) });
            eprintln!("weftd: persistent store {path} — {replayed} objects replayed");
            hub
        }
        None => weftd::new_hub(),
    };
    if args.iter().any(|a| a == "--demo") {
        if hub.lock().unwrap().repo.is_none() {
            weftd::seed_demo(&hub);
            eprintln!("weftd: demo scenario seeded");
        } else {
            eprintln!("weftd: demo skip — store already has a repository");
        }
    }
    if args.iter().any(|a| a == "--readonly") {
        hub.lock().unwrap().readonly = true;
        eprintln!("weftd: read-only mode — all POST routes disabled");
    }
    let sandbox = flag("--sandbox").unwrap_or("auto".into());
    let mode = match sandbox.as_str() {
        "none" => "none".to_string(),
        "unshare" => "unshare".to_string(),
        _ => if weftd::sandbox_available() { "unshare".into() } else { "none".into() },
    };
    let readonly = hub.lock().unwrap().readonly;
    if mode == "none" && sandbox != "none" && !readonly {
        eprintln!("weftd: WARNING — no sandbox available (unshare userns); \
                   evidence recipes run unconfined. Do not expose a writable \
                   hub publicly in this state (RFC §12.5).");
    } else if readonly && mode == "none" {
        eprintln!("weftd: evidence sandbox = none (read-only hub executes nothing)");
    } else {
        eprintln!("weftd: evidence sandbox = {mode}");
    }
    hub.lock().unwrap().sandbox = mode;

    let gate = hub.lock().unwrap().gate_pub;
    println!("weftd listening on 0.0.0.0:{port}  gate={}",
             gate.iter().map(|b| format!("{b:02x}")).collect::<String>());
    weftd::serve(port, hub);
}
