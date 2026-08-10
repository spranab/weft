fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port: u16 = args.iter().find_map(|a| a.parse().ok()).unwrap_or(8747);
    let hub = weftd::new_hub();
    if args.iter().any(|a| a == "--demo") {
        weftd::seed_demo(&hub);
        eprintln!("weftd: demo scenario seeded");
    }
    if args.iter().any(|a| a == "--readonly") {
        hub.lock().unwrap().readonly = true;
        eprintln!("weftd: read-only mode — all POST routes disabled");
    }
    let gate = hub.lock().unwrap().gate_pub;
    println!("weftd listening on 0.0.0.0:{port}  gate={}",
             gate.iter().map(|b| format!("{b:02x}")).collect::<String>());
    weftd::serve(port, hub);
}
