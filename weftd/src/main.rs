fn main() {
    let port: u16 = std::env::args().nth(1)
        .and_then(|p| p.parse().ok()).unwrap_or(8747);
    let hub = weftd::new_hub();
    let gate = hub.lock().unwrap().gate_pub;
    println!("weftd listening on 127.0.0.1:{port}  gate={}",
             gate.iter().map(|b| format!("{b:02x}")).collect::<String>());
    weftd::serve(port, hub);
}
