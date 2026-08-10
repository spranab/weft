//! Multi-node replication (RFC §8). A follower pulls a peer's objects and
//! then **verifies rather than trusts**: it re-derives the certified landing
//! chain locally, re-materializing every state and re-running the §7.3
//! checklist, so a forged landing, a landing signed by a non-gate key, or a
//! fork can never advance the head. Objects are self-verifying on store, so
//! the transport is deliberately dumb: "give me the oids you have," fetch the
//! ones we lack, then reconstruct.

use crate::Hub;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use weft_core::cbor::V;
use weft_core::*;

/// Result of verifying the certified landing chain from genesis forward.
pub struct Chain {
    pub head: Option<Oid>,
    pub head_state: Option<Oid>,
    pub seq: i64,
    pub log: Vec<String>,
    pub fork: Option<String>,
}

fn gate_set(hub: &Hub) -> (BTreeSet<Vec<u8>>, i64) {
    let repo = match hub.repo {
        Some(r) => r,
        None => return (BTreeSet::new(), 1),
    };
    let g = hub.store.body(&repo).get("refs").and_then(|r| r.get("trunk"));
    let gates: BTreeSet<Vec<u8>> = g.and_then(|t| t.get("gates")).and_then(V::arr)
        .unwrap_or(&[]).iter().filter_map(|k| k.bytes().map(|b| b.to_vec())).collect();
    let threshold = g.and_then(|t| t.get("threshold")).and_then(V::int).unwrap_or(1);
    (gates, threshold)
}

/// Re-derive the head by walking certified landings from seq 0 forward. Never
/// trusts a peer's claimed head — each step is re-verified locally.
pub fn verify_landing_chain(hub: &Hub) -> Chain {
    let mut chain = Chain { head: None, head_state: None, seq: -1, log: vec![], fork: None };
    if hub.repo.is_none() {
        return chain;
    }
    let (gates, threshold) = gate_set(hub);
    let stale = hub.policy.as_ref().and_then(|p| p.get("stale_reads"))
        .and_then(V::text).unwrap_or("reject").to_string();

    // index: subject landing oid → distinct gate keys that certified it
    let mut certs: BTreeMap<Oid, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut landings: Vec<Oid> = Vec::new();
    for (oid, env) in &hub.store.env {
        match env.get("type").and_then(V::text) {
            Some("landing") => landings.push(*oid),
            Some("certificate") => {
                let author = env.get("author").and_then(V::bytes).unwrap_or(&[]).to_vec();
                if gates.contains(&author) {
                    if let Some(subj) = env.get("body").and_then(|b| b.get("subject")) {
                        if let Some(b) = subj.bytes() {
                            if let Ok(s) = Oid::try_from(b) {
                                certs.entry(s).or_default().insert(author);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let certified = |l: &Oid| certs.get(l).map(|s| s.len() as i64 >= threshold).unwrap_or(false);

    let verify = |l: &Oid, expect_seq: i64, expect_prev: &V, expect_base: &V| -> bool {
        let env = &hub.store.env[l];
        // authored by a gate key, and quorum-certified
        if !gates.contains(env.get("author").and_then(V::bytes).unwrap_or(&[])) {
            return false;
        }
        if !certified(l) {
            return false;
        }
        let body = env.get("body").unwrap();
        if body.get("seq").and_then(V::int) != Some(expect_seq) {
            return false;
        }
        if body.get("prev").unwrap_or(&V::Null) != expect_prev {
            return false;
        }
        if body.get("base_state").unwrap_or(&V::Null) != expect_base {
            return false;
        }
        // authorization is frozen at CERTIFICATION time (finding A6): verify
        // with the landing's own envelope ts, and with no later revocations
        let ts = env.get("ts").and_then(V::int).unwrap_or(0);
        let chk = check_landing_r(&hub.store, body, &hub.authority, ts, &stale,
                                  &BTreeSet::new());
        if !chk.errors.is_empty() {
            return false;
        }
        // evidence: every referenced non-approval evidence must be bound to
        // this manifest and pass; approvals must meet the policy bar
        let man = body.get("manifest").and_then(V::bytes).map(|b| b.to_vec());
        let need = hub.policy.as_ref().and_then(|p| p.get("approvals"))
            .and_then(V::int).unwrap_or(0);
        let mut approvals = 0i64;
        for e in body.get("evidence").and_then(V::arr).unwrap_or(&[]) {
            let Some(ev) = e.bytes().and_then(|b| Oid::try_from(b).ok())
                .and_then(|o| hub.store.env.get(&o)) else { return false };
            let eb = ev.get("body").unwrap();
            if eb.get("manifest").and_then(V::bytes).map(|b| b.to_vec()) != man {
                return false;
            }
            let kind = eb.get("recipe").and_then(|r| r.get("kind")).and_then(V::text);
            if kind == Some("approval") {
                approvals += 1;
            } else {
                let all_pass = eb.get("results").and_then(V::arr).unwrap_or(&[]).iter()
                    .all(|r| r.get("status").and_then(V::text) == Some("pass"));
                if !all_pass {
                    return false;
                }
            }
        }
        approvals >= need
    };

    let (mut prev, mut base) = (V::Null, V::Null);
    let mut seq = 0i64;
    loop {
        let candidates: Vec<Oid> = landings.iter().copied()
            .filter(|l| verify(l, seq, &prev, &base)).collect();
        match candidates.len() {
            0 => break,
            1 => {
                let l = candidates[0];
                let body = hub.store.body(&l).clone();
                let st = as_oid(body.get("target_state").unwrap());
                chain.head = Some(l);
                chain.head_state = Some(st);
                chain.seq = seq;
                let delta: Vec<Oid> = body.get("delta").and_then(V::arr).unwrap_or(&[])
                    .iter().map(as_oid).collect();
                let changes: Vec<String> = delta.iter()
                    .map(|c| crate::chg_json(&hub.store, c)).collect();
                chain.log.push(format!(
                    "{{\"seq\":{seq},\"landing\":\"{}\",\"markers\":0,\"warnings\":[],\"changes\":[{}]}}",
                    crate::hex(&l), changes.join(",")));
                prev = V::Bytes(l.to_vec());
                base = V::Bytes(st.to_vec());
                seq += 1;
            }
            _ => {
                // two certified landings at the same (prev, seq): a fork. A
                // CP trunk does not pick arbitrarily — stop and flag it.
                chain.fork = Some(format!(
                    "fork at seq {seq}: {} certified candidates", candidates.len()));
                break;
            }
        }
    }
    chain
}

// ------------------------------------------------------------ follower -----

fn http_get(host: &str, port: u16, path: &str) -> Result<(u16, Vec<u8>), String> {
    let mut s = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).map_err(|e| e.to_string())?;
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n")
        .ok_or("malformed response")? + 4;
    let code = std::str::from_utf8(&resp[..split]).ok()
        .and_then(|h| h.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok()).ok_or("bad status")?;
    Ok((code, resp[split..].to_vec()))
}

fn parse_url(url: &str) -> (String, u16) {
    let hp = url.trim_start_matches("http://").trim_end_matches('/');
    let (h, p) = hp.split_once(':').unwrap_or((hp, "8747"));
    (h.to_string(), p.parse().unwrap_or(8747))
}

/// Pull from a peer once: bootstrap genesis if needed, fetch every object we
/// lack, then re-verify the certified chain and adopt the verified head.
/// Returns the number of objects newly stored.
pub fn pull(hub: &crate::Shared, peer_url: &str) -> Result<usize, String> {
    let (host, port) = parse_url(peer_url);

    // 1. learn the peer's repo (genesis oid); bootstrap it if we're empty
    let (_, pbody) = http_get(&host, port, "/policy")?;
    let policy: serde_json::Value = serde_json::from_slice(&pbody).map_err(|e| e.to_string())?;
    let repo_hex = policy["repo"].as_str().ok_or("peer has no repository")?;
    let repo: Oid = (0..64).step_by(2)
        .map(|i| u8::from_str_radix(&repo_hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>().map_err(|e| e.to_string())?
        .try_into().map_err(|_| "bad repo oid")?;
    {
        let mut h = hub.lock().unwrap();
        if let Some(local) = h.repo {
            if local != repo {
                return Err("peer serves a different repository (genesis mismatch)".into());
            }
        } else {
            let (_, raw) = http_get(&host, port, &format!("/obj/{repo_hex}"))?;
            let oid = h.store.put(raw).map_err(|e| e.to_string())?;
            h.replica = true;   // a follower verifies; it never certifies
            crate::adopt_genesis(&mut h, &oid, false)?;
        }
    }

    // 2. diff oids, fetch what we lack (each put re-verifies the signature)
    let (_, obody) = http_get(&host, port, "/oids")?;
    let oids: serde_json::Value = serde_json::from_slice(&obody).map_err(|e| e.to_string())?;
    let mut fetched = 0usize;
    for o in oids["oids"].as_array().ok_or("bad /oids")? {
        let hexs = o.as_str().ok_or("oid not string")?;
        let oid: Oid = (0..64).step_by(2)
            .filter_map(|i| u8::from_str_radix(&hexs[i..i + 2], 16).ok())
            .collect::<Vec<u8>>().try_into().map_err(|_| "bad oid")?;
        if hub.lock().unwrap().store.contains(&oid) {
            continue;
        }
        let (code, raw) = http_get(&host, port, &format!("/obj/{hexs}"))?;
        if code != 200 {
            continue;
        }
        let mut h = hub.lock().unwrap();
        if let Ok(stored) = h.store.put(raw) {
            fetched += 1;
            // apply genesis/revocation side-effects as they arrive
            if matches!(h.store.env[&stored].get("type").and_then(V::text),
                        Some("revocation")) {
                let _ = crate::apply_side_effects(&mut h, &stored);
            }
        }
    }

    // 3. re-verify the certified chain locally and adopt the verified head
    let chain = verify_landing_chain(&hub.lock().unwrap());
    if let Some(fork) = &chain.fork {
        let mut h = hub.lock().unwrap();
        h.rejects.push(format!("{{\"sync\":\"{}\"}}", crate::jesc(fork)));
    }
    {
        let mut h = hub.lock().unwrap();
        if chain.seq > h.seq {
            h.head = chain.head;
            h.head_state = chain.head_state;
            h.seq = chain.seq;
            h.log = chain.log;
        }
    }
    Ok(fetched)
}

/// Background replication: pull from the peer every `interval` seconds.
pub fn follow(hub: crate::Shared, peer_url: String, interval: u64) {
    std::thread::spawn(move || loop {
        if let Err(e) = pull(&hub, &peer_url) {
            eprintln!("weftd: sync from {peer_url} failed: {e}");
        }
        std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
    });
}
