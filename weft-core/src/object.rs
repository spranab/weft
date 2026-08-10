//! Signed content-addressed envelopes and the object store (RFC §4).
//! Sign first (over the pre-`sig` fields with domain separation), then
//! OID = blake3 of the complete signed envelope. `repo: null` only on genesis.

use crate::cbor::{decode, encode, CborError, V};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;

pub const CTX: &[u8] = b"weft/0.1";
pub type Oid = [u8; 32];

pub fn h(b: &[u8]) -> Oid {
    *blake3::hash(b).as_bytes()
}

pub fn keygen() -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

fn sig_payload(repo: &V, typ: &str, ts: i64, author: &[u8], auth: &V, body: &V) -> Oid {
    let repo_bytes = repo.bytes().unwrap_or(b"");
    let inner = encode(&V::Arr(vec![
        V::Int(1),
        V::Int(ts),
        V::Bytes(author.to_vec()),
        auth.clone(),
        body.clone(),
    ]));
    let mut buf = Vec::with_capacity(CTX.len() + repo_bytes.len() + typ.len() + inner.len());
    buf.extend(CTX);
    buf.extend(repo_bytes);
    buf.extend(typ.as_bytes());
    buf.extend(inner);
    h(&buf)
}

/// The 32-byte digest an author signs (RFC §4) — exposed so remote signers
/// (e.g. a browser holding the key) can sign without shipping the key.
pub fn sig_payload_hash(repo: Option<Oid>, typ: &str, ts: i64, author: &[u8],
                        auth: Option<Oid>, body: &V) -> Oid {
    let repo_v = repo.map(|r| V::Bytes(r.to_vec())).unwrap_or(V::Null);
    let auth_v = auth.map(|a| V::Bytes(a.to_vec())).unwrap_or(V::Null);
    sig_payload(&repo_v, typ, ts, author, &auth_v, body)
}

/// Assemble a canonical envelope from parts + an externally produced
/// signature. Verification happens at `Store::put`.
pub fn assemble_obj(repo: Option<Oid>, typ: &str, ts: i64, author: &[u8],
                    auth: Option<Oid>, body: V, sig: &[u8]) -> (Oid, Vec<u8>) {
    let env = V::map(vec![
        ("v", V::Int(1)),
        ("repo", repo.map(|r| V::Bytes(r.to_vec())).unwrap_or(V::Null)),
        ("type", V::Text(typ.into())),
        ("ts", V::Int(ts)),
        ("author", V::Bytes(author.to_vec())),
        ("auth", auth.map(|a| V::Bytes(a.to_vec())).unwrap_or(V::Null)),
        ("body", body),
        ("sig", V::Bytes(sig.to_vec())),
    ]);
    let raw = encode(&env);
    (h(&raw), raw)
}

pub fn make_obj(sk: &SigningKey, repo: Option<Oid>, typ: &str, body: V, auth: Option<Oid>,
                ts: i64) -> (Oid, Vec<u8>) {
    let repo_v = repo.map(|r| V::Bytes(r.to_vec())).unwrap_or(V::Null);
    let auth_v = auth.map(|a| V::Bytes(a.to_vec())).unwrap_or(V::Null);
    let author = sk.verifying_key().to_bytes();
    let payload = sig_payload(&repo_v, typ, ts, &author, &auth_v, &body);
    let sig = sk.sign(&payload);
    let env = V::map(vec![
        ("v", V::Int(1)),
        ("repo", repo_v),
        ("type", V::Text(typ.into())),
        ("ts", V::Int(ts)),
        ("author", V::Bytes(author.to_vec())),
        ("auth", auth_v),
        ("body", body),
        ("sig", V::Bytes(sig.to_bytes().to_vec())),
    ]);
    let raw = encode(&env);
    (h(&raw), raw)
}

pub fn verify_obj(raw: &[u8]) -> Result<V, CborError> {
    let env = decode(raw)?;
    if encode(&env) != raw {
        return Err(CborError("non-canonical object bytes".into()));
    }
    let get = |k: &str| env.get(k).ok_or_else(|| CborError(format!("missing {k}")));
    let typ = get("type")?.text().ok_or_else(|| CborError("type not text".into()))?;
    let ts = get("ts")?.int().ok_or_else(|| CborError("ts not int".into()))?;
    let author = get("author")?.bytes().ok_or_else(|| CborError("author not bytes".into()))?;
    let payload = sig_payload(get("repo")?, typ, ts, author, get("auth")?, get("body")?);
    let vk = VerifyingKey::from_bytes(author.try_into()
        .map_err(|_| CborError("bad author key length".into()))?)
        .map_err(|e| CborError(format!("bad author key: {e}")))?;
    let sig_bytes: &[u8] = get("sig")?.bytes().ok_or_else(|| CborError("sig not bytes".into()))?;
    let sig = Signature::from_bytes(sig_bytes.try_into()
        .map_err(|_| CborError("bad sig length".into()))?);
    vk.verify(&payload, &sig).map_err(|e| CborError(format!("bad signature: {e}")))?;
    Ok(env)
}

#[derive(Default)]
pub struct Store {
    pub raw: HashMap<Oid, Vec<u8>>,
    pub env: HashMap<Oid, V>,
}

impl Store {
    pub fn put(&mut self, raw: Vec<u8>) -> Result<Oid, CborError> {
        let env = verify_obj(&raw)?;
        let oid = h(&raw);
        self.raw.insert(oid, raw);
        self.env.insert(oid, env);
        Ok(oid)
    }
    pub fn get(&self, oid: &Oid) -> &V {
        &self.env[oid]
    }
    pub fn body(&self, oid: &Oid) -> &V {
        self.env[oid].get("body").expect("envelope has body")
    }
    pub fn contains(&self, oid: &Oid) -> bool {
        self.env.contains_key(oid)
    }
}

pub fn as_oid(v: &V) -> Oid {
    v.bytes().expect("oid bytes").try_into().expect("32-byte oid")
}
