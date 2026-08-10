"""weft_core — executable subset of RFC-0001 (Weft protocol, Draft v0.2).

Prototype fidelity notes:
- Hash: BLAKE2b-256 (stdlib) stands in for BLAKE3-256. Same shape, same role.
- Signatures: real Ed25519 via `cryptography`.
- Serialization: real deterministic CBOR (RFC 8949 core deterministic subset),
  implemented below — ints, bytes, text, arrays, maps, bool, null.
- Objects implemented: genesis, capability, intent, change, patch, state,
  manifest (computed), evidence, policy, landing, certificate.
- Not implemented (out of spike scope): revocation, amendment, lease,
  proposal-supersession, chunklist, sync framing, git bridge.
"""

from __future__ import annotations
import hashlib, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

CTX = b"weft/0.1"
START = ("S",)          # per-file pseudo-anchor


def H(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=32).digest()

# ---------------------------------------------------------------- CBOR ------

def cbor_encode(o) -> bytes:
    if o is None:
        return b"\xf6"
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if isinstance(o, int):
        if o >= 0:
            return _head(0, o)
        return _head(1, -1 - o)
    if isinstance(o, bytes):
        return _head(2, len(o)) + o
    if isinstance(o, str):
        b = o.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(o, (list, tuple)):
        return _head(4, len(o)) + b"".join(cbor_encode(x) for x in o)
    if isinstance(o, dict):
        items = [(cbor_encode(k), cbor_encode(v)) for k, v in o.items()]
        items.sort(key=lambda kv: kv[0])          # canonical: bytewise key order
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(f"cbor: unsupported {type(o)}")


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < (1 << (8 * size)):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("int too large")


def cbor_decode(b: bytes):
    v, i = _dec(b, 0)
    if i != len(b):
        raise ValueError("trailing bytes")
    return v


def _dec(b: bytes, i: int):
    ib = b[i]; major, ai = ib >> 5, ib & 0x1F; i += 1
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        size = 1 << (ai - 24)
        n = int.from_bytes(b[i:i + size], "big"); i += size
        if n < 24 or (size > 1 and n < (1 << (8 * (size >> 1)))):
            raise ValueError("non-minimal int encoding")
    else:
        raise ValueError(f"unsupported additional info {ai}")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        return b[i:i + n], i + n
    if major == 3:
        return b[i:i + n].decode("utf-8"), i + n
    if major == 4:
        out = []
        for _ in range(n):
            v, i = _dec(b, i); out.append(v)
        return out, i
    if major == 5:
        out, last = {}, None
        for _ in range(n):
            k, i = _dec(b, i)
            ek = cbor_encode(k)
            if last is not None and ek <= last:
                raise ValueError("non-canonical map order")
            last = ek
            v, i = _dec(b, i); out[k] = v
        return out, i
    if major == 7:
        return {20: False, 21: True, 22: None}[n], i
    raise ValueError(f"unsupported major {major}")

# ---------------------------------------------------------- envelopes -------

def keygen():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def make_obj(priv, repo, typ: str, body, auth=None, ts=None) -> tuple[bytes, bytes]:
    """Returns (oid, canonical bytes) of a signed envelope."""
    ts = int(time.time() * 1000) if ts is None else ts
    author = priv.public_key().public_bytes_raw()
    payload = H(CTX + (repo or b"") + typ.encode()
                + cbor_encode([1, ts, author, auth, body]))
    env = {"v": 1, "repo": repo, "type": typ, "ts": ts,
           "author": author, "auth": auth, "body": body,
           "sig": priv.sign(payload)}
    raw = cbor_encode(env)
    return H(raw), raw


def verify_obj(raw: bytes) -> dict:
    env = cbor_decode(raw)
    if cbor_encode(env) != raw:
        raise ValueError("non-canonical object bytes")
    payload = H(CTX + (env["repo"] or b"") + env["type"].encode()
                + cbor_encode([env["v"], env["ts"], env["author"],
                               env["auth"], env["body"]]))
    Ed25519PublicKey.from_public_bytes(env["author"]).verify(env["sig"], payload)
    return env


class Store:
    def __init__(self):
        self.raw: dict[bytes, bytes] = {}
        self.env: dict[bytes, dict] = {}

    def put(self, raw: bytes) -> bytes:
        env = verify_obj(raw)
        oid = H(raw)
        self.raw[oid], self.env[oid] = raw, env
        return oid

    def get(self, oid: bytes) -> dict:
        return self.env[oid]

    def __contains__(self, oid):
        return oid in self.env

# ------------------------------------------------------------- patches ------
# ops: ["mkfile", path] | ["insert", fid, anchor, [bytes,...]]
#      ["delete", fid, [id,...]] | ["rmfile", fid] | ["move", fid, path]
# ids: [patch_oid, ordinal] as 2-lists; anchor also ["S"] for START.


def patch_ids(patch_oid: bytes, body: dict):
    """Assign ordinals: walk ops, yield created ids in order (RFC §5.8)."""
    n = 0
    created = []
    for op in body["ops"]:
        if op[0] == "mkfile":
            created.append(("file", (patch_oid, n))); n += 1
        elif op[0] == "insert":
            for _ in op[3]:
                created.append(("line", (patch_oid, n))); n += 1
    return created


def patch_deps(body: dict) -> set[bytes]:
    """Intrinsic dependencies: creator patches of every referenced identity."""
    deps = set()
    for op in body["ops"]:
        if op[0] in ("insert", "delete", "rmfile", "move"):
            fid = op[1]
            deps.add(bytes(fid[0]))
        if op[0] == "insert" and tuple(op[2]) != START:
            deps.add(bytes(op[2][0]))
        if op[0] == "delete":
            for lid in op[2]:
                deps.add(bytes(lid[0]))
    return deps


def patch_paths(body: dict, fid_paths: dict) -> set[str]:
    """Touched paths, resolved against a base fid→path map (RFC §7.3 step 5)."""
    out = set()
    for op in body["ops"]:
        if op[0] == "mkfile":
            out.add(op[1])
        elif op[0] == "move":
            out.add(op[2])
            out.add(fid_paths.get(_fid(op[1]), op[2]))
        else:
            p = fid_paths.get(_fid(op[1]))
            if p:
                out.add(p)
    return out


def _fid(x):
    return (bytes(x[0]), x[1])

# ------------------------------------------------- states & closure ---------

def state_set(store: Store, state_oid: bytes) -> frozenset[bytes]:
    """Full change set of a delta-form state (walk base chain)."""
    out, cur = set(), state_oid
    while cur is not None:
        body = store.get(cur)["body"]
        out.update(bytes(c) for c in body["add"])
        cur = bytes(body["base"]) if body["base"] else None
    return frozenset(out)


def make_state(priv, repo, base_oid, add_changes, store: Store):
    body = {"base": base_oid, "add": sorted(add_changes),
            "summary": H((store.get(base_oid)["body"]["summary"] if base_oid
                          else b"") + cbor_encode(sorted(add_changes)))}
    return make_obj(priv, repo, "state", body)


def closure_ok(store: Store, changes: frozenset[bytes]) -> bool:
    patches = {bytes(store.get(c)["body"]["patch"]) for c in changes}
    for c in changes:
        pb = store.get(bytes(store.get(c)["body"]["patch"]))["body"]
        if not patch_deps(pb) <= patches:
            return False
    return True

# --------------------------------------------------- materialization --------
# RFC §6.2 agc/weft-rga-v1 + §6.3 conflict classification + §6.4 byte model.


def materialize(store: Store, changes: frozenset[bytes], _iter_order=None):
    """Pure function of the change SET. Returns dict with tree, file_map,
    conflicts, markers, line_index, manifest_body. `_iter_order` lets the
    fuzzer shuffle internal iteration to prove order-independence."""
    patches = {}                                  # patch_oid -> body
    for c in (_iter_order or sorted(changes)):
        p = bytes(store.get(c)["body"]["patch"])
        if p in patches:
            raise ValueError("patch claimed by two changes")
        patches[p] = store.get(p)["body"]

    files = {}          # fid -> {"claims":[(patch_oid,path)], "rm":set, ...}
    children = {}       # fid -> {anchor: [(patch_oid, ordinal, text)]}
    tombs = {}          # fid -> set(line id)
    edits_after_rm = []

    for poid in patches:                          # set-iteration; order-free
        body = patches[poid]
        n = 0
        for op in body["ops"]:
            kind = op[0]
            if kind == "mkfile":
                fid = (poid, n); n += 1
                files.setdefault(fid, {"claims": [], "rm": set()})
                files[fid]["claims"].append((poid, op[1]))
                children.setdefault(fid, {}); tombs.setdefault(fid, {})
            elif kind == "insert":
                fid = _fid(op[1])
                anchor = START if tuple(op[2]) == START else (bytes(op[2][0]), op[2][1])
                ch = children.setdefault(fid, {})
                for text in op[3]:
                    lid = (poid, n); n += 1
                    ch.setdefault(anchor, []).append((poid, lid[1], text))
                    anchor = lid                  # chain: next line anchors this one
            elif kind == "delete":
                fid = _fid(op[1])
                td = tombs.setdefault(fid, {})
                for l in op[2]:
                    td.setdefault((bytes(l[0]), l[1]), set()).add(poid)
            elif kind == "rmfile":
                files.setdefault(_fid(op[1]), {"claims": [], "rm": set()})
                files[_fid(op[1])]["rm"].add(poid)
            elif kind == "move":
                fid = _fid(op[1])
                files.setdefault(fid, {"claims": [], "rm": set()})
                files[fid]["claims"].append((poid, op[2]))

    conflicts, markers = [], []

    # --- per-file path resolution (RFC §6.3 tree conflicts) -----------------
    live_path, file_map = {}, {}
    for fid, meta in files.items():
        if meta["rm"]:
            file_map[fid] = None                  # tombstoned file
            editors = {p for a, cs in children.get(fid, {}).items()
                       for (p, _, _) in cs} - {fid[0]} - meta["rm"]
            if editors:                           # SPEC GAP (see findings)
                conflicts.append(["edit-rm", _idj(fid)])
            continue
        claims = sorted(meta["claims"])
        if len({c[1] for c in claims}) > 1:       # move-move divergence
            conflicts.append(["move-move", _idj(fid)])
        path = max(claims)[1] if claims else None # winner: highest patch oid
        file_map[fid] = path

    by_path = {}
    for fid, path in file_map.items():
        if path is not None:
            by_path.setdefault(path, []).append(fid)
    for path, fids in by_path.items():
        if len(fids) > 1:                         # same-path collision
            conflicts.append(["tree", path])
            for fid in sorted(fids)[1:]:          # deterministic rename
                file_map[fid] = f"{path}~{fid[0].hex()[:8]}"
    for fid, path in file_map.items():
        if path is not None:
            live_path[fid] = path

    # --- per-file RGA traversal (RFC §6.2) ----------------------------------
    tree, line_index = {}, {}
    for fid, path in live_path.items():
        ch = children.get(fid, {})
        dead = tombs.get(fid, {})                 # lid -> set(deleter poids)
        multi = {a for a, cs in ch.items() if len({p for p, _, _ in cs}) > 1}
        for _ in multi:                           # one marker per hot anchor
            markers.append(["order", path])       # advisory, not conflict
        for a, cs in ch.items():                  # RFC §6.3 edit-delete
            if a != START and a in dead and any(p not in dead[a]
                                                for p, _, _ in cs):
                conflicts.append(["edit-delete", path])
                break
        out, idx = [], []
        # descending patch-OID among siblings; a node's chain-children follow
        # it before its next sibling → classic RGA DFS.
        agenda = _rga_order(ch, dead)
        for lid, text, is_dead in agenda:
            if not is_dead:
                out.append(text); idx.append(lid)
        tree[path] = b"\n".join(out) + (b"\n" if out else b"")
        line_index[path] = idx

    manifest_body = {
        "algorithm": "weft-rga-v1",
        "tree_root": H(cbor_encode(sorted(
            [p, H(c)] for p, c in tree.items()))),
        "file_map_root": H(cbor_encode(sorted(
            [_idj(f), file_map[f] or "\x00TOMB"] for f in file_map))),
        "conflict_root": H(cbor_encode(sorted(conflicts))),
        "clean": not conflicts,
    }
    return {"tree": tree, "file_map": file_map, "conflicts": conflicts,
            "markers": sorted(markers), "line_index": line_index,
            "manifest_body": manifest_body}


def _rga_order(ch, dead):
    """Iterative DFS. Sibling visit order: patch-OID DESCENDING, ordinal
    ASCENDING within a patch (the spec pins only the former — see findings).
    Stack pop order is the reverse of push order, so we push the inverse key.
    Each child is immediately followed by its own subtree (chain + children).
    """
    push_key = lambda t: (t[0], -t[1])            # → pop = (oid desc, ord asc)
    out = []
    stack = sorted(ch.get(START, []), key=push_key)
    while stack:
        poid, ordn, text = stack.pop()
        lid = (poid, ordn)
        out.append((lid, text, lid in dead))
        stack.extend(sorted(ch.get(lid, []), key=push_key))
    return out


def _idj(fid):
    return [fid[0], fid[1]]

# --------------------------------------------------- capabilities -----------

def cap_chain_valid(store: Store, cap_oid, actor: bytes, action: str,
                    paths: set[str], authority: list[bytes], now_ms: int):
    """RFC §5.3: walk to an authority root; attenuation + expiry + action."""
    link = store.get(bytes(cap_oid))
    if link["body"]["audience"] != actor:
        return False, "audience mismatch"
    while True:
        b = link["body"]
        if now_ms > b["exp"]:
            return False, "expired"
        if action not in b["scope"]["actions"]:
            return False, f"action {action} not granted"
        if not all(_covered(p, b["scope"]["paths"]) for p in paths):
            return False, "path out of scope"
        if b["parent"] is None:
            return ((link["author"] in authority), "root not an authority key"
                    if link["author"] not in authority else "ok")
        parent = store.get(bytes(b["parent"]))
        if parent["body"]["audience"] != link["author"]:
            return False, "chain link broken"
        link = parent


def _covered(path: str, patterns: list[str]) -> bool:
    ok = False
    for pat in patterns:
        neg = pat.startswith("!")
        if _glob1(pat.lstrip("!"), path):
            ok = not neg
    return ok


def _glob1(pat: str, path: str) -> bool:
    if pat == "**":
        return True
    if pat.endswith("/**"):
        return path.startswith(pat[:-2]) or path == pat[:-3]
    return pat == path

# ------------------------------------------------------ policy gate ---------

def policy_requirements(policy_body, footprint: set[str]):
    req = {"recipes": set(), "approvals": 0}
    for rule in policy_body["rules"]:
        if any(_covered(p, rule["paths"]) for p in footprint):
            req["recipes"].update(bytes(r) for r in rule["recipe_digests"])
            req["approvals"] = max(req["approvals"], rule.get("approvals", 0))
    return req


def check_landing(store: Store, body, authority, gate_keys, now_ms,
                  stale_reads="reject"):
    """RFC §7.3 certification checklist (evidence *execution* is caller's
    job; this validates structure, chain, closure, footprint, reads).
    Returns (errors, warnings, materialization)."""
    errs, warns = [], []
    base = state_set(store, bytes(body["base_state"])) if body["base_state"] else frozenset()
    target = state_set(store, bytes(body["target_state"]))
    delta = {bytes(c) for c in body["delta"]}
    if not (base <= target and target == base | delta):
        errs.append("target != base ∪ delta (supersets only)")
    if not closure_ok(store, target):
        errs.append("dependency closure violated")
    base_mat = materialize(store, base) if base else {"line_index": {}, "tree": {}, "file_map": {}}
    mat = materialize(store, target)
    # §5.3: scope/footprint = path at base ∪ resulting path (covers files
    # created by sibling changes inside this very delta)
    fidp = {f: p for f, p in mat["file_map"].items() if p}
    fidp.update({f: p for f, p in base_mat["file_map"].items() if p})
    for c in sorted(delta):
        ch = store.get(c)
        pb = store.get(bytes(ch["body"]["patch"]))["body"]
        touched = patch_paths(pb, fidp)
        if touched != set(ch["body"]["footprint"]):
            errs.append(f"footprint mismatch on {c.hex()[:8]}")
        ok, why = cap_chain_valid(store, ch["auth"], ch["author"],
                                  "publish_change", touched, authority, now_ms)
        if not ok:
            errs.append(f"auth invalid on {c.hex()[:8]}: {why}")
        for rd in ch["body"].get("reads", []):
            path, digest = rd[0], bytes(rd[1])
            if path in base_mat["tree"] and H(base_mat["tree"][path]) != digest:
                (errs if stale_reads == "reject" else warns).append(
                    f"stale read of {path} in {c.hex()[:8]}")
    man = store.get(bytes(body["manifest"]))["body"]
    for k in ("tree_root", "file_map_root", "conflict_root", "clean"):
        if man.get(k) != mat["manifest_body"][k]:
            errs.append(f"manifest field {k} does not match re-materialization")
    if not mat["manifest_body"]["clean"]:
        errs.append("target state is conflicted")
    return errs, warns, mat
