"""swarm_demo — three concurrent agents (named after their models) work one
repo through a live weftd gate, across the Windows→WSL boundary.

Flow: genesis + inline policy → capability delegation chain → base landing →
three workers propose concurrently (two collide on quotes.txt EOF — the
same-anchor case; one edits authors.txt) → gate batches/serializes, runs the
pinned evidence recipe in its sandbox, certifies landings → light-client
verification re-materializes everything locally and checks manifest roots →
provenance drill from one line back to the authority key.
"""
import json, threading, time, sys, urllib.request
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from weft_core import (Store, keygen, make_obj, cbor_encode, H, START,
                       materialize, state_set)

BASE = "http://localhost:8747"
NOW = lambda: int(time.time() * 1000)
EXP = NOW() + 3600_000

CHECK_SRC = (
    "q=open('quotes.txt').read().splitlines()\n"
    "assert q and all(q), 'empty quote line'\n"
    "assert len(set(q))==len(q), 'duplicate quotes'\n"
    "a=open('authors.txt').read().splitlines()\n"
    "assert a, 'no authors'\n"
    "print('check-ok quotes=%d authors=%d'%(len(q),len(a)))\n")
RECIPE = {"kind": "test", "image": "local",
          "cmd": ["python3", "-c", CHECK_SRC], "env": b""}
POLICY = {"rules": [{"paths": ["**"],
                     "recipe_digests": [H(cbor_encode(RECIPE))],
                     "approvals": 0}],
          "recipes": [RECIPE], "stale_reads": "warn"}


def get(path):
    with urllib.request.urlopen(BASE + path) as r:
        return json.loads(r.read())


def post(path, raw: bytes):
    req = urllib.request.Request(BASE + path, data=raw,
                                 headers={"Content-Type": "application/cbor"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def fetch_obj(store: Store, oid: bytes):
    if oid in store:
        return store.get(oid)
    req = urllib.request.Request(f"{BASE}/obj/{oid.hex()}")
    with urllib.request.urlopen(req) as r:
        store.put(r.read())
    return store.get(oid)


def publish(store, priv, repo, typ, body, auth=None):
    oid, raw = make_obj(priv, repo, typ, body, auth)
    store.put(raw)
    post("/obj", raw)
    return oid


# ------------------------------------------------------------- setup --------
LOCAL = Store()
gate_pub = bytes.fromhex(get("/gatekey")["pub"])
auth_priv, auth_pub = keygen()                    # Pranab (authority, cold)
orch_priv, orch_pub = keygen()                    # orchestrator

gen_oid, gen_raw = make_obj(auth_priv, None, "genesis", {
    "name": "quotes-service", "authority": [auth_pub], "quorum": 1,
    "refs": {"trunk": {"gates": [gate_pub], "threshold": 1}},
    "policy_init": POLICY, "config_init": {}})
LOCAL.put(gen_raw); post("/obj", gen_raw)
REPO = gen_oid
print(f"genesis {gen_oid.hex()[:12]}…  (repo id)")

cap_auth = publish(LOCAL, auth_priv, REPO, "capability", {
    "audience": auth_pub, "parent": None,
    "scope": {"actions": ["publish_change", "propose"], "paths": ["**"]},
    "exp": EXP, "meta": {"reason": "bootstrap"}})
cap_orch = publish(LOCAL, auth_priv, REPO, "capability", {
    "audience": orch_pub, "parent": None,
    "scope": {"actions": ["publish_change", "propose", "delegate"],
              "paths": ["**"]},
    "exp": EXP, "meta": {"reason": "swarm orchestrator"}})

WORKERS = []
for model, paths in [("claude-fable-5", ["quotes.txt"]),
                     ("gpt-5.6-sol", ["quotes.txt"]),
                     ("qwen3.8-max", ["authors.txt"])]:
    priv, pub = keygen()
    cap = publish(LOCAL, orch_priv, REPO, "capability", {
        "audience": pub, "parent": cap_orch,
        "scope": {"actions": ["publish_change", "propose"], "paths": paths},
        "exp": NOW() + 600_000, "meta": {"reason": f"worker {model}"}})
    WORKERS.append({"model": model, "priv": priv, "pub": pub, "cap": cap})

# ------------------------------------------------- base landing (seq 0) -----
p1 = publish(LOCAL, auth_priv, REPO, "patch", {"nonce": b"base-mk\x00", "ops": [
    ["mkfile", "quotes.txt"], ["mkfile", "authors.txt"]]})
fid_q, fid_a = (p1, 0), (p1, 1)
p2 = publish(LOCAL, auth_priv, REPO, "patch", {"nonce": b"base-in\x00", "ops": [
    ["insert", [fid_q[0], fid_q[1]], list(START),
     [b"Talk is cheap. Show me the code."]],
    ["insert", [fid_a[0], fid_a[1]], list(START),
     [b"Linus Torvalds (temp bio: kernel person)"]]]})
c1 = publish(LOCAL, auth_priv, REPO, "change",
             {"patch": p1, "footprint": ["quotes.txt", "authors.txt"],
              "reads": [], "message": "scaffold files",
              "provenance": {"model": None}}, auth=cap_auth)
c2 = publish(LOCAL, auth_priv, REPO, "change",
             {"patch": p2, "footprint": ["quotes.txt", "authors.txt"],
              "reads": [], "message": "seed content",
              "provenance": {"model": None}}, auth=cap_auth)
prop = publish(LOCAL, auth_priv, REPO, "proposal",
               {"ref": "trunk", "base": None, "delta": [c1, c2],
                "evidence": [], "status": "open"}, auth=cap_auth)
post("/propose", LOCAL.raw[prop])
while get("/heads")["seq"] < 0:
    time.sleep(0.2)
print(f"base landed: seq 0")

# ------------------------------------------------------- worker swarm -------

def run_worker(w, results):
    ws = get("/workspace")
    priv, model = w["priv"], w["model"]
    if model == "qwen3.8-max":                    # edit: replace the bio line
        f = ws["files"]["authors.txt"]
        victim = f["line_ids"][0]
        ops = [["delete", [bytes.fromhex(f["fid"][0]), f["fid"][1]],
                [[bytes.fromhex(victim[0]), victim[1]]]],
               ["insert", [bytes.fromhex(f["fid"][0]), f["fid"][1]],
                [bytes.fromhex(victim[0]), victim[1]],
                [b"Linus Torvalds \xe2\x80\x94 created git for Linux; Weft is for the swarm."]]]
        footprint, readpath = ["authors.txt"], "authors.txt"
        msg = "rewrite Torvalds bio"
    else:
        f = ws["files"]["quotes.txt"]
        last = f["line_ids"][-1]
        quote = {"claude-fable-5":
                 b"State is a set; landing is a log. \xe2\x80\x94 RFC-0001",
                 "gpt-5.6-sol":
                 b"A local CAS is not a distributed CAS."}[model]
        ops = [["insert", [bytes.fromhex(f["fid"][0]), f["fid"][1]],
                [bytes.fromhex(last[0]), last[1]], [quote]]]
        footprint, readpath = ["quotes.txt"], "quotes.txt"
        msg = "append quote"
    p = publish(LOCAL, priv, REPO, "patch",
                {"nonce": model.encode()[:8].ljust(8, b"\x00"), "ops": ops})
    c = publish(LOCAL, priv, REPO, "change", {
        "patch": p, "footprint": footprint,
        "reads": [[readpath, bytes.fromhex(ws["files"][readpath]["digest"])]],
        "message": msg,
        "provenance": {"model": model, "session": H(model.encode()),
                       "prompt": H(b"demo")}}, auth=w["cap"])
    pr = publish(LOCAL, priv, REPO, "proposal",
                 {"ref": "trunk", "base": None, "delta": [c],
                  "evidence": [], "status": "open"}, auth=w["cap"])
    post("/propose", LOCAL.raw[pr])
    for _ in range(120):
        time.sleep(0.25)
        log = get("/log")
        landed = {ch["oid"] for e in log["log"] for ch in e["changes"]}
        if c.hex() in landed:
            results[model] = ("landed", c)
            return
    results[model] = ("TIMEOUT", c)


results = {}
threads = [threading.Thread(target=run_worker, args=(w, results))
           for w in WORKERS]
[t.start() for t in threads]
[t.join(timeout=40) for t in threads]

# --------------------------------------------------------- reporting --------
log = get("/log")
print("\n=== landing log ===")
for e in log["log"]:
    ev = ", ".join(f"{x['status']}:{x['out']}" for x in e["evidence"])
    print(f"seq {e['seq']}  changes={len(e['changes'])}  evidence[{ev}]")
    for ch in e["changes"]:
        print(f"   {ch['oid'][:10]}  model={ch['model'] or 'human/authority':<15}"
              f" footprint={ch['footprint']}  \"{ch['message']}\"")
    if e["markers"]:
        print(f"   order markers: {e['markers']}")
    if e["warnings"]:
        print(f"   warnings: {e['warnings']}")
if log["rejects"]:
    print("rejects:", json.dumps(log["rejects"], indent=1)[:600])

ws = get("/workspace")
print("\n=== quotes.txt (head) ===")
print(ws["files"]["quotes.txt"]["content"].rstrip())
print("=== authors.txt (head) ===")
print(ws["files"]["authors.txt"]["content"].rstrip())

# --- light-client verification (RFC §7.4): re-materialize locally, compare
#     manifest roots against the gate's published manifest object -----------
heads = get("/heads")
lnd = fetch_obj(LOCAL, bytes.fromhex(heads["landing"]))
man = fetch_obj(LOCAL, bytes(lnd["body"]["manifest"]))
st_oid = bytes(lnd["body"]["target_state"])
todo = [st_oid]
while todo:                                       # pull the state chain
    b = fetch_obj(LOCAL, todo.pop())["body"]
    for cch in b["add"]:
        ch = fetch_obj(LOCAL, bytes(cch))
        fetch_obj(LOCAL, bytes(ch["body"]["patch"]))
    if b["base"]:
        todo.append(bytes(b["base"]))
mat = materialize(LOCAL, state_set(LOCAL, st_oid))
ok = all(mat["manifest_body"][k] == man["body"][k]
         for k in ("tree_root", "file_map_root", "conflict_root", "clean"))
print(f"\nlight-client verification: {'PASS' if ok else 'FAIL'} "
      f"(local re-materialization matches gate manifest)")

# --- provenance drill: newest quotes.txt line → authority ------------------
lid = ws["files"]["quotes.txt"]["line_ids"][-1]
lid_patch = bytes.fromhex(lid[0])
chg = next(LOCAL.get(bytes(c)) for e in log["log"] for c in
           [bytes.fromhex(ch["oid"]) for ch in e["changes"]]
           if bytes(LOCAL.get(bytes(c))["body"]["patch"]) == lid_patch)
line_txt = ws["files"]["quotes.txt"]["content"].rstrip().splitlines()[-1]
print(f"\nprovenance of last line {json.dumps(line_txt)}:")
print(f"  line-id ({lid[0][:10]}…, {lid[1]}) → patch {lid_patch.hex()[:10]}…")
print(f"  → change by model={chg['body']['provenance']['model']} "
      f"key={chg['author'].hex()[:10]}…")
cap = chg["auth"]
while cap is not None:
    env = fetch_obj(LOCAL, bytes(cap))
    b = env["body"]
    root = " [AUTHORITY ROOT]" if b["parent"] is None else ""
    print(f"  → capability {bytes(cap).hex()[:10]}… issued by "
          f"{env['author'].hex()[:10]}… reason={b['meta']['reason']!r}{root}")
    cap = b["parent"]
print(f"  authority key present in genesis: "
      f"{fetch_obj(LOCAL, REPO)['body']['authority'][0].hex()[:10]}…")

fails = [m for m, (s, _) in results.items() if s != "landed"]
print(f"\nworkers landed: {len(results) - len(fails)}/3"
      + (f"  FAILED: {fails}" if fails else ""))
sys.exit(1 if fails or not ok else 0)
