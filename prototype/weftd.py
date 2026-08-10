"""weftd — minimal Weft hub: object store + trunk gate + merge queue.

Runs the RFC §7 loop for real: proposals arrive, the gate batches
footprint-disjoint ones, fixes the target state, re-materializes, verifies
the §7.3 checklist, executes the policy-pinned evidence recipe in a scratch
sandbox, then signs a landing + certificate (threshold 1).

Bootstrap note (implementation finding W3): genesis carries its initial
policy INLINE, not by OID — a policy object's envelope must bind `repo`
(the genesis OID), so genesis referencing a policy OID is a cross-object
hash cycle. RFC §5.1 `policy_init: <policy-oid>` is unconstructible as
written.
"""
import json, subprocess, tempfile, threading, time, sys, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from weft_core import (Store, keygen, make_obj, make_state, materialize,
                       state_set, check_landing, patch_paths, cbor_encode,
                       policy_requirements, H)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8747
GATE_PRIV, GATE_PUB = keygen()

S = Store()
LOCK = threading.RLock()
R = {"repo": None, "authority": [], "policy": None,      # inline policy body
     "head": None, "head_state": None, "seq": -1,
     "queue": [], "log": [], "rejects": []}


def gate_loop():
    while True:
        time.sleep(0.25)
        with LOCK:
            if R["repo"] is None or not R["queue"]:
                continue
            pending, R["queue"] = R["queue"], []
        batch, footprints, requeue = [], set(), []
        with LOCK:
            for prop_oid in pending:
                body = S.get(prop_oid)["body"]
                fps = set()
                for c in body["delta"]:
                    fps |= set(S.get(bytes(c))["body"]["footprint"])
                if fps & footprints:
                    requeue.append(prop_oid)       # serialize overlapping work
                else:
                    footprints |= fps
                    batch.append((prop_oid, [bytes(c) for c in body["delta"]]))
            R["queue"].extend(requeue)
        if batch:
            land(batch)


def land(batch):
    with LOCK:
        base_state, prev, seq = R["head_state"], R["head"], R["seq"] + 1
        delta = [c for _, cs in batch for c in cs]
        st_oid, st_raw = make_state(GATE_PRIV, R["repo"], base_state, delta, S)
        S.put(st_raw)
        target = state_set(S, st_oid)
        mat = materialize(S, target)
        man_oid, man_raw = make_obj(GATE_PRIV, R["repo"], "manifest",
                                    dict(mat["manifest_body"], state=st_oid))
        S.put(man_raw)
        body = {"ref": "trunk", "seq": seq, "prev": prev,
                "base_state": base_state, "delta": sorted(delta),
                "target_state": st_oid, "manifest": man_oid,
                "policy": H(cbor_encode(R["policy"])),
                "evidence": [], "proposals": sorted(b[0] for b in batch)}
        errs, warns, _ = check_landing(
            S, body, R["authority"], [GATE_PUB], int(time.time() * 1000),
            stale_reads=R["policy"].get("stale_reads", "reject"))
        if errs:
            R["rejects"].append({"seq_attempt": seq, "errors": errs,
                                 "proposals": [b[0].hex() for b in batch]})
            return
    # --- evidence execution outside the lock: scratch sandbox, pinned cmd ---
    req = policy_requirements(R["policy"], set())
    ev_oids, ev_summaries = [], []
    with tempfile.TemporaryDirectory(prefix="weft-gate-") as tmp:
        for path, content in mat["tree"].items():
            fp = os.path.join(tmp, path.replace("/", os.sep))
            os.makedirs(os.path.dirname(fp), exist_ok=True) if os.sep in fp else None
            open(fp, "wb").write(content)
        for recipe in R["policy"]["recipes"]:
            digest = H(cbor_encode(recipe))
            r = subprocess.run(recipe["cmd"], cwd=tmp, capture_output=True,
                               timeout=30)
            status = "pass" if r.returncode == 0 else "fail"
            ev_body = {"manifest": man_oid, "recipe": recipe,
                       "results": [{"status": status,
                                    "out": r.stdout.decode()[:512]}]}
            with LOCK:
                oid, raw = make_obj(GATE_PRIV, R["repo"], "evidence", ev_body)
                S.put(raw)
            ev_oids.append(oid)
            ev_summaries.append({"recipe": digest.hex()[:12], "status": status,
                                 "out": r.stdout.decode()[:200].strip()})
            if status != "pass":
                with LOCK:
                    R["rejects"].append({"seq_attempt": seq,
                                         "errors": [f"evidence failed: "
                                                    f"{r.stdout.decode()[:200]}"],
                                         "proposals": [b[0].hex() for b in batch]})
                return
    with LOCK:
        body["evidence"] = ev_oids
        lnd_oid, lnd_raw = make_obj(GATE_PRIV, R["repo"], "landing", body)
        S.put(lnd_raw)
        crt_oid, crt_raw = make_obj(GATE_PRIV, R["repo"], "certificate",
                                    {"subject": lnd_oid,
                                     "signatures": [[GATE_PUB, b""]]})
        S.put(crt_raw)
        R["head"], R["head_state"], R["seq"] = lnd_oid, st_oid, seq
        R["log"].append({
            "seq": seq, "landing": lnd_oid.hex(), "state": st_oid.hex(),
            "manifest": man_oid.hex(), "warnings": warns,
            "markers": mat["markers"], "evidence": ev_summaries,
            "changes": [{
                "oid": c.hex(),
                "author": S.get(c)["author"].hex()[:12],
                "model": S.get(c)["body"].get("provenance", {}).get("model"),
                "footprint": S.get(c)["body"]["footprint"],
                "message": S.get(c)["body"].get("message", ""),
            } for c in sorted(delta)]})


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        with LOCK:
            if self.path == "/gatekey":
                return self._send(200, {"pub": GATE_PUB.hex()})
            if self.path == "/heads":
                return self._send(200, {"seq": R["seq"],
                                        "landing": R["head"].hex() if R["head"] else None,
                                        "state": R["head_state"].hex() if R["head_state"] else None})
            if self.path == "/log":
                return self._send(200, {"log": R["log"], "rejects": R["rejects"],
                                        "queued": len(R["queue"])})
            if self.path.startswith("/obj/"):
                oid = bytes.fromhex(self.path[5:])
                if oid not in S:
                    return self._send(404, {"error": "unknown oid"})
                return self._send(200, S.raw[oid], "application/cbor")
            if self.path == "/workspace":
                if R["head_state"] is None:
                    return self._send(200, {"files": {}, "seq": -1})
                mat = materialize(S, state_set(S, R["head_state"]))
                files = {}
                fid_by_path = {p: f for f, p in mat["file_map"].items() if p}
                for path, content in mat["tree"].items():
                    fid = fid_by_path[path]
                    files[path] = {
                        "content": content.decode(errors="replace"),
                        "digest": H(content).hex(),
                        "fid": [fid[0].hex(), fid[1]],
                        "line_ids": [[l[0].hex(), l[1]]
                                     for l in mat["line_index"][path]]}
                return self._send(200, {"files": files, "seq": R["seq"]})
        self._send(404, {"error": "no route"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        try:
            with LOCK:
                if self.path == "/obj":
                    oid = S.put(raw)                     # sig + canonical check
                    env = S.get(oid)
                    if env["type"] == "genesis":
                        if env["repo"] is not None:
                            return self._send(400, {"error": "genesis must have repo null"})
                        R["repo"] = oid
                        R["authority"] = [bytes(k) for k in env["body"]["authority"]]
                        R["policy"] = env["body"]["policy_init"]   # INLINE (finding W3)
                        if GATE_PUB not in [bytes(g) for g in
                                            env["body"]["refs"]["trunk"]["gates"]]:
                            return self._send(400, {"error": "this gate not in genesis"})
                    return self._send(200, {"oid": oid.hex()})
                if self.path == "/propose":
                    oid = S.put(raw)
                    if S.get(oid)["type"] != "proposal":
                        return self._send(400, {"error": "not a proposal"})
                    R["queue"].append(oid)
                    return self._send(200, {"queued": oid.hex()})
        except Exception as e:
            return self._send(400, {"error": f"{type(e).__name__}: {e}"})
        self._send(404, {"error": "no route"})


if __name__ == "__main__":
    threading.Thread(target=gate_loop, daemon=True).start()
    print(f"weftd listening on :{PORT}  gate={GATE_PUB.hex()[:16]}…", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
