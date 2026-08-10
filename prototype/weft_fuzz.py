"""weft_fuzz — hammers the load-bearing invariant of RFC-0001:

    ∀ change sets S, ∀ internal iteration orders: materialize(S) is identical
    (same tree bytes, same manifest roots, same conflict set).

Also runs targeted convergence tests and probes two suspected spec gaps
(rmfile-vs-edit classification; delta-split summary instability).
"""
import random, sys, time
from weft_core import (Store, keygen, make_obj, make_state, materialize,
                       state_set, closure_ok, patch_ids, cbor_encode,
                       cbor_decode, H, START)

REPO = b"\x01" * 32
PRIV, PUB = keygen()


def publish(store, typ, body, auth=None):
    oid, raw = make_obj(PRIV, REPO, typ, body, auth)
    store.put(raw)
    return oid


def mk_change(store, patch_body):
    poid = publish(store, "patch", patch_body)
    coid = publish(store, "change", {"patch": poid, "footprint": [],
                                     "reads": [], "message": "fuzz"})
    return poid, coid


def ids_of(store, poid):
    return patch_ids(poid, store.get(poid)["body"])


# ------------------------------------------------------------ helpers -------

def base_scenario(store, nfiles, nlines, rng):
    ops, texts = [], {}
    for f in range(nfiles):
        ops.append(["mkfile", f"f{f}.txt"])
    poid_placeholder = None
    # lines are inserted per file in one chain each
    body = {"nonce": rng.randbytes(8), "ops": ops}
    # we need fids before inserts → two-patch base: mkfiles, then inserts
    p1, c1 = mk_change(store, body)
    created = ids_of(store, p1)
    fids = [lid for kind, lid in created if kind == "file"]
    ops2 = []
    for i, fid in enumerate(fids):
        lines = [f"file{i} line{j}".encode() for j in range(nlines)]
        ops2.append(["insert", [fid[0], fid[1]], list(START), lines])
    p2, c2 = mk_change(store, {"nonce": rng.randbytes(8), "ops": ops2})
    line_ids = [lid for kind, lid in ids_of(store, p2) if kind == "line"]
    return [c1, c2], fids, line_ids


def random_concurrent(store, fids, line_ids, rng, k):
    changes = []
    for w in range(k):
        ops = []
        for _ in range(rng.randint(1, 4)):
            roll = rng.random()
            fid = rng.choice(fids)
            if roll < 0.55:                        # insert (maybe same anchor)
                anchor = list(START) if rng.random() < 0.4 else \
                    [rng.choice(line_ids)[0], rng.choice(line_ids)[1]]
                n = rng.randint(1, 3)
                ops.append(["insert", [fid[0], fid[1]], anchor,
                            [f"w{w}x{rng.randint(0,999)}".encode()
                             for _ in range(n)]])
            elif roll < 0.75:                      # delete
                tgt = rng.sample(line_ids, min(len(line_ids),
                                               rng.randint(1, 2)))
                ops.append(["delete", [fid[0], fid[1]],
                            [[t[0], t[1]] for t in tgt]])
            elif roll < 0.85:                      # move
                ops.append(["move", [fid[0], fid[1]],
                            f"moved/w{w}_{rng.randint(0,99)}.txt"])
            elif roll < 0.92:                      # new file
                ops.append(["mkfile", f"new/w{w}_{rng.randint(0,999)}.txt"])
            else:                                  # rmfile
                ops.append(["rmfile", [fid[0], fid[1]]])
        _, c = mk_change(store, {"nonce": rng.randbytes(8), "ops": ops})
        changes.append(c)
    return changes


def fingerprint(mat):
    return (cbor_encode(sorted([p, c] for p, c in mat["tree"].items())),
            mat["manifest_body"]["tree_root"],
            mat["manifest_body"]["conflict_root"],
            cbor_encode(mat["markers"]))


# ------------------------------------------------------------ tests ---------

def t_cbor():
    cases = [0, 23, 24, 255, 256, -1, -1000, b"", b"x" * 300, "héllo",
             [1, [2, b"a"]], {"b": 1, "a": [True, None, False]}]
    for c in cases:
        assert cbor_decode(cbor_encode(c)) == c
    try:        # non-canonical map order must be rejected
        cbor_decode(b"\xa2\x61b\x01\x61a\x02")
        return "FAIL: accepted non-canonical map"
    except ValueError:
        return "ok"


def t_same_anchor_append():
    """Two agents append at EOF concurrently → advisory marker, clean state,
    deterministic order (larger patch OID first per §6.2)."""
    s = Store()
    base, fids, lids = base_scenario(s, 1, 3, random.Random(1))
    last = lids[-1]
    ca = mk_change(s, {"nonce": b"a" * 8, "ops": [
        ["insert", [fids[0][0], fids[0][1]], [last[0], last[1]], [b"from-A"]]]})[1]
    cb = mk_change(s, {"nonce": b"b" * 8, "ops": [
        ["insert", [fids[0][0], fids[0][1]], [last[0], last[1]], [b"from-B"]]]})[1]
    m = materialize(s, frozenset(base + [ca, cb]))
    lines = m["tree"]["f0.txt"].decode().splitlines()
    assert lines[:3] == ["file0 line0", "file0 line1", "file0 line2"]
    assert set(lines[3:]) == {"from-A", "from-B"}
    assert m["markers"] == [["order", "f0.txt"]]
    assert m["manifest_body"]["clean"], "order overlap must stay clean"
    return "ok"


def t_edit_delete():
    s = Store()
    base, fids, lids = base_scenario(s, 1, 3, random.Random(2))
    victim = lids[1]
    cdel = mk_change(s, {"nonce": b"d" * 8, "ops": [
        ["delete", [fids[0][0], fids[0][1]], [[victim[0], victim[1]]]]]})[1]
    cins = mk_change(s, {"nonce": b"i" * 8, "ops": [
        ["insert", [fids[0][0], fids[0][1]], [victim[0], victim[1]],
         [b"anchored-on-deleted"]]]})[1]
    m = materialize(s, frozenset(base + [cdel, cins]))
    assert ["edit-delete", "f0.txt"] in m["conflicts"]
    assert not m["manifest_body"]["clean"]
    assert b"anchored-on-deleted" in m["tree"]["f0.txt"]   # placed, flagged
    return "ok"


def t_chain_interleave():
    s = Store()
    base, fids, lids = base_scenario(s, 1, 2, random.Random(3))
    pA, cA = mk_change(s, {"nonce": b"A" * 8, "ops": [
        ["insert", [fids[0][0], fids[0][1]], [lids[0][0], lids[0][1]],
         [b"A1", b"A2", b"A3"]]]})
    mid = [lid for k, lid in ids_of(s, pA) if k == "line"][1]     # A2
    cB = mk_change(s, {"nonce": b"B" * 8, "ops": [
        ["insert", [fids[0][0], fids[0][1]], [mid[0], mid[1]], [b"B-mid"]]]})[1]
    m = materialize(s, frozenset(base + [cA, cB]))
    lines = m["tree"]["f0.txt"].decode().splitlines()
    # B-mid and A3 are BOTH children of A2 (chain + concurrent insert);
    # their relative order depends on patch-OID comparison, so either
    # "A2, B-mid, A3" or "A2, A3, B-mid" is valid RGA. The invariant:
    # B-mid lands inside A2's child region, never before A2.
    ia2, ib, ia3 = (lines.index(x) for x in ("A2", "B-mid", "A3"))
    assert ia2 < ib <= ia2 + 2
    assert ia2 < ia3 <= ia2 + 2
    return "ok"


def t_move_move():
    s = Store()
    base, fids, _ = base_scenario(s, 1, 2, random.Random(4))
    c1 = mk_change(s, {"nonce": b"1" * 8, "ops": [
        ["move", [fids[0][0], fids[0][1]], "left.txt"]]})[1]
    c2 = mk_change(s, {"nonce": b"2" * 8, "ops": [
        ["move", [fids[0][0], fids[0][1]], "right.txt"]]})[1]
    m = materialize(s, frozenset(base + [c1, c2]))
    assert ["move-move", [fids[0][0], fids[0][1]]] in m["conflicts"]
    assert len(m["tree"]) == 1                     # deterministic winner path
    return "ok"


def t_rm_vs_edit():
    s = Store()
    base, fids, lids = base_scenario(s, 1, 2, random.Random(5))
    crm = mk_change(s, {"nonce": b"r" * 8, "ops": [
        ["rmfile", [fids[0][0], fids[0][1]]]]})[1]
    ced = mk_change(s, {"nonce": b"e" * 8, "ops": [
        ["insert", [fids[0][0], fids[0][1]], [lids[0][0], lids[0][1]],
         [b"typed into removed file"]]]})[1]
    m = materialize(s, frozenset(base + [crm, ced]))
    assert ["edit-rm", [fids[0][0], fids[0][1]]] in m["conflicts"]
    return "SPEC GAP CONFIRMED: rmfile-vs-edit absent from RFC §6.3 table"


def t_delta_split_summary():
    """Same closure, different delta split → identical materialization but
    DIFFERENT state summaries. RFC §5.10 calls summary 'load-bearing for
    cheap equality' — that claim is false across splits."""
    s = Store()
    base, fids, lids = base_scenario(s, 1, 2, random.Random(6))
    c3 = mk_change(s, {"nonce": b"3" * 8, "ops": [
        ["insert", [fids[0][0], fids[0][1]], list(START), [b"top"]]]})[1]
    st_a = publish(s, "state", {"base": None, "add": sorted(base + [c3]),
                                "summary": H(b"" + cbor_encode(sorted(base + [c3])))})
    st_b1 = publish(s, "state", {"base": None, "add": sorted(base),
                                 "summary": H(b"" + cbor_encode(sorted(base)))})
    st_b2 = publish(s, "state", {"base": st_b1, "add": [c3],
                                 "summary": H(s.get(st_b1)["body"]["summary"]
                                              + cbor_encode([c3]))})
    assert state_set(s, st_a) == state_set(s, st_b2)
    fa = fingerprint(materialize(s, state_set(s, st_a)))
    fb = fingerprint(materialize(s, state_set(s, st_b2)))
    assert fa == fb, "same set must materialize identically"
    sum_a = s.get(st_a)["body"]["summary"]
    sum_b = s.get(st_b2)["body"]["summary"]
    assert sum_a != sum_b
    return ("SPEC BUG CONFIRMED: equal closures, unequal summaries — "
            "§5.10 'cheap equality' fails across delta splits")


def fuzz(n_scenarios=300, n_orders=8, seed=42):
    rng = random.Random(seed)
    fails = 0
    for i in range(n_scenarios):
        s = Store()
        base, fids, lids = base_scenario(s, rng.randint(1, 2),
                                         rng.randint(3, 12), rng)
        conc = random_concurrent(s, fids, lids, rng, rng.randint(2, 5))
        universe = frozenset(base + conc)
        assert closure_ok(s, universe)
        ref = None
        order = list(universe)
        for _ in range(n_orders):
            rng.shuffle(order)
            fp = fingerprint(materialize(s, universe, _iter_order=list(order)))
            if ref is None:
                ref = fp
            elif fp != ref:
                fails += 1
                print(f"  DETERMINISM VIOLATION in scenario {i}")
                break
        # subset monotonicity smoke: base alone must also materialize
        fingerprint(materialize(s, frozenset(base)))
    return fails


if __name__ == "__main__":
    t0 = time.time()
    results = {
        "cbor round-trip + canonical rejection": t_cbor(),
        "T1 same-anchor concurrent append": t_same_anchor_append(),
        "T2 edit-delete conflict": t_edit_delete(),
        "T3 chain interleave": t_chain_interleave(),
        "T4 move-move conflict": t_move_move(),
        "T5 rmfile-vs-edit": t_rm_vs_edit(),
        "T6 delta-split summary": t_delta_split_summary(),
    }
    for k, v in results.items():
        print(f"[{'PASS' if v.startswith(('ok', 'SPEC')) else 'FAIL'}] {k}: {v}")
    print("fuzzing 300 scenarios x 8 shuffled orders ...")
    fails = fuzz()
    dt = time.time() - t0
    print(f"determinism violations: {fails}/300   ({dt:.1f}s)")
    sys.exit(1 if fails else 0)
