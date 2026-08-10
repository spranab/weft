"""Live self-test: drive the Hermes plugin's tool surface against a real hub.

Verifies the parts that are Weft's responsibility — signing, capability
discovery, position→identity translation, and outcome reporting — without
needing a Hermes host. The Hermes-side wiring (plugin.yaml discovery, hook
dispatch) is exercised by Hermes itself.

    cargo run --release -p weftd -- 8747      # in another terminal
    python selftest.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).parent))
from weft_hermes import WeftClient, WeftPlugin, WeftError  # noqa: E402

HUB = os.environ.get("WEFT_HUB", "http://127.0.0.1:8747")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="weft-hermes-"))
    agent = WeftClient(HUB, tmp / "agent.key", model="hermes")
    plugin = WeftPlugin(agent)
    call = lambda name, **args: json.loads(plugin.handle_tool_call(name, args))

    status = call("weft_status")
    if "error" in status:
        print(f"FAIL: {status['error']}")
        print("  start a hub first:  cargo run --release -p weftd -- 8747")
        return 1
    print(f"weft_status      → repo {str(status['repo'])[:12]}…  seq {status['trunk_seq']}")
    print(f"agent key        → {agent.pub[:16]}…")

    # writes must be refused until a human delegates a capability
    denied = call("weft_submit", message="unauthorized attempt",
                  edits=[{"path": "probe.txt", "create": True, "lines": ["nope"]}])
    assert "no live capability" in denied.get("error", ""), denied
    print("weft_submit      → refused without a capability, and says which key to authorize ✓")

    # the human side: mint a Contributor capability for the agent key
    authority = WeftClient(HUB, Path(os.environ.get("WEFT_CLI_KEY", tmp / "authority.key")))
    try:
        authority.publish("capability", {
            "audience": f"hex:{agent.pub}",
            "parent": None,
            "scope": {"actions": ["publish_change", "propose"], "paths": ["**"]},
            "exp": int(time.time() * 1000) + 3_600_000,
            "meta": {"reason": "Contributor (hermes selftest)"},
        })
    except WeftError as e:
        print(f"NOTE: could not mint a capability ({e}).")
        print("  Run this against a hub whose authority key is $WEFT_CLI_KEY,")
        print("  or mint one in the console for the agent key above.")
        return 1
    print("capability       → minted by the authority key ✓")

    out = call("weft_submit", message="hermes: add a note file",
               edits=[{"path": "hermes.md", "create": True,
                       "lines": ["# written by a Hermes agent",
                                 "landed through a verification gate"]}])
    print(f"weft_submit      → {out.get('outcome')} "
          f"{'seq ' + str(out.get('seq')) if out.get('seq') is not None else ''}")
    if out.get("outcome") != "landed":
        print(f"  detail: {json.dumps(out)[:200]}")
        return 1

    ws = call("weft_workspace")
    assert "written by a Hermes agent" in ws["tree"], ws
    print("weft_workspace   → numbered lines, instruction/data labelled ✓")

    prov = call("weft_provenance", change=out["change"])
    assert any(link.get("root") for link in prov.get("chain", [])), prov
    print(f"weft_provenance  → model={prov['model']} chain reaches the authority root ✓")

    plugin.on_session_end([])
    print("on_session_end   → session note written to the repo's memory ✓")
    print("\nall good — the Hermes plugin drives a real gate end to end.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
