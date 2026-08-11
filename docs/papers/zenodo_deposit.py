"""Create a Zenodo DRAFT deposit for the Weft whitepaper.

Reads ZENODO_API_KEY from ~/codes/grievance/.env. Creates a *draft* (NOT
published), uploads the three deposit files, sets metadata, and prints the
review URL. Pass --publish to publish (irreversible) — left to the author.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys

import httpx
from dotenv import load_dotenv

PAPER_DIR = pathlib.Path(__file__).resolve().parent / "zenodo-bundle"
GRIEVANCE_ENV = pathlib.Path.home() / "codes" / "grievance" / ".env"
ZENODO_API = "https://zenodo.org/api"

FILES = [
    ("weft-whitepaper.pdf", PAPER_DIR / "weft-whitepaper.pdf"),
    ("README.md", PAPER_DIR / "README.md"),
    ("source.md", PAPER_DIR / "source.md"),
    ("weft-evidence.tar.gz", PAPER_DIR / "weft-evidence.tar.gz"),
]

METADATA = {
    "metadata": {
        "title": "Weft: Evidence-Gated Version Control for Autonomous Agent Swarms",
        "upload_type": "publication",
        "publication_type": "preprint",
        "publication_date": "2026-08-11",
        "language": "eng",
        "version": "1.0.0",
        "access_right": "open",
        "license": "cc-by-4.0",
        "creators": [
            {"name": "Sarkar, Pranab", "affiliation": "Independent Researcher",
             "orcid": "0009-0009-8683-1481"},
        ],
        "description": (
            "<p>Version control systems assume that a human reads each change before it is integrated. Commit messages are prose for a reader; pull requests exist to partition work into human-reviewable units; branch protection encodes &ldquo;someone approved this.&rdquo; Autonomous coding agents violate that assumption by roughly two orders of magnitude in throughput, leaving practitioners to choose between throttling agents to human reading speed and abandoning pre-integration verification altogether.</p><p>This paper presents Weft, a version-control and coordination protocol in which integration is gated by machine-checkable evidence bound to exact content rather than by human attention. Weft contributes: a change object carrying an explicit read-set, enabling detection of semantically stale work whose textual footprint does not conflict &mdash; a failure class three-way textual merge cannot observe; evidence bound to a Merkle materialization manifest, so an attestation refers to specific bytes rather than a mutable reference; capability-based agent identity with authorization frozen at certification time, so credential expiry and revocation cannot retroactively invalidate history; and a batching-and-bisection gate that amortizes verification across commutable work while isolating faults.</p><p>A reference implementation in approximately 7,000 lines of Rust is evaluated on four workloads spanning code, structured data, and prose. Across all four, output assembled without a gate fails its own validator while gated output passes; a 50-agent, 100-task workload lands 82 changes in 15 certified landings, refusing 8 of 8 stale-read changes, 8 of 8 seeded defects, and 3 of 3 revoked credentials. The specification underwent adversarial review by two frontier language models, an executable prototype, continuous integration, and public critique, yielding 92 dispositioned findings &mdash; including one fatal content-model defect that fuzzing and model review both missed and only a live demonstration exposed.</p>"
        ),
        "keywords": [
            "version control", "autonomous agents", "multi-agent systems",
            "software verification", "optimistic concurrency control", "CRDT",
            "capability-based security", "supply chain attestation",
        ],
        "notes": (
            "Reference implementation, all recorded runs, the with/without-gate showcase "
            "artifacts, and the complete review log of 92 dispositioned findings are bundled "
            "for reproduction. A live read-only instance runs at https://demo.weftgate.com."
        ),
        "related_identifiers": [
            {"identifier": "https://github.com/spranab/weft",
             "relation": "isSupplementTo", "resource_type": "software"},
            {"identifier": "https://weftgate.com",
             "relation": "isDocumentedBy", "resource_type": "other"},
        ],
        "default_preview": "weft-whitepaper.pdf",
    }
}


def load_token() -> str:
    if GRIEVANCE_ENV.exists():
        load_dotenv(GRIEVANCE_ENV)
    token = os.environ.get("ZENODO_API_KEY")
    if not token:
        print(f"ZENODO_API_KEY not found (expected in {GRIEVANCE_ENV}).", file=sys.stderr)
        sys.exit(1)
    return token


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--publish", action="store_true",
                    help="Publish (assigns DOI; irreversible). Default: draft only.")
    args = ap.parse_args()

    token = load_token()
    headers = {"Authorization": f"Bearer {token}"}

    def _check(r, label):
        if r.status_code >= 400:
            url = str(r.request.url).replace(token, "<redacted>")
            print(f"\n[{label}] HTTP {r.status_code} {url}")
            try:
                print(json.dumps(r.json(), indent=2))
            except Exception:
                print(r.text[:1000])
            sys.exit(2)

    with httpx.Client(timeout=60, base_url=ZENODO_API, headers=headers) as cli:
        r = cli.post("/deposit/depositions", json={})
        _check(r, "create-draft")
        dep = r.json()
        dep_id = dep["id"]
        bucket = dep["links"]["bucket"]
        print(f"Created draft deposit id={dep_id}")

        r = cli.put(f"/deposit/depositions/{dep_id}", json=METADATA)
        _check(r, "set-metadata")
        print("  metadata set")

        for name, src in FILES:
            if not src.exists():
                print(f"  MISSING {name} ({src}) — aborting"); sys.exit(3)
            data = src.read_bytes()
            r = httpx.put(f"{bucket}/{name}", content=data, headers=headers, timeout=180)
            _check(r, f"upload-{name}")
            print(f"  uploaded {name:32s} {len(data):>10,} bytes  md5:{hashlib.md5(data).hexdigest()[:8]}")

        if args.publish:
            print("\n!! Publishing (irreversible) !!")
            r = cli.post(f"/deposit/depositions/{dep_id}/actions/publish")
            _check(r, "publish")
            pub = r.json()
            print(f"\nPublished. DOI: {pub.get('doi','(pending)')}")
            print(f"Record: https://zenodo.org/records/{pub.get('record_id','')}")
        else:
            print(f"\nDraft created (NOT published). Review + Publish here:")
            print(f"  https://zenodo.org/uploads/{dep_id}")


if __name__ == "__main__":
    main()
