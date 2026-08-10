# Hosting a Weft hub

## The safe public tier today: read-only demo

```bash
weftd 8747 --demo --readonly
```

`--demo` seeds a living scenario **through the real gate** at boot (landings
from three models, a stale-read rejection, a revoked-credential rejection,
intents, identities, provenance chains). `--readonly` returns 403 for every
POST route. No persistence is needed — state rebuilds on each boot. This is
what runs the public demo.

### systemd (what the demo instance uses)

```ini
[Unit]
Description=Weft governance hub - public read-only demo
After=network.target
[Service]
ExecStart=/opt/weft/weftd 8747 --demo --readonly
Restart=always
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=512M
[Install]
WantedBy=multi-user.target
```

Build a matching binary with `cargo build --release -p weftd` on a machine
with the same (or older) glibc as the host, `scp` it to `/opt/weft/weftd`,
`systemctl enable --now weftd-demo`.

### Docker

```bash
docker build -t weftd . && docker run -p 8747:8747 weftd
```

## Durable, sandboxed hubs

```bash
weftd 8747 --data /var/lib/weft/hub.wal --sandbox unshare
```

**`--data <path>`** makes the hub crash-durable. The store is an append-only
write-ahead log (`u32-le length ‖ canonical object bytes`); objects are
immutable and self-verifying, so replay re-verifies **every signature**, a
torn tail is truncated at the last good frame, and no index or compaction is
needed for correctness. On boot the hub rebuilds genesis/authority,
revocations, the landing chain, seq/head, and re-queues any proposal whose
changes never landed — so work in flight during a crash is re-adjudicated,
not lost. The gate keypair is stored beside the log (`hub.key`, mode it
0600) because a persistent hub must keep the key its genesis pinned.

**`--sandbox unshare|none|auto`** (default `auto`) controls evidence
execution per RFC §12.5. `unshare` runs each recipe in a fresh user +
network namespace — no network, no privilege, fresh scratch dir per run.
`auto` probes for unprivileged user namespaces and falls back to `none`
with a loud warning. **Never expose a writable hub publicly while the
warning is printing.**

## Replicas (RFC §8)

```bash
weftd 8748 --data ./replica.wal --follow http://gate-host:8747 --readonly
```

A follower bootstraps from the peer's genesis, pulls objects (each
self-verifying on store), then **re-derives the certified landing chain
locally** — re-materializing every state, re-running the §7.3 checklist, and
requiring each landing to be authored *and* certified by a key the genesis
names. It never adopts a peer's claimed head on the peer's word.

- a landing signed by a non-gate key → refused
- a landing with no gate certificate → refused
- two certified landings claiming the same slot → **fork reported**, head
  frozen (a CP trunk must not pick arbitrarily)

Replicas set `replica = true` and never certify, so pointing one at a peer is
safe by construction. Replication is pull-based over HTTP today; the QUIC
frames and push subscriptions in RFC §8 are still roadmap.

## Why a WRITABLE public hub still needs care

1. **Sandbox depth** — namespaces bound network and privilege, not CPU or
   disk. For untrusted contributors, run the hub in a container/VM too and
   set `MemoryMax`/`CPUQuota` on the unit.
2. **TLS and rate limiting** — terminate TLS at nginx/Caddy; capability
   checks stop unauthorized *writes*, not request floods.
3. **One repo per hub**, and multi-node gossip sync is still roadmap.

A private writable hub on your own network/VPN is straightforward today:
`weftd 8747 --data ./hub.wal` behind your firewall or an authenticated
reverse proxy. TLS via any proxy
(`caddy reverse-proxy --from weft.example.com --to localhost:8747`).
