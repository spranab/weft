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

## Why a WRITABLE public hub is not offered yet

Do not put a writable hub on the public internet until these land (all on
the roadmap):

1. **Persistence** — the store is in-memory; a restart loses the repo.
2. **Evidence sandboxing (RFC §12.5)** — recipes execute commands. On a
   writable public hub that is remote-code-execution-as-a-service. The
   demo policy has zero recipes and `--readonly` makes it moot.
3. **One repo per hub**, no TLS termination (put nginx/Caddy in front),
   no rate limiting beyond capability checks.

A private writable hub on your own network/VPN (agents + trusted humans) is
fine today: run `weftd 8747` without flags and put it behind your firewall
or an authenticated reverse proxy. TLS: any reverse proxy
(`caddy reverse-proxy --from weft.example.com --to localhost:8747`).
