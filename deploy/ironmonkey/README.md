# IronMonkey Conpot deployment

Deployment artifacts for running this Conpot fork as the OT honeypot half of the IronMonkey threat-intel platform (Story 17.3).

Pairs with [`HillviewCap/honeygo`](https://github.com/HillviewCap/honeygo) (IT layer) to capture the full IT→OT attack chain via planted breadcrumb files.

## Architecture

```
Attacker
  │
  ├─► Honeygo SSH (port 22) ──► IronPot:8003 ──► Redis honeypot:breadcrumb:<ip>
  │      (reads /root/credentials.cfg planted by Honeygo isolation engine)
  │
  └─► Conpot OT (502/102/2404/8088)
         │
         ▼
       conpot-forwarder (sidecar)
         │
         ├─► reads honeypot:breadcrumb:<ip> from Redis
         └─► POST → IronPot:8003 with parent_session_id
                  │
                  ▼
            STIX relationship (OT)-[:RELATED_TO]-(IT)
```

## Layout

```
deploy/ironmonkey/
├── docker-compose.yml            # Conpot + forwarder sidecar
├── forwarder/
│   ├── Dockerfile
│   ├── conpot_forwarder.py       # tail JSONL + POST to IronPot
│   ├── requirements.txt
│   └── .env.example
└── README.md (this file)

conpot/templates/s7-315-substation/   # ← upstream-style location
├── template.xml                  # S7-315-2 PN/DP substation persona
└── index.html                    # SIMATIC WinCC HMI login page
```

## Deploy targets

| Target | Sensor ID | IronPot URL | Routing |
|--------|-----------|-------------|---------|
| snakeplskn (test bench) | `sensor-lab-snakeplskn-01-ot` | `http://localhost:8003` | `stix:honeypot:lab:queue` (skips Neo4j + MISP) |
| VPS (production) | `sensor-nyc-01-ot` | `http://snakeplskn:8003` (Tailscale) | `stix:honeypot:queue` |

## snakeplskn quick-start

```bash
# On snakeplskn (Node 1)
git clone https://github.com/HillviewCap/ironmonkey-conpot.git /home/snakep/ironmonkey-conpot
cd /home/snakep/ironmonkey-conpot/deploy/ironmonkey
cp forwarder/.env.example forwarder/.env
# Edit forwarder/.env: fill in HONEYPOT_WEBHOOK_TOKEN (must match IronPot's)

docker compose up -d --build

# Verify
docker ps --filter name=ironmonkey-conpot
docker logs ironmonkey-conpot-forwarder --follow
docker exec ironmonkey-conpot tail -f /var/log/conpot/conpot.json
```

## Template

`conpot/templates/s7-315-substation/template.xml` — Siemens S7-315-2 PN/DP substation persona designed as an INDUSTROYER/CRASHOVERRIDE trap. IEC-104 ASDU types 45/46/50/58 (Single/Double Command, Set-point) are highest-signal captures.

Conpot fingerprint strings (`copyright = "Original Siemens Equipment"`, `as_name`) have been stripped — see `template.xml` notes.

## Related

- Story 17.3 spec: [`HillviewCap/ironmonkey-unified` _bmad-output/implementation-artifacts/17-3-…md](https://github.com/HillviewCap/ironmonkey-unified)
- IronPot ingestion: [`HillviewCap/ironmonkey-ironpot`](https://github.com/HillviewCap/ironmonkey-ironpot)
- IT layer: [`HillviewCap/honeygo`](https://github.com/HillviewCap/honeygo)
