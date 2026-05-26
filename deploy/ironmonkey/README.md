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
├── template.xml                  # root: core/template metadata + databus seeds
├── modbus/modbus.xml             # Modbus/TCP (FC-3 holding regs, FC-1 coils)
├── s7comm/s7comm.xml             # S7Comm SZL 0x011C / 0x0011 identity
├── http/
│   ├── http.xml                  # HTTP config (Server: Siemens CP443-1...)
│   └── htdocs/index.html         # SIMATIC WinCC HMI login page
├── IEC104/IEC104.xml             # IEC 60870-5-104 ASDU types 1/3/13/30
├── snmp/                         # (empty — protocol intentionally not loaded)
└── ssl/                          # self-signed cert for HTTPS variant
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

`conpot/templates/s7-315-substation/` — Siemens S7-315-2 PN/DP substation persona designed as an INDUSTROYER/CRASHOVERRIDE trap. IEC-104 ASDU types 1 (M_SP_NA_1) / 3 (M_DP_NA_1) / 13 (M_ME_NC_1) / 30 (M_SP_TB_1) are exposed as monitored telemetry; command-type ASDUs (45/46/50/58) trigger via incoming commands and are highest-signal captures.

### Template structure

Conpot 0.6.0's loader (`bin/conpot:299-405`) treats `--template` as either an absolute path (if `<path>/template.xml` exists) or a name under `conpot/templates/`. The root `template.xml` is validated against `conpot/template.xsd` and feeds `<core><databus>` into the databus. For each protocol directory under the template root, the loader looks for `<root>/<proto>/<proto>.xml` and validates it against `conpot/protocols/<proto>/<proto>.xsd`. Protocol directory names follow `conpot.protocols.name_mapping` — note `IEC104` is CamelCase, all others lowercase. Each per-protocol XML's root element name MUST match the directory name (`<modbus>`, `<s7comm>`, `<http>`, `<IEC104>`), and its `enabled` attribute (`"True"`/`"False"`) gates whether the protocol server spins up.

### XSD shape rules (must hold across template edits)

These shapes don't match a naive read of the monolithic 17.3 draft — they are XSD-enforced and Conpot will refuse to start otherwise:

| Element | Correct shape | XSD reference |
|---|---|---|
| `modbus.xml` `<device_info>` | `<VendorName>`, `<ProductCode>`, `<MajorMinorRevision>` — CamelCase | `conpot/protocols/modbus/modbus.xsd:9-11` |
| `modbus.xml` block backing | `<content>databus_list_key</content>` — single list-typed databus key | `conpot/protocols/modbus/modbus.xsd:44-47` |
| `s7comm.xml` SZL identity | `<system_name id="W#16#0001">DatabusKey</system_name>` — child text is a databus key NAME, not a literal | `conpot/protocols/s7comm/s7comm.xsd:12-21` |
| `http.xml` `<global>/<headers>` | maxOccurs=1 — only one entity per global headers block; per-node headers can have many | `conpot/protocols/http/http.xsd:27-43` vs `:76-95` |
| `IEC104.xml` `<device_info>` | `<vendor_name>`, `<product_code>` — lowercase (differs from modbus.xsd) | `conpot/protocols/IEC104/IEC104.xsd:9-10` |
| `IEC104.xml` register `<value>` | databus key NAME, not literal value | `conpot/protocols/IEC104/IEC104.xsd:24` |

### OPSEC scrub rules

None of the following may appear anywhere in the template tree (verify with `grep -r` before commits):

- `Original Siemens Equipment` (Conpot-default Copyright) — replaced by `SIMATIC S7-300 V3.3`
- `<as_name>` — no counterpart in real S7-315 SZL output; a known fingerprint
- `Mouser Factory`, `Technodrome`, `Venus`, `the conpot team`, `Patrick Reichenberger` — upstream Conpot seed strings
- Default Python `BaseHTTPServer/0.6` Server header — overridden per-node by `Server: Siemens CP443-1 Advanced V3.3.0`

## Related

- Story 17.3 spec: [`HillviewCap/ironmonkey-unified` _bmad-output/implementation-artifacts/17-3-…md](https://github.com/HillviewCap/ironmonkey-unified)
- IronPot ingestion: [`HillviewCap/ironmonkey-ironpot`](https://github.com/HillviewCap/ironmonkey-ironpot)
- IT layer: [`HillviewCap/honeygo`](https://github.com/HillviewCap/honeygo)
