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

conpot/templates/<persona>/       # ← upstream-style location. Three personas
                                  #   ship: s7-315-substation (the default),
                                  #   water-utility, oil-gas-pipeline.
├── template.xml                  # root: core/template metadata + databus seeds
├── ironmonkey/persona.json       # device roster — read by the FORWARDER, not
│                                 #   by Conpot (step H11)
├── modbus/modbus.xml             # Modbus/TCP (FC-3 holding regs, FC-1 coils)
├── s7comm/s7comm.xml             # S7Comm SZL 0x011C / 0x0011 identity
├── http/
│   ├── http.xml                  # HTTP config, per-node Server banner
│   ├── htdocs/
│   │   ├── index.html            # start page, carries the /login form
│   │   └── hmi/
│   │       ├── index.html        # 401 Basic challenge (persona realm)
│   │       └── denied.html       # 403 sign-in-failed page, aliased from /login
│   └── statuscodes/              # 400, 403, 404, 501, 503 (step H11)
├── IEC104/IEC104.xml             # IEC 60870-5-104 ASDU types 1/3/13/30
├── snmp/snmp.xml                 # SNMPv2-MIB system group (step H10)
├── bacnet/bacnet.xml             # BACnet/IP building controller (step H10)
├── enip/enip.xml                 # EtherNet/IP identity + tags (step H10)
└── ssl/                          # substation only: self-signed cert for the
                                  #   proxy protocol, which no persona serves
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

## Templates: the sector personas (step H11)

A persona is a SITE, not a device: several emulated boxes behind one address, each answering the protocols it actually speaks. All three serve the same seven protocols on the same ports, because the sensor's published ports and its ufw rules are fleet-wide — a persona changes identity and content, not reach.

| Persona | Sector | Site | Devices |
|---|---|---|---|
| `s7-315-substation` | `energy` | `SUBSTATION-01` | S7-315-2 PN/DP (modbus, s7comm, IEC-104, snmp, http) · Desigo PXC4.E16 (bacnet) · 1769-AENTR/B (enip) |
| `water-utility` | `water_wastewater` | `WTP-01` | MicroLogix 1400 (modbus, enip, http) · S7-1200 + CP 1243-1 (s7comm, IEC-104, snmp) · Metasys NAE5510 (bacnet) |
| `oil-gas-pipeline` | `oil_gas` | `CS-07` | S7-1500 + TIM 1531 IRC (s7comm, IEC-104, snmp, http) · Emerson ROC809 (modbus) · 1734-AENTR (enip) · FX-PCX27 (bacnet) |

`s7-315-substation` is the default and the persona every sensor ran before H11; it is designed as an INDUSTROYER/CRASHOVERRIDE trap. On every persona, IEC-104 ASDU types 1 (M_SP_NA_1) / 3 (M_DP_NA_1) / 13 (M_ME_NC_1) / 30 (M_SP_TB_1) are exposed as monitored telemetry; command-type ASDUs (45/46/50/58) trigger via incoming commands and are the highest-signal captures.

Model numbers and serials are plausible values for the products named, not values captured from real devices. What matters is that they are internally consistent, are not upstream Conpot defaults, and are not repeated across personas — two sensors answering with the same ENIP serial or the same BACnet device instance correlate the fleet in one scan.

Select one with `ironmonkey-unified`'s `scripts/sensor-deploy.sh --template <name>`, which writes `CONPOT_TEMPLATE` into the sensor's `.env`; the compose files here and in `ironmonkey-unified/sensors/` mount the whole `conpot/templates` tree and pass `-t /opt/conpot-templates/${CONPOT_TEMPLATE}`.

### `ironmonkey/persona.json` — the device roster

Conpot never reads this file; its loader only looks at `template.xml` and `<proto>/<proto>.xml`, so the directory is invisible to it. The forwarder reads it to decide which emulated device answered which protocol, because `asset_type`/`vendor`/`model` seed the uuid5 of the `x-ics-asset` node IronPot writes. One identity for every protocol would tell an analyst a BACnet write landed on the PLC that runs the plant; two identities for one device would split its history in half.

Keys under `assets.services` are the forwarder's own `data_type` values — `modbus`, `s7comm`, `iec104`, `iec-104`, `http`, `snmp`, `bacnet`, `enip` — not directory names and not ports. A persona that puts IEC-104 on its own device must map BOTH spellings, since `_map_record` accepts either. `assets.default` covers everything with no entry of its own.

A missing or malformed manifest fails OPEN: the forwarder logs a warning and falls back to the pre-H11 substation roster rather than stopping. An asset label is observability, and observability must not block ingest. `sensor-deploy.sh` refuses to ship a persona without one, so that fallback should only ever be reached by a sensor deployed before H11.

### `http/statuscodes/` is not optional

A code declared in `http.xml` without a matching `<code>.status` file makes `load_status` (`command_responder.py:266-276`) log `FileNotFoundError .../http/statuscodes/404.status` and answer with a zero-length body. The substation persona shipped the XML block and none of the files from 2026-05-26 until step H11, so every scanner probe of a nonexistent path — the single most common request an internet-exposed sensor gets — produced a traceback and a content-free 404.

Two upstream limits, so nobody re-derives them: `<entity name="Content-Type">` under `<status>` is read by no code path in Conpot 0.6.0, and `http.xsd` gives `<status>` no `<headers>` child. A status response therefore carries the one global header (Date) plus Content-Length, and the persona's `Server` banner cannot be attached to it from the template. Fixing that means patching the responder.

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

### Credential bait (Phase 2 step H4)

The persona asks for credentials in two places, and the forwarder decodes whichever arrives.

| Path | Method | Answer | What it provokes |
|---|---|---|---|
| `/hmi/`, `/hmi`, `/hmi/index.html` | GET, POST | `401` + `WWW-Authenticate: Basic realm="SIMATIC HMI"` | Any client that is given a credential (`curl -u`, a browser, a stuffing tool) sends `Authorization: Basic` on the retry |
| `/login` (alias of `/hmi/denied.html`) | POST | `403` + "Invalid user name or password" | The start page's form has always posted here; before H4 there was no node and it returned 404 |

Both are ordinary static nodes. Conpot 0.6.0's `load_entity` reads a per-node `<status>` and `<headers>` for GET and POST alike (`command_responder.py:433-442`, reached from `do_GET:867` and `do_POST:935`), so no protocol-handler patch was required.

There is **no credential comparison anywhere in this path**. Every pair is rejected identically, so no input — default, guessed or correct-for-a-real-device — can produce a page suggesting something is reachable behind the login. The default-credential *list* lives on the platform side (`ironmonkey-unified/shared/honeypot/default_credentials.yaml`), is read only by the STIX rule mapper, and never reaches a sensor.

`conpot_forwarder.py` decodes `Authorization: Basic` (padding repaired, junk tolerated) and an `application/x-www-form-urlencoded` body (`username`/`user`/`login` and `password`/`pass`/`pwd`) into `username` and `password`, both inside `protocol_data` (per-exchange) and at the event top level. Neither is ever logged. Verify end to end with `curl -u admin:admin http://<sensor>/hmi/` and check `docs/honeypot-ops.md`.

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
