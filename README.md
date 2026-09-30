# netforensics-toolkit (`nfa`)

A defensive PCAP analysis CLI for triaging captures of **ransomware** and **browser-extension stealer** activity
(the threat classes studied in the Albabat / Rilide network-forensics work). It parses a capture, runs
behavior-based detectors, and exports IOCs you can push to a SIEM, firewall, or blocklist.

> Detection is **behavioral**, not signature-based: it does not ship family-specific IOCs. Feed your own
> intel in with `--blocklist`.

## Install
```bash
pip install -e .            # requires Python 3.9+, scapy
pip install -e ".[dev]"     # + pytest
```

## Usage
```bash
python samples/make_sample_pcap.py                 # harmless synthetic capture
nfa analyze samples/synthetic.pcap                 # Markdown report to stdout
nfa analyze cap.pcapng -f json -o report.json      # JSON report
nfa analyze cap.pcap --iocs iocs.csv               # export IOCs (.csv or .json)
nfa analyze cap.pcap --blocklist bad.txt --fail-on high   # CI gate: exit code 2 on hits
```

## Detectors
| Category | Signal | Why it matters here |
|---|---|---|
| `c2-beaconing` | Low-jitter periodic outbound TCP connects | Stealer/RAT heartbeats to C2 |
| `dns-dga-like` / `dns-nxdomain-burst` | High-entropy labels; bursts of NXDOMAIN | Domain-generation fallbacks |
| `dns-tunneling` | Very long queries | Covert channels |
| `http-suspicious` | Raw-IP Host, POST without UA, non-browser UA, large POST | Data upload to gate/panel endpoints |
| `exfiltration` | Large outbound volume to one external host | Stolen data / pre-encryption exfil |
| `lateral-movement` | One host fanning out over SMB (445/139) | Ransomware spread |
| `port-scan` | SYN sweep of many ports | Recon |

Thresholds are function arguments in `netforensics/detectors.py`; `--beacon-min` is exposed on the CLI.

## Companion deliverables (matches the investigation repo layout)
- `rules/albabat-c2-detection.rules`: Suricata 7 rules (config fetch from GitHub raw, raw-IP POST exfil, SMB fan-out, DNS). Validate with `bash samples/validate_rules.sh`.
- `nfa config <file>`: extract targeted extensions, killed processes and URLs from a remote-config JSON; tags T1083/T1057/T1486.
- `iocs/indicators.md`, `report/investigation-report.md`, `notes/methodology-notes.md`: fill-in templates (TLS decryption via `editcap --inject-secrets`, tshark exports, SOC report).
- Findings from `nfa analyze` carry MITRE ATT&CK IDs (`netforensics/attack.py`).

Rilide IOCs and findings come from the investigation report; **Albabat data is still to be added**. Sample pcaps/configs are synthetic; no real Albabat/Rilide indicators are bundled. Add yours from your captures.

## Layout
```
netforensics/  parser.py  detectors.py  attack.py  config_parser.py  ioc.py  report.py  cli.py
rules/ iocs/ report/ notes/   (investigation deliverables)
samples/       make_sample_pcap.py (synthetic test traffic)
tests/         pytest suite incl. end-to-end pcap round-trip
```

## Limitations / next steps
- IPv4/IPv6 TCP/UDP only; HTTP is parsed from cleartext requests (TLS shows up as beaconing/volume only).
- Ideas: JA3/SNI extraction, Zeek log input, STIX 2.1 export, per-flow timelines, MITRE ATT&CK tagging.
- Analyze only captures you are authorized to handle.
