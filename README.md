# Network Forensics: Albabat Ransomware & Rilide Infostealer

![Status](https://img.shields.io/badge/status-complete-teal) ![Tools](https://img.shields.io/badge/tools-Wireshark%20%7C%20Suricata%20%7C%20Dalton-blue) ![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

## Overview

This project documents a full network forensics investigation into two active malware families — **Albabat ransomware** and **Rilide infostealer** — with a focus on C2 communication analysis, detection engineering, and incident response.

---

## Objectives

- Decrypt and reconstruct TLS-encrypted C2 traffic for both malware families
- Extract and parse Albabat's remote configuration payload hosted on GitHub
- Develop Suricata IDS signatures to detect C2 activity
- Produce a SOC-ready investigation report with IOCs and remediation steps

---

## Tools & Environment

| Tool | Purpose |
|------|---------|
| Wireshark | TLS decryption via SSL session key injection, traffic analysis |
| Suricata | IDS/IPS rule development and testing |
| Dalton | Synthetic traffic emulation for rule validation |
| MITRE ATT&CK | TTP mapping and adversary behavior contextualization |

---

## Methodology

### 1. TLS Traffic Decryption
- Injected SSL session keys into Wireshark to decrypt HTTPS traffic
- Reconstructed full end-to-end C2 communication flows for both Albabat and Rilide

### 2. Albabat Configuration Extraction
- Located and retrieved Albabat's GitHub-hosted configuration payload
- Parsed the config to enumerate targeted file extensions and processes terminated pre-encryption

### 3. Suricata Detection Engineering
- Authored custom Suricata signatures targeting C2 config retrieval patterns
- Validated signatures using synthetic traffic generated in the Dalton emulation platform

### 4. IOC Documentation
- Compiled indicators of compromise (IOCs) including domains, IPs, URLs, and file hashes
- Mapped all findings to MITRE ATT&CK techniques

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Malware |
|---|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols | Albabat, Rilide |
| T1041 | Exfiltration Over C2 Channel | Rilide |
| T1486 | Data Encrypted for Impact | Albabat |
| T1083 | File and Directory Discovery | Albabat |
| T1057 | Process Discovery | Albabat |

---

## Deliverables

- [ ] Wireshark capture analysis notes
- [ ] Albabat config payload (sanitized)
- [ ] Suricata detection rules (`/rules/`)
- [ ] IOC list (`/iocs/`)
- [ ] SOC-style investigation report (`/report/`)

---

## Folder Structure

```
network-forensics-albabat-rilide/
├── README.md
├── rules/
│   └── albabat-c2-detection.rules
├── iocs/
│   └── indicators.md
├── report/
│   └── investigation-report.md
└── notes/
    └── methodology-notes.md
```

---

## Skills Demonstrated

- TLS decryption and deep packet inspection
- Malware C2 communication reconstruction
- IDS/IPS detection rule authoring
- Threat intelligence documentation (SOC-style reporting)
- MITRE ATT&CK framework application

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Emerging Threats Ruleset](https://rules.emergingthreats.net/)
