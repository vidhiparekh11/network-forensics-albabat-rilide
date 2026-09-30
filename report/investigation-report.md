# Incident Investigation Report: Rilide Information Stealer
**C2 over HTTP / exfiltration via messaging platforms**

**Investigator:** Vidhi Parekh  **Assessment:** 2025-08-04 -> 2025-08-06  **Classification:** Business Confidential
**Affected host:** 192.168.100.232  **Tooling:** Wireshark 4.2 (TLS keys loaded), Suricata, `nfa`

## 1. Executive summary
Suspicious outbound HTTP/DNS activity from 192.168.100.232 was analyzed in a PCAP with TLS keys. The traffic was
assessed as matching Rilide, a Chromium-targeting infostealer (credential theft, cookie/session access, crypto-wallet
monitoring, C2 over trusted domains). Findings: Microsoft device-credential requests, Google account enumeration,
Google Play telemetry, Microsoft activation calls, crypto-related DNS lookups, and `/report/v4` POSTs to Cloudflare
NEL, with a malicious Chrome extension (`pnkjgfienlbflgofbgoepgmpaiflcahf`) noted for persistence. Traffic hid inside
HTTPS to legitimate cloud services, defeating simple domain blocking.

## 2. Scope
Reviewed HTTP/HTTPS/DNS in the PCAP; followed HTTP streams to recover payloads; extracted IOCs; mapped to ATT&CK.

**Filters used:** `http.request.method == "POST"` · `http contains "report/v4"` ·
`frame contains "base64" && frame matches "[A-Za-z0-9+/]{20,}={0,2}"` · `http.response`

## 3. Activity timeline
| Phase | Activity | Evidence |
|---|---|---|
| 1 | Google `ListAccounts` POST; body `["gaia.l.a.r",[]]` (no signed-in accounts) | accounts.google.com, `source=ChromiumBrowser` |
| 2a | Microsoft `deviceaddcredential.srf` POST with `Membername`/`Password`/`OldMembername`; server `Error Code="dc13"` | login.live.com |
| 2b | `SLActivateProduct.asmx?configextension=Retail` SOAP with ProductKey/PublishLicense; response `0xC004C008` | activation-v2.sls.microsoft.com |
| 3 | `play.google.com/log` gzip POST: Chromium 122, Windows 10.0.0, session IDs, location hint "DEU" | play.google.com |
| 4 | TLS sessions to accounts.google.com, login.live.com, play.google.com; crypto domains | TLS filter |
| 5 | DNS: Google/Microsoft/GitHub hosts, `btcscan.org`, `mmemento-mori.com` (Cloudflare IPs) | DNS filter |
| 6 | Repeated failed activation / credential-bind attempts over short intervals | frame list |
| 7 | Multiple POSTs to `/report/v4` (gzip/JSON blobs), 192.168.100.232 -> 35.190.80.1 | `http contains "report/v4"` |

## 4. MITRE ATT&CK (as reported)
| ID | Name | Reviewer note |
|---|---|---|
| T1056.002 | Input Capture: API Hooking / Credential Capture | **Check ID:** T1056.002 is *GUI Input Capture*; *Credential API Hooking* is T1056.004 |
| T1071.001 | Application Layer Protocol: Web Protocols | OK |
| T1005 | Data from Local System | OK |
| T1041 | Exfiltration Over C2 Channel | OK, contingent on confirming exfil (see §6) |
| T1082 | System Information Discovery | OK |

## 5. Remediation (as reported)
| Finding | Recommendation | Severity |
|---|---|---|
| Microsoft device credential harvesting | Reset affected accounts, enable MFA, review SOAP `Membername`/`Password` payloads, DLP | Critical |
| Google ListAccounts session hijack | Audit/remove unapproved Chrome extensions, browser hardening | High |
| C2 via legitimate cloud services | TLS inspection, cloud allow-listing | High |
| No DNS detection for dynamic C2 | DNS logging, threat-intel blocking (mmemento-mori.com) | Medium |
| Obfuscated HTTPS payloads | IDS rules for encoded POSTs, JA3/JA3S | Medium |

## 6. Reviewer notes: validate before publishing
These are points a senior analyst would probe. Each can be settled from the existing capture.

1. **Native Windows/Chrome behavior vs malware.** In the screenshots the `deviceaddcredential.srf` request carries
   `IDCRL` and `svchost.exe` markers in its User-Agent, and `SLActivateProduct` uses the `SLSSoapClient` agent. Those are
   how Windows' own sign-in and activation services identify themselves. Random 16-character `Membername`/`Password`
   pairs are also consistent with Windows auto-generated *device* accounts, not stolen user credentials. If so,
   Phases 2a/2b/6 are benign OS noise and the "credential theft" claim would not stand. **Check:** map each request to
   its originating process (Sysmon/EDR), and compare to a clean Windows 10 baseline capture.
2. **`/report/v4` is Chrome's Network Error Logging.** `a.nel.cloudflare.com/report/v4` (35.190.80.1) receives NEL
   reports from any Chrome visiting a Cloudflare-fronted site. **Check:** decode the POST bodies; NEL bodies are JSON
   with `"type":"network-error"`. Arbitrary stolen data would look different.
3. **Play `/log` and `ListAccounts`** are standard Chromium calls. Their presence alone doesn't indicate compromise; the
   evidence is the *client* that sent them (extension origin, non-Chrome UA). See rules 1000010, 1000014.
4. **Indicators.** Google/Microsoft/GitHub hostnames are not IOCs and shouldn't be blocked. `mmemento-mori.com` and the
   extension ID need independent corroboration (VirusTotal, URLhaus, Chrome Web Store/CRX hash).
5. **Evidence gap.** The report shows no packet proving stolen data left to attacker infrastructure. The strongest
   single artifact would be the extension's own traffic (`Origin: chrome-extension://pnkj...`).
6. Minor: assessment end date reads `2025-08-062`; "Windows 10.0.0" is a User-Agent artifact, not a build number.

## 7. Conclusion
Rilide activity on the host is asserted; the network evidence should be tied to the malicious extension and to a
non-native client before it is presented as confirmed. Recommended controls: extension allow-listing, DNS/TLS
correlation, and the client-anomaly Suricata rules in `rules/`.
