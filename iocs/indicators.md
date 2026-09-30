# Indicators of Compromise: Rilide investigation

Source: *Incident Investigation Report: Rilide Information Stealer* (V. Parekh, 2025-08-04 to 08-06).
Defanged where relevant. Victim host: `192.168.100.232` (internal).

## A. Actionable indicators
| Type | Value | Note | Confidence |
|---|---|---|---|
| Chrome extension ID | `pnkjgfienlbflgofbgoepgmpaiflcahf` | Malicious extension identified in the report; detect via `chrome-extension://` Origin (sid 1000010) and endpoint inventory | Medium: confirm against the extension's manifest/hash |
| Domain | `mmemento-mori[.]com` | Suspected C2; Cloudflare-fronted per the report | **Unverified**: no public corroboration found; check VirusTotal/URLhaus/passive DNS before blocking org-wide (sid 1000011) |

## B. Context only. Legitimate services, **do not block**
Blocking these would break Microsoft sign-in, Windows activation, Chrome sync and Google services.
The malware may abuse or mimic them, so detect by **client and behavior** instead (sids 1000012-1000014).

| Value | Observed use |
|---|---|
| `login.live.com` `/ppsecure/deviceaddcredential.srf` | Microsoft device-credential request |
| `accounts.google.com` `/ListAccounts?gpsia=1&source=ChromiumBrowser` | Signed-in account check |
| `play.google.com` `/log?format=json&hasfast=true` | Google telemetry POST |
| `activation-v2.sls.microsoft.com` `/SLActivateProduct/SLActivateProduct.asmx` | Windows activation SOAP |
| `a.nel.cloudflare.com` `/report/v4` | Cloudflare Network Error Logging reports |
| `api.github.com` | Queried in DNS |
| `btcscan.org`, `bitcoinexplorer.org`, `blockstream.info`, `blockchain.info`, `api.bitcore.io`, `mempool.space` | Public blockchain explorers/APIs; possibly wallet-monitoring targets, not necessarily attacker infrastructure |

## C. Data exposure (from decrypted traffic)
Microsoft-account style `Membername`/`Password` pairs (**redacted here**; rotate anything real), TPM RSA public key
material, product-key/activation blobs, OS/browser/GPU/extension fingerprint. Affected OS: Windows 10 (10.0.x), Chromium 122.

## D. Still to collect
File hashes (extension package, dropper), C2 IPs behind Cloudflare, extension manifest permissions, campaign
attribution references. Albabat indicators are in a separate section once that capture is analyzed.
