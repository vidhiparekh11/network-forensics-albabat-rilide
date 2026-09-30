# Methodology notes

## Rilide capture (as performed)
- Wireshark 4.2 with TLS session keys loaded. Portable copy: `editcap --inject-secrets tls,keys.log in.pcap out.pcapng`.
- Display filters: `http.request.method == "POST"`; `http contains "report/v4"`;
  `frame contains "base64" && frame matches "[A-Za-z0-9+/]{20,}={0,2}"`; `http.response`; DNS/TLS SNI filters.
- Follow HTTP streams to recover bodies; export objects (`File -> Export Objects -> HTTP`).

## Verifying benign vs malicious (recommended next steps)
```bash
# who sent it? UA + Origin for each interesting POST
tshark -r decrypted.pcapng -Y 'http.request.method=="POST"' -T fields \
  -e frame.number -e ip.dst -e http.host -e http.request.uri -e http.user_agent -e http.origin
# is /report/v4 really NEL?  (expect "type":"network-error")
tshark -r decrypted.pcapng -Y 'http.request.uri contains "report/v4"' -T fields -e http.file_data
# any traffic from the extension itself?
tshark -r decrypted.pcapng -Y 'http.origin contains "chrome-extension://"' 
```
Baseline: capture a clean Windows 10 + Chrome 122 VM and diff the endpoint list.

## Automation & detection
```bash
nfa analyze decrypted.pcapng -o report/nfa-output.md --iocs iocs/candidates.csv --blocklist iocs/blocklist.txt
bash samples/validate_rules.sh        # Suricata syntax + replay incl. benign controls
```
Rules 1000010-1000014 target the Rilide findings; 1000012-1000014 alert only on a *non-native client* hitting the
Microsoft/Google endpoints, to avoid flooding on normal Windows traffic. Validate in Dalton with a clean-baseline pcap.
