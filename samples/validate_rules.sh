#!/usr/bin/env bash
# Validate rule syntax with Suricata, then replay a test pcap and list which sids fired.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d)
python samples/make_rule_test_pcap.py "$W/t.pcap" 2>/dev/null
cat > "$W/s.yaml" <<Y
%YAML 1.1
---
vars: {address-groups: {HOME_NET: "[10.0.0.0/8]", EXTERNAL_NET: "!\$HOME_NET"}}
default-rule-path: $PWD/rules
rule-files: [albabat-c2-detection.rules]
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
outputs: [{fast: {enabled: yes, filename: fast.log}}]
app-layer: {protocols: {http: {enabled: yes}, tls: {enabled: yes}, dns: {enabled: yes}}}
Y
suricata -T -c "$W/s.yaml" -l "$W" >/dev/null 2>"$W/err" && echo "rule syntax: OK" || { cat "$W/err"; exit 1; }
suricata -c "$W/s.yaml" -r "$W/t.pcap" -l "$W" >/dev/null 2>&1 || true
echo "alerts fired:"; grep -o 'LOCAL NFA[^\[]*' "$W/fast.log" | sort | uniq -c
