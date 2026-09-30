from __future__ import annotations
import json, datetime as dt
from collections import Counter


def summary(pkts):
    ts = [p.ts for p in pkts]
    iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat()
    return {"packets": len(pkts), "bytes": sum(p.length for p in pkts),
            "start": iso(min(ts)) if ts else None, "end": iso(max(ts)) if ts else None,
            "protocols": dict(Counter(p.proto for p in pkts))}


def to_json(name, pkts, findings, iocs, blocklist_hits=None):
    return json.dumps({"capture": name, "summary": summary(pkts), "findings": [f.to_dict() for f in findings],
                       "iocs": iocs, "blocklist_hits": blocklist_hits or []}, indent=2)


def to_markdown(name, pkts, findings, iocs, blocklist_hits=None):
    s = summary(pkts)
    L = [f"# Network Forensics Report: `{name}`", "",
         f"- Packets: **{s['packets']}**  |  Bytes: **{s['bytes']:,}**",
         f"- Window: {s['start']} -> {s['end']}", f"- Protocols: {s['protocols']}", "",
         f"## Findings ({len(findings)})", ""]
    if not findings:
        L.append("_No detections triggered._")
    for f in findings:
        L += [f"### [{f.severity.upper()}] {f.title}", f"*Category:* `{f.category}`  ", f.detail,
              "*ATT&CK:* " + (", ".join(f"{t['id']} ({t['name']})" for t in f.attack) or "n/a"), ""]
    if blocklist_hits:
        L += ["## Blocklist matches", ""] + [f"- `{h}`" for h in blocklist_hits] + [""]
    L += ["## Indicators of Compromise", ""]
    for k, vals in iocs.items():
        if vals:
            L += [f"**{k}**", ""] + [f"- `{v}`" for v in vals] + [""]
    return "\n".join(L)
