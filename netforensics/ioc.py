from __future__ import annotations
import csv, json


def collect(findings):
    """Merge IOCs attached to findings, deduplicated and sorted."""
    iocs = {"ip": set(), "domain": set(), "url": set(), "user_agent": set()}
    for f in findings:
        for k, vals in f.iocs.items():
            iocs.setdefault(k, set()).update(vals)
    return {k: sorted(v) for k, v in iocs.items()}


def load_blocklist(path):
    with open(path) as fh:
        return {ln.strip().lower() for ln in fh if ln.strip() and not ln.startswith("#")}


def match_blocklist(pkts, blocklist):
    hits = set()
    for p in pkts:
        for v in (p.dst, p.src, p.dns_query, (p.http or {}).get("host")):
            if v and v.lower() in blocklist:
                hits.add(v.lower())
    return sorted(hits)


def write_json(iocs, path):
    with open(path, "w") as fh:
        json.dump(iocs, fh, indent=2)


def write_csv(iocs, path):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "value"])
        for k, vals in iocs.items():
            for v in vals:
                w.writerow([k, v])
