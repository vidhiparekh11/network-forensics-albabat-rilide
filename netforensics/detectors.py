"""Behavioral detectors. Each takes list[Packet] and returns list[Finding]."""
from __future__ import annotations
import ipaddress, math, statistics
from collections import defaultdict
from .models import Finding

SMB_PORTS = {445, 139}
BROWSER_UA_HINTS = ("mozilla", "chrome", "safari", "firefox", "edge")


# Documentation ranges are "private" per Python, but lab/sample captures use them as
# stand-ins for internet hosts, so we deliberately treat them as external.
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def is_private(ip: str) -> bool:
    """True for internal/non-routable addresses (RFC1918, loopback, link-local, multicast)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(a in n for n in _DOC_NETS):
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast


def is_ip_literal(s: str) -> bool:
    if not s:
        return False
    host = s.rsplit(":", 1)[0] if s.count(":") == 1 else s.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def detect_beaconing(pkts, min_conns=6, max_cv=0.25, min_interval=1.0):
    """Regular outbound connection starts to the same dst:port => possible C2 heartbeat."""
    starts = defaultdict(list)
    for p in pkts:
        if p.proto == "TCP" and p.flags == "S" and is_private(p.src) and not is_private(p.dst):
            starts[(p.src, p.dst, p.dport)].append(p.ts)
    out = []
    for (src, dst, dport), ts in starts.items():
        if len(ts) < min_conns:
            continue
        ts.sort()
        iv = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.mean(iv)
        if mean < min_interval:
            continue
        cv = statistics.pstdev(iv) / mean
        if cv <= max_cv:
            out.append(Finding(
                "high" if cv < 0.1 else "medium", "c2-beaconing",
                f"Periodic connections {src} -> {dst}:{dport}",
                f"{len(ts)} connections, mean interval {mean:.1f}s, jitter (CV) {cv:.2f}.",
                iocs={"ip": [dst]},
                evidence={"src": src, "dst": dst, "dport": dport, "count": len(ts),
                          "mean_interval_s": round(mean, 2), "cv": round(cv, 3)}))
    return out


def detect_dns_anomalies(pkts, nx_threshold=20, entropy_threshold=3.4, min_label=12, long_query=60):
    out, nx, seen = [], defaultdict(int), set()
    for p in pkts:
        if p.dns_rcode == 3:          # NXDOMAIN response; dst is the client
            nx[p.dst] += 1
        q = p.dns_query
        if not q or p.dns_rcode is not None or q in seen:
            continue
        labels = q.split(".")
        sld = labels[-2] if len(labels) >= 2 else labels[0]
        if len(q) >= long_query:
            seen.add(q)
            out.append(Finding("medium", "dns-tunneling", "Unusually long DNS query",
                               f"{len(q)} chars: {q[:80]}...", iocs={"domain": [q]},
                               evidence={"client": p.src, "qtype": p.dns_qtype}))
        elif len(sld) >= min_label and entropy(sld) >= entropy_threshold:
            seen.add(q)
            out.append(Finding("medium", "dns-dga-like", f"High-entropy domain queried: {q}",
                               f"Label '{sld}' length {len(sld)}, entropy {entropy(sld):.2f} bits/char.",
                               iocs={"domain": [q]}, evidence={"client": p.src, "entropy": round(entropy(sld), 2)}))
    for client, n in nx.items():
        if n >= nx_threshold:
            out.append(Finding("medium", "dns-nxdomain-burst", f"{n} NXDOMAIN responses to {client}",
                               "Bulk failed lookups are typical of domain-generation algorithms.",
                               evidence={"client": client, "nxdomain": n}))
    return out


def detect_http_anomalies(pkts):
    out, seen = [], set()
    for p in pkts:
        h = p.http
        if not h or is_private(p.dst):
            continue
        key = (p.src, p.dst, h["method"], h["host"], h["uri"])
        if key in seen:
            continue
        seen.add(key)
        reasons = []
        if is_ip_literal(h["host"]):
            reasons.append("Host header is a raw IP")
        if h["method"] == "POST" and not h["ua"]:
            reasons.append("POST with no User-Agent")
        elif h["ua"] and not any(x in h["ua"].lower() for x in BROWSER_UA_HINTS):
            reasons.append(f"non-browser User-Agent '{h['ua'][:40]}'")
        if h["method"] == "POST" and h["content_length"] > 100_000:
            reasons.append(f"large POST body ({h['content_length']} bytes)")
        if reasons:
            url = f"http://{h['host'] or p.dst}{h['uri']}"
            iocs = {"ip": [p.dst], "url": [url]}
            if h["host"] and not is_ip_literal(h["host"]):
                iocs["domain"] = [h["host"].split(":")[0]]
            if h["ua"]:
                iocs["user_agent"] = [h["ua"]]
            out.append(Finding("high" if len(reasons) > 1 else "medium", "http-suspicious",
                               f"Suspicious HTTP {h['method']} {url}", "; ".join(reasons),
                               iocs=iocs, evidence={"client": p.src}))
    return out


def detect_exfiltration(pkts, threshold_bytes=5_000_000):
    vol = defaultdict(int)
    for p in pkts:
        if is_private(p.src) and not is_private(p.dst) and p.proto in ("TCP", "UDP"):
            vol[(p.src, p.dst)] += p.length
    return [Finding("high" if b > threshold_bytes * 4 else "medium", "exfiltration",
                    f"{b/1e6:.1f} MB sent {s} -> {d}",
                    "Outbound volume above threshold; verify against expected uploads.",
                    iocs={"ip": [d]}, evidence={"src": s, "dst": d, "bytes": b})
            for (s, d), b in vol.items() if b >= threshold_bytes]


def detect_smb_fanout(pkts, min_hosts=10):
    """One internal host opening SMB to many internal peers: worm-like spread / ransomware staging."""
    peers = defaultdict(set)
    for p in pkts:
        if p.proto == "TCP" and p.flags == "S" and p.dport in SMB_PORTS and is_private(p.dst):
            peers[p.src].add(p.dst)
    return [Finding("high", "lateral-movement", f"{s} contacted {len(d)} hosts over SMB",
                    "Fan-out on 445/139 is consistent with ransomware propagation or share enumeration.",
                    evidence={"src": s, "targets": sorted(d)[:50], "count": len(d)})
            for s, d in peers.items() if len(d) >= min_hosts]


def detect_port_scan(pkts, min_ports=25):
    ports = defaultdict(set)
    for p in pkts:
        if p.proto == "TCP" and p.flags == "S":
            ports[(p.src, p.dst)].add(p.dport)
    return [Finding("medium", "port-scan", f"{s} probed {len(pp)} ports on {d}", "SYN sweep across many ports.",
                    evidence={"src": s, "dst": d, "ports": len(pp)})
            for (s, d), pp in ports.items() if len(pp) >= min_ports]


ALL = [detect_beaconing, detect_dns_anomalies, detect_http_anomalies,
       detect_exfiltration, detect_smb_fanout, detect_port_scan]


def run_all(pkts, cfg=None):
    cfg = cfg or {}
    findings = []
    for fn in ALL:
        findings += fn(pkts, **cfg.get(fn.__name__, {}))
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda f: order[f.severity])
