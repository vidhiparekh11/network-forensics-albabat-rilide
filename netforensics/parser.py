"""PCAP/PCAPNG -> stream of Packet. Uses scapy's streaming reader."""
from __future__ import annotations
from typing import Iterator
from .models import Packet

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def _parse_http(payload: bytes):
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    cl = hdrs.get("content-length", "")
    return {"method": parts[0], "uri": parts[1], "host": hdrs.get("host", ""),
            "ua": hdrs.get("user-agent", ""), "content_length": int(cl) if cl.isdigit() else 0}


def read_pcap(path: str) -> Iterator[Packet]:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, Raw  # lazy import

    with PcapReader(path) as rd:
        for pkt in rd:
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None:
                continue
            rec = Packet(ts=float(pkt.time), src=ip.src, dst=ip.dst, proto="OTHER", length=len(pkt))
            if TCP in pkt:
                t = pkt[TCP]
                rec.proto, rec.sport, rec.dport, rec.flags = "TCP", int(t.sport), int(t.dport), str(t.flags)
            elif UDP in pkt:
                u = pkt[UDP]
                rec.proto, rec.sport, rec.dport = "UDP", int(u.sport), int(u.dport)
            if DNS in pkt:
                d = pkt[DNS]
                if d.qd is not None:
                    q = d.qd.qname
                    rec.dns_query = (q.decode(errors="replace") if isinstance(q, bytes) else str(q)).rstrip(".").lower()
                    rec.dns_qtype = int(d.qd.qtype)
                if d.qr == 1:
                    rec.dns_rcode = int(d.rcode)
            if TCP in pkt and Raw in pkt:
                rec.http = _parse_http(bytes(pkt[Raw].load))
            yield rec
