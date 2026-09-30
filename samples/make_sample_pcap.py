"""Generate a synthetic, harmless capture that exercises every detector (RFC 5737 / private addresses)."""
import random, sys
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


def build():
    random.seed(7)
    pk, t = [], 1_700_000_000.0

    def add(p, ts):
        p.time = ts
        pk.append(p)

    victim, c2, dns = "10.0.0.15", "203.0.113.50", "10.0.0.2"
    for i in range(12):   # beaconing ~30s
        add(Ether()/IP(src=victim, dst=c2)/TCP(sport=40000+i, dport=8443, flags="S"), t + i*30 + random.uniform(-.4, .4))
    for i in range(25):   # DGA-like + NXDOMAIN
        q = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16)) + ".example"
        add(Ether()/IP(src=victim, dst=dns)/UDP(sport=5000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=q)), t+i)
        add(Ether()/IP(src=dns, dst=victim)/UDP(sport=53, dport=5000+i)/DNS(qr=1, rcode=3, qd=DNSQR(qname=q)), t+i+.01)
    req = b"POST /gate.php HTTP/1.1\r\nHost: 198.51.100.7\r\nContent-Length: 250000\r\n\r\nx"
    add(Ether()/IP(src=victim, dst="198.51.100.7")/TCP(sport=41000, dport=80, flags="PA")/Raw(req), t+100)
    for i in range(4000): # exfil volume
        add(Ether()/IP(src=victim, dst=c2)/TCP(sport=42000, dport=443, flags="A")/Raw(b"A"*1400), t+200+i*.01)
    for i in range(30, 50):  # SMB fan-out
        add(Ether()/IP(src="10.0.0.99", dst=f"10.0.0.{i}")/TCP(sport=43000+i, dport=445, flags="S"), t+300+i*.05)
    return pk


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples/synthetic.pcap"
    wrpcap(out, build())
    print("wrote", out)
