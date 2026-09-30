"""Build a pcap with proper TCP sessions so Suricata's HTTP parser engages (for rule validation)."""
import sys
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


def session(pk, t, src, dst, sport, dport, req):
    c = lambda **k: Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, **k)
    s = lambda **k: Ether()/IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, **k)
    seq_c, seq_s = 1000, 5000
    pk += [c(flags="S", seq=seq_c), s(flags="SA", seq=seq_s, ack=seq_c+1),
           c(flags="A", seq=seq_c+1, ack=seq_s+1),
           c(flags="PA", seq=seq_c+1, ack=seq_s+1)/Raw(req),
           s(flags="A", seq=seq_s+1, ack=seq_c+1+len(req)),
           c(flags="FA", seq=seq_c+1+len(req), ack=seq_s+1), s(flags="FA", seq=seq_s+1, ack=seq_c+2+len(req)),
           c(flags="A", seq=seq_c+2+len(req), ack=seq_s+2)]
    for i, p in enumerate(pk[-8:]):
        p.time = t + i * 0.01


pk = []
session(pk, 1.7e9, "10.0.0.15", "185.199.108.133", 50001, 80,
        b"GET /someuser/cfg/main/config.json HTTP/1.1\r\nHost: raw.githubusercontent.com\r\nUser-Agent: reqwest/0.11\r\n\r\n")
session(pk, 1.7e9+10, "10.0.0.15", "198.51.100.7", 50002, 80,
        b"POST /gate.php HTTP/1.1\r\nHost: 198.51.100.7\r\nContent-Length: 4\r\n\r\ndata")
session(pk, 1.7e9+20, "10.0.0.20", "185.199.108.133", 50003, 80,
        b"GET /x HTTP/1.1\r\nHost: raw.githubusercontent.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n\r\n")  # benign control

ms = "13.107.42.14"
NATIVE_UA = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 10.0; Win64; .NET4.0C; IDCRL 1.0.19041.3636; App svchost.exe)"
body = b"<DeviceAddRequest/>"
def post(host, uri, ua, extra=b""):
    return (f"POST {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nContent-Length: {len(body)}\r\n").encode() + extra + b"\r\n" + body
session(pk, 1.7e9+40, "10.0.0.15", ms, 50010, 80, post("login.live.com", "/ppsecure/deviceaddcredential.srf", NATIVE_UA))          # benign control
session(pk, 1.7e9+50, "10.0.0.16", ms, 50011, 80, post("login.live.com", "/ppsecure/deviceaddcredential.srf", "python-requests/2.31"))  # should fire 1000012
session(pk, 1.7e9+60, "10.0.0.16", ms, 50012, 80, post("activationv2.sls.microsoft.com", "/SLActivateProduct/SLActivateProduct.asmx?configextension=Retail", "SLSSoapClient"))  # benign control
session(pk, 1.7e9+70, "10.0.0.16", ms, 50013, 80, post("activationv2.sls.microsoft.com", "/SLActivateProduct/SLActivateProduct.asmx?configextension=Retail", "curl/8.0"))  # 1000013
session(pk, 1.7e9+80, "10.0.0.17", "142.250.185.99", 50014, 80,
        b"POST /ListAccounts?gpsia=1&source=ChromiumBrowser HTTP/1.1\r\nHost: accounts.google.com\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 0\r\n\r\n")  # 1000014
session(pk, 1.7e9+90, "10.0.0.17", "142.250.185.99", 50015, 80,
        b"POST /ListAccounts?gpsia=1&source=ChromiumBrowser HTTP/1.1\r\nHost: accounts.google.com\r\nUser-Agent: Mozilla/5.0 Chrome/122.0.0.0 Safari/537.36\r\nContent-Length: 0\r\n\r\n")  # benign control
session(pk, 1.7e9+100, "10.0.0.17", "203.0.113.50", 50016, 80,
        b"POST /x HTTP/1.1\r\nHost: example.invalid\r\nUser-Agent: Mozilla/5.0 Chrome/122\r\nOrigin: chrome-extension://pnkjgfienlbflgofbgoepgmpaiflcahf\r\nContent-Length: 0\r\n\r\n")  # 1000010
d = Ether()/IP(src="10.0.0.17", dst="10.0.0.2")/UDP(sport=53001, dport=53)/DNS(rd=1, qd=DNSQR(qname="mmemento-mori.com")); d.time = 1.7e9+110; pk.append(d)  # 1000011
for i in range(20):  # SMB fan-out
    p = Ether()/IP(src="10.0.0.99", dst=f"10.0.1.{i+1}")/TCP(sport=44000+i, dport=445, flags="S"); p.time = 1.7e9+30+i*.1; pk.append(p)
wrpcap(sys.argv[1] if len(sys.argv) > 1 else "rule_test.pcap", pk)
