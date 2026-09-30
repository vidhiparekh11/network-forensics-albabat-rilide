import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "samples"))
from scapy.all import wrpcap
from make_sample_pcap import build
from netforensics.parser import read_pcap
from netforensics.detectors import run_all, entropy
from netforensics.models import Packet
from netforensics.cli import main


def _pcap(tmp_path):
    p = str(tmp_path / "s.pcap")
    wrpcap(p, build())
    return p


def test_entropy_ordering():
    assert entropy("aaaaaaaa") < entropy("a8f3k2m9q1z7")


def test_end_to_end_all_categories(tmp_path):
    cats = {f.category for f in run_all(list(read_pcap(_pcap(tmp_path))))}
    assert {"c2-beaconing", "dns-dga-like", "dns-nxdomain-burst", "http-suspicious",
            "exfiltration", "lateral-movement"} <= cats


def test_no_false_beacon_on_irregular_traffic():
    pk = [Packet(ts=t, src="10.0.0.1", dst="8.8.4.4", proto="TCP", dport=443, flags="S")
          for t in (0, 3, 50, 51, 200, 260, 900)]
    assert not [f for f in run_all(pk) if f.category == "c2-beaconing"]


def test_cli_outputs_and_fail_on(tmp_path):
    pcap, out, iocs = _pcap(tmp_path), str(tmp_path / "r.md"), str(tmp_path / "i.csv")
    bl = tmp_path / "bl.txt"
    bl.write_text("203.0.113.50\n")
    rc = main(["analyze", pcap, "-o", out, "--iocs", iocs, "--blocklist", str(bl), "--fail-on", "high"])
    assert rc == 2
    assert "203.0.113.50" in open(iocs).read()
    assert "c2-beaconing" in open(out).read()


def test_config_parser_and_attack_tags():
    from netforensics.config_parser import parse_config
    root = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_config.json")
    r = parse_config(open(root).read())
    assert ".jpg" in r["extensions"] and ".sql" in r["extensions"]
    assert "sqlservr.exe" in r["processes"] and "outlook.exe" in r["processes"]
    assert {a["id"] for a in r["attack"]} == {"T1083", "T1057", "T1486"}


def test_findings_carry_attack_ids(tmp_path):
    f = [x for x in run_all(list(read_pcap(_pcap(tmp_path)))) if x.category == "c2-beaconing"][0]
    assert f.attack[0]["id"] == "T1071.001"


def test_blocklist_hits_from_rilide_ioc(tmp_path):
    from netforensics.ioc import match_blocklist, load_blocklist
    from netforensics.models import Packet
    bl = os.path.join(os.path.dirname(__file__), "..", "iocs", "blocklist.txt")
    pk = [Packet(ts=1, src="10.0.0.1", dst="10.0.0.2", proto="UDP", dns_query="mmemento-mori.com"),
          Packet(ts=2, src="10.0.0.1", dst="10.0.0.2", proto="UDP", dns_query="login.live.com")]
    assert match_blocklist(pk, load_blocklist(bl)) == ["mmemento-mori.com"]


def test_rules_file_has_unique_sids():
    import re
    txt = open(os.path.join(os.path.dirname(__file__), "..", "rules", "albabat-c2-detection.rules")).read()
    sids = re.findall(r"^alert .*sid:(\d+);", txt, re.M)
    assert len(sids) == len(set(sids)) >= 11
