from __future__ import annotations
import argparse, os, sys
from . import __version__, ioc, report
from .parser import read_pcap
from .detectors import run_all


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nfa", description="Defensive PCAP analysis & IOC export")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a pcap/pcapng file")
    a.add_argument("pcap")
    a.add_argument("-f", "--format", choices=["md", "json"], default="md")
    a.add_argument("-o", "--out", help="write report here (default: stdout)")
    a.add_argument("--iocs", help="write IOCs to a .csv or .json file")
    a.add_argument("--blocklist", help="file of known-bad IPs/domains, one per line")
    a.add_argument("--beacon-min", type=int, default=6, help="min connections to call it beaconing")
    a.add_argument("--fail-on", choices=["medium", "high"], help="exit 2 if findings at/above severity (CI use)")
    c = sub.add_parser("config", help="parse a ransomware remote-config JSON (extensions, processes, URLs)")
    c.add_argument("file")
    args = ap.parse_args(argv)

    if args.cmd == "config":
        import json
        from .config_parser import parse_config
        with open(args.file) as fh:
            print(json.dumps(parse_config(fh.read()), indent=2))
        return 0

    if not os.path.exists(args.pcap):
        ap.error(f"file not found: {args.pcap}")
    pkts = list(read_pcap(args.pcap))
    findings = run_all(pkts, {"detect_beaconing": {"min_conns": args.beacon_min}})
    iocs = ioc.collect(findings)
    hits = ioc.match_blocklist(pkts, ioc.load_blocklist(args.blocklist)) if args.blocklist else []

    render = report.to_json if args.format == "json" else report.to_markdown
    text = render(os.path.basename(args.pcap), pkts, findings, iocs, hits)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
    else:
        print(text)
    if args.iocs:
        (ioc.write_csv if args.iocs.endswith(".csv") else ioc.write_json)(iocs, args.iocs)

    if args.fail_on:
        levels = {"medium": {"medium", "high"}, "high": {"high"}}[args.fail_on]
        if any(f.severity in levels for f in findings) or hits:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
