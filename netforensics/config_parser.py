"""Tolerant parser for ransomware remote-config payloads (JSON of unknown schema).

Walks any JSON structure and pulls out (a) file extensions targeted for encryption and
(b) process names killed pre-encryption, keyed on value shape rather than field names,
so it works even if the schema changes between builds.
"""
from __future__ import annotations
import json, re

EXT_RE = re.compile(r"^\.?[A-Za-z0-9]{1,8}$")
PROC_RE = re.compile(r"^[\w .\-]+\.(exe|com|bat|dll|sys)$", re.I)
KEY_EXT = ("ext", "extension", "type", "suffix", "target")
KEY_PROC = ("proc", "kill", "service", "task", "process", "terminate")


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}/{k}".lower())
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v, path)
    elif isinstance(node, str):
        yield path, node.strip()


def parse_config(text: str) -> dict:
    data = json.loads(text)
    exts, procs, other_urls = set(), set(), set()
    for path, val in _walk(data):
        if PROC_RE.match(val):
            procs.add(val.lower())
        elif val.startswith(("http://", "https://")):
            other_urls.add(val)
        elif any(k in path for k in KEY_EXT) and EXT_RE.match(val):
            exts.add(val.lower() if val.startswith(".") else "." + val.lower())
        elif val.startswith(".") and EXT_RE.match(val):
            exts.add(val.lower())
    return {"extensions": sorted(exts), "processes": sorted(procs), "urls": sorted(other_urls),
            "attack": [{"id": "T1083", "name": "File and Directory Discovery"},
                       {"id": "T1057", "name": "Process Discovery"},
                       {"id": "T1486", "name": "Data Encrypted for Impact"}]}
