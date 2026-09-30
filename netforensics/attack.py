"""Map detector categories to MITRE ATT&CK techniques (matches the project's ATT&CK table)."""
ATTACK = {
    "c2-beaconing":       [("T1071.001", "Application Layer Protocol: Web Protocols")],
    "http-suspicious":    [("T1071.001", "Application Layer Protocol: Web Protocols"),
                           ("T1041", "Exfiltration Over C2 Channel")],
    "exfiltration":       [("T1041", "Exfiltration Over C2 Channel")],
    "dns-dga-like":       [("T1568.002", "Dynamic Resolution: Domain Generation Algorithms")],
    "dns-nxdomain-burst": [("T1568.002", "Dynamic Resolution: Domain Generation Algorithms")],
    "dns-tunneling":      [("T1071.004", "Application Layer Protocol: DNS")],
    "lateral-movement":   [("T1021.002", "Remote Services: SMB/Windows Admin Shares")],
    "port-scan":          [("T1046", "Network Service Discovery")],
}


def techniques(category):
    return ATTACK.get(category, [])
