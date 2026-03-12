"""
Security Log Analyzer - Analyzer
================================
Detects suspicious IPs from parsed firwall logs using three detection rules:

    Rule 1. Repeated DENY - same IP denied N+ times within a time window
    Rule 2. Repeated external access - same external IP connects N+ times within a time window
    Rule 3. Unusual port access - connections to non-standard ports

Each suspicious IP is tagged with reasons and supporting evidence.
"""

from collections import defaultdict
from datetime import datetime
from typing import List, Dict

import config


def is_external_ip(ip: str) -> bool:
    """Check if an IP address is external (not in internal ranges)."""
    return not ip.startswith(config.INTERNAL_IP_PREFIX)


def detect_repeated_denies(records: List[Dict]) -> Dict[str, Dict]:
    """
    Rule 1: Flag IPs that are denied multiple times within the time window.

    Logic:
        1. Filter for DENY records only
        2. Group by source IP
        3. Check if deny count exceeds threshold within the time window
    """
    # Collect all DENY records grouped by source IP
    deny_by_ip = defaultdict(list)
    for r in records:
        if r["action"] == "Denied":
            deny_by_ip[r["src_ip"]].append(r)

    flagged = {}

    for ip, deny_records in deny_by_ip.items():
        # Sort records by timestamp
        deny_records.sort(key=lambda r: r["timestamp"])

        # Check if enough denies occur within the time window
        count = len(deny_records)
        first_seen = deny_records[0]["timestamp"]
        last_seen = deny_records[-1]["timestamp"]
        time_span = (last_seen - first_seen).total_seconds()

        if (
            count >= config.DENY_COUNT_THRESHOLD
            and time_span <= config.DENY_TIME_WINDOW_SEC
        ):
            flagged[ip] = {
                "deny_count": count,
                "time_span_sec": time_span,
                "reason": f"Repeated DENY: {count} denies in {time_span:.0f}s",
                "records": deny_records,
            }

    return flagged


def detect_repeated_external_access(records: List[Dict]) -> Dict[str, Dict]:
    """
    Rule 2: Flag external IPs that connect too frequently within the time window.

    Logic:
        1. Filter for external source IPs only (exclude internal ranges)
        2. Group by source IP
        3. Check if connection count exceeds threshold within the time window
    """
    # Collect all records from external IPs
    ext_by_ip = defaultdict(list)
    for r in records:
        if is_external_ip(r["src_ip"]):
            ext_by_ip[r["src_ip"]].append(r)

    flagged = {}

    for ip, ip_records in ext_by_ip.items():
        ip_records.sort(key=lambda r: r["timestamp"])

        count = len(ip_records)
        first_seen = ip_records[0]["timestamp"]
        last_seen = ip_records[-1]["timestamp"]
        time_span = (last_seen - first_seen).total_seconds()

        if (
            count >= config.REPEAT_COUNT_THRESHOLD
            and time_span <= config.REPEAT_TIME_WINDOW_SEC
        ):
            flagged[ip] = {
                "connection_count": count,
                "time_span_sec": time_span,
                "reason": f"Repeated external access: {count} connections in {time_span:.0f}s",
                "records": ip_records,
            }

    return flagged


def detect_unusual_port_access(records: List[Dict]) -> Dict[str, Dict]:
    """
    Rule 3: Flag connections to non-standard ports.

    Logic:
        1. Filter for records where dst_port is NOT in the common ports set
        2. Exclude port 0 (invalid/missing data)
        3. Group by source IP
    """
    unusual_by_ip = defaultdict(list)

    for r in records:
        port = r["dst_port"]
        if port != 0 and port not in config.COMMON_PORTS:
            unusual_by_ip[r["src_ip"]].append(r)

    flagged = {}

    for ip, ip_records in unusual_by_ip.items():
        unusual_ports = list(set(r["dst_port"] for r in ip_records))
        flagged[ip] = {
            "unusual_ports": unusual_ports,
            "hit_count": len(ip_records),
            "reason": f"Unusual port access: port(s) {unusual_ports}",
            "records": ip_records,
        }

    return flagged


def analyze(records: List[Dict]) -> List[Dict]:
    """
    Run all detection rules and merge results into a unified suspicious IP list.

    Each entry includes:
        - IP address
        - Whether it's external
        - List of reasons it was flagged
        - Connection stats (total,  denied, first/last seen)
        - Targeted ports and destination IPs

    Returns:
        List of suspicious IP dictionaries, sorted by number of reasons (most suspicious first)
    """
    print("\n[*] Running detection rules...")

    # Run each rule
    rule1_results = detect_repeated_denies(records)
    rule2_results = detect_repeated_external_access(records)
    rule3_results = detect_unusual_port_access(records)

    print(f"   Rule 1 (Repeated DENY)            : {len(rule1_results)} IP(s) flagged")
    print(f"   Rule 2 (Repeated External Access) : {len(rule2_results)} IP(s) flagged")
    print(f"   Rule 3 (Unusual Port Access)      : {len(rule3_results)} IP(s) flagged")

    # Collect all flagged IPs
    all_flagged_ips = set()
    all_flagged_ips.update(rule1_results.keys())
    all_flagged_ips.update(rule2_results.keys())
    all_flagged_ips.update(rule3_results.keys())

    if not all_flagged_ips:
        print("  [OK] No suspicious IPs detected.")
        return []

    # Build per-IP profiles by scanning all records
    ip_all_records = defaultdict(list)
    for r in records:
        if r["src_ip"] in all_flagged_ips:
            ip_all_records[r["src_ip"]].append(r)

    # Merge results into unified profiles
    suspicious_list = []

    for ip in all_flagged_ips:
        ip_records = ip_all_records[ip]
        ip_records.sort(key=lambda r: r["timestamp"])

        # Collect reasons from each rule
        reasons = []
        if ip in rule1_results:
            reasons.append(rule1_results[ip]["reason"])
        if ip in rule2_results:
            reasons.append(rule2_results[ip]["reason"])
        if ip in rule3_results:
            reasons.append(rule3_results[ip]["reason"])

        # Build profile
        profile = {
            "ip": ip,
            "is_external": is_external_ip(ip),
            "reasons": reasons,
            "total_connections": len(ip_records),
            "denied_count": sum(1 for r in ip_records if r["action"] == "Denied"),
            "first_seen": ip_records[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": ip_records[-1]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "targeted_ports": list(set(r["dst_port"] for r in ip_records)),
            "targeted_dst_ips": list(set(r["dst_ip"] for r in ip_records)),
        }

        suspicious_list.append(profile)

    # Sort by number of reasons (most suspicious first)
    suspicious_list.sort(key=lambda x: (-len(x["reasons"]), -x["total_connections"]))

    print(f"\n  [RESULT] {len(suspicious_list)} suspicious IP(s) detected totally")
    return suspicious_list


def print_suspicious_ips(suspicious_list: List[Dict]) -> None:
    """Pretty-print the list of suspicious IPs with details."""
    if not suspicious_list:
        print("\n  No suspicious IPs to display.")
        return

    print("\n" + "=" * 65)
    print("  SUSPICIOUS IP REPORT")
    print("=" * 65)

    for i, entry in enumerate(suspicious_list, 1):
        ext_label = "EXTERNAL" if entry["is_external"] else "INTERNAL"
        print(f"\n  [{i}] {entry['ip']} ({ext_label})")
        print(
            f"      Connections : {entry['total_connections']} total, {entry['denied_count']} denied"
        )
        print(f"      First Seen  : {entry['first_seen']}")
        print(f"      Last Seen   : {entry['last_seen']}")
        print(f"      Ports       : {entry['targeted_ports']}")
        print(f"      Targets     : {entry['targeted_dst_ips']}")
        print(f"      Reasons     :")
        for reason in entry["reasons"]:
            print(f"          - {reason}")

    print("\n" + "=" * 65)


# --------------------------------
# Standalone test function
# --------------------------------
if __name__ == "__main__":
    from parser import parse_log_file

    print(f"[*] Loading log file: {config.LOG_FILE_PATH}")
    records = parse_log_file(config.LOG_FILE_PATH)

    suspicious = analyze(records)
    print_suspicious_ips(suspicious)
