"""
Security Log Analyzer - Log Parser
Parses firewall log CSV files into structured, normalized data.

Key features:
- Reads CSV log files row by row
- Normalizes fields (type convention, whitespace trimming)
- Outputs basic log statistics
"""

import csv
from datetime import datetime
from typing import List, Dict, Optional


def parse_log_file(filepath: str) -> List[Dict]:
    """
    Parse a CSV firewall log file and return a list of normalized records.

    Args:
        filepath: Path to the CSV log file

    Returns:
        List of parsed log records as dictionaries
    """
    records = []

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row_num, row in enumerate(reader, start=1):
            try:
                record = _normalize_row(row, row_num)
                if record:
                    records.append(record)
            except Exception as e:
                print(f"   [WARN] Row {row_num} failed to parse: {e}")

    print(f"   [OK] {len(records)} records parsed successfully.")
    return records


def _normalize_row(row: Dict, row_num: int) -> Optional[Dict]:
    """
    Convert a raw CSV row into a normalized dictionary.
    - Timestamps are converted to datetime objects
    - Ports are converted to integers
    - Whitespace is stripped from string fields
    """
    time_str = row.get("Time", "").strip()
    if not time_str:
        return None

    # Parse timestamp
    try:
        timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        print(f"   [WARN] Row {row_num} invalid time format: {time_str}")
        return None

    # Safe integer conversion for ports (defaults to 0 on failure)
    src_port = _safe_int(row.get("Src port", "0"))
    dst_port = _safe_int(row.get("Dst port", "0"))

    return {
        "timestamp": timestamp,
        "log_component": row.get("log component", "").strip(),
        "action": row.get("Log subtype", "").strip(),  # Allowed / Denied
        "username": row.get("Username", "").strip(),
        "firewall_rule_id": row.get("Firewall rule", "").strip(),
        "firewall_rule_name": row.get("Firewall rule name", "").strip(),
        "nat_rule": row.get("NAT rule", "").strip(),
        "nat_rule_name": row.get("NAT rule name", "").strip(),
        "in_interface": row.get("In interface", "").strip(),
        "out_interface": row.get("Out interface", "").strip(),
        "src_ip": row.get("Src IP", "").strip(),
        "dst_ip": row.get("Dst IP", "").strip(),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": row.get("protocol", "").strip(),
        "message": row.get("Message", "").strip(),
    }


def _safe_int(value: str) -> int:
    """Safely convert a string to an integer, returning 0 on failure."""
    try:
        return int(float(value.strip()))
    except (ValueError, TypeError):
        return 0


def get_log_summary(records: List[Dict]) -> Dict:
    """Generate summary statistics from the parsed log records."""
    if not records:
        return {"error": "No records found"}

    from collections import Counter

    actions = Counter(r["action"] for r in records)
    protocols = Counter(r["protocol"] for r in records)
    src_ips = Counter(r["src_ip"] for r in records)
    dst_ports = Counter(r["dst_port"] for r in records)

    time_range_start = min(r["timestamp"] for r in records)
    time_range_end = max(r["timestamp"] for r in records)

    return {
        "total_records": len(records),
        "time_range": f"{time_range_start} ~ {time_range_end}",
        "duration_seconds": (time_range_end - time_range_start).total_seconds(),
        "action_counts": dict(actions),
        "protocol_counts": dict(protocols),
        "unique_src_ips": len(src_ips),
        "unique_dst_ports": len(dst_ports),
        "top_src_ips": dict(src_ips.most_common(10)),
        "top_dst_ports": dict(dst_ports.most_common(5)),
    }


def print_summary(summary: Dict) -> None:
    """Pretty-print the log summary statistics."""
    print("\n" + "=" * 55)
    print("  LOG SUMMARY")
    print("=" * 55)
    print(f"  Total records       : {summary['total_records']}")
    print(f"  Time range          : {summary['time_range']}")
    print(f"  Duration (seconds)  : {summary['duration_seconds']}")
    print(f"  Unique Src IPs      : {summary['unique_src_ips']}")
    print(f"  Unique Dst Ports    : {summary['unique_dst_ports']}")

    print("\n  [Action Distribution]")
    for action, count in summary["action_counts"].items():
        print(f"    {action:10}: {count}")

    print("\n  [Protocol Distribution]")
    for proto, count in summary["protocol_counts"].items():
        print(f"    {proto:10s}: {count}")

    print("\n  [Top Source IPs]")
    for ip, count in summary["top_src_ips"].items():
        print(f"    {ip:20s}: {count}")

    print("\n  [Top Destination Ports]")
    for port, count in summary["top_dst_ports"].items():
        print(f"    {str(port):10s}: {count}")
    print("=" * 55)


# ---------------------------------------
# Standalone test
# ---------------------------------------
if __name__ == "__main__":
    import config

    print(f"[*] Loading log file: {config.LOG_FILE_PATH}")
    records = parse_log_file(config.LOG_FILE_PATH)

    summary = get_log_summary(records)
    print_summary(summary)

    # Print sample records
    print("\n[*] First 3 records:")
    for i, r in enumerate(records[:3]):
        print(
            f"  [{i + 1}] {r['timestamp']} | {r['action']:7s} | "
            f"{r['src_ip']}:{r['src_port']} -> {r['dst_ip']}:{r['dst_port']} | "
            f"{r['protocol']} | Rule: {r['firewall_rule_name']}"
        )
