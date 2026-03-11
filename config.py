"""
Security Log Analyzer - Configuration
Manages API keys, detection thresholds, alert settings, and file paths.
"""

import os


# --------------------
# API Keys
# --------------------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# --------------------
# Log File Path
# --------------------
LOG_FILE_PATH = "sample_logs/new_logs.csv"

# --------------------
# Detection Thresholds
# --------------------

# Rule 1 - Repeated DENY: flag if same IP is denied N+ times within the time window
DENY_TIME_WINDOW_SEC = 300  # 5 minutes
DENY_COUNT_THRESHOLD = 3  # Lowered due to small dataset

# Rule 2 - Repeated external access: flag if an external IP connects N+ times within the window
REPEAT_TIME_WINDOW_SEC = 300  # 5 minutes
REPEAT_COUNT_THRESHOLD = 5

# Rule 3 - Unusual port access: connections to ports outside this set are flagged
COMMON_PORTS = {80, 443, 53, 123, 22, 25, 587, 993, 995, 8080, 8443}

# --------------------
# AbuseIPDB Settings
# --------------------
ABUSEIPDB_MAX_AGE_DAYS = 90  # Look back this many days for abuse reports
THREAT_SCORE_HIGH = 50  # 50+ = HIGH threat
THREAT_SCORE_MEDIUM = 25  # 25+ = MEDIUM threat

# ---------------------------------------------
# Internal IP Ranges (exclueded from analysis)
# ---------------------------------------------
INTERNAL_IP_PREFIX = (
    "192.168.",  # Common private IP range
    "10.",  # Another private IP range
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "0.0.0.0",
    "127.",
)

# ------------------------
# Report Output Directory
# ------------------------
REPORT_OUTPUT_DIR = "reports"
