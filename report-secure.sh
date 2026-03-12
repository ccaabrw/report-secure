#!/usr/bin/env bash
#
# report-secure.sh - Analyze /var/log/secure for SSH session opened events
#
# Collates "session opened for user" events and reports on the list of users.
# Handles both current and older compressed logs.
# Suitable for running as a cron job.
#
# Usage: report-secure.sh [-l <log_dir>] [-t] [-h]
#   -l <log_dir>  Directory containing secure logs (default: /var/log)
#   -t            Simple table output: tab-separated username and count per line, no decorations
#   -h            Show this help message
#
# Cron example (daily at 06:00):
#   0 6 * * * /usr/local/sbin/report-secure.sh | mail -s "SSH Session Report" root

set -euo pipefail

LOG_DIR="/var/log"
TABLE_ONLY=0
PROG="$(basename "$0")"

usage() {
    # Print the contiguous leading comment block (after the shebang line)
    awk '/^#!/{next} /^#/{sub(/^# ?/,""); print; next} /^[^#]/{exit}' "$0"
    exit 0
}

die() {
    echo "${PROG}: error: $*" >&2
    exit 1
}

while getopts ":l:th" opt; do
    case "$opt" in
        l) LOG_DIR="$OPTARG" ;;
        t) TABLE_ONLY=1 ;;
        h) usage ;;
        :) die "Option -${OPTARG} requires an argument." ;;
        \?) die "Unknown option: -${OPTARG}" ;;
    esac
done

[[ -d "$LOG_DIR" ]] || die "Log directory not found: ${LOG_DIR}"

SECURE_PATTERN="${LOG_DIR}/secure"

# Collect all matching log files: current, rotated, and compressed.
# Files are sorted so output is processed in a consistent order.
mapfile -t LOG_FILES < <(
    find "$LOG_DIR" -maxdepth 1 \( \
        -name "secure" -o \
        -name "secure.[0-9]*" -o \
        -name "secure-[0-9]*" -o \
        -name "secure.gz" -o \
        -name "secure.[0-9]*.gz" -o \
        -name "secure-[0-9]*.gz" \
    \) -print 2>/dev/null | sort
)

if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
    echo "No secure log files found in ${LOG_DIR}." >&2
    exit 0
fi

# Read each log file (plain or gzip-compressed) and extract
# "session opened for user <username>" lines.
extract_events() {
    local file="$1"
    case "$file" in
        *.gz) zcat "$file" ;;
        *)    cat  "$file" ;;
    esac
}

# Parse all log files and build a sorted username frequency table.
declare -A user_count=()

while IFS= read -r line; do
    # Match lines such as:
    #   Mar 12 10:00:01 host sshd[123]: pam_unix(sshd:session): session opened for user alice by (uid=0)
    if [[ "$line" =~ session\ opened\ for\ user\ ([^[:space:]]+) ]]; then
        user="${BASH_REMATCH[1]}"
        user_count["$user"]=$(( ${user_count["$user"]:-0} + 1 ))
    fi
done < <(
    for f in "${LOG_FILES[@]}"; do
        extract_events "$f"
    done
)

# Report
if [[ "$TABLE_ONLY" -eq 1 ]]; then
    # Simple table: one "USER COUNT" line per user, sorted by count desc then name asc
    for user in "${!user_count[@]}"; do
        printf "%d %s\n" "${user_count[$user]}" "$user"
    done | sort -k1,1rn -k2,2 | while read -r count user; do
        printf "%s\t%d\n" "$user" "$count"
    done
    exit 0
fi

echo "============================================================"
echo " SSH Session Report"
echo " Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo " Log source: ${LOG_DIR}/secure{,.gz,.N,.N.gz,-YYYYMMDD{,.gz}}"
echo "============================================================"
echo ""

if [[ ${#user_count[@]} -eq 0 ]]; then
    echo "No 'session opened for user' events found."
else
    echo "Sessions opened per user:"
    echo ""
    printf "  %-20s  %s\n" "USER" "COUNT"
    printf "  %-20s  %s\n" "--------------------" "-----"

    # Sort by count (descending), then by username (ascending)
    for user in "${!user_count[@]}"; do
        printf "%s %s\n" "${user_count[$user]}" "$user"
    done | sort -k1,1rn -k2,2 | while read -r count user; do
        printf "  %-20s  %d\n" "$user" "$count"
    done

    echo ""
    total=0
    for c in "${user_count[@]}"; do
        total=$(( total + c ))
    done
    echo "  Total sessions : ${total}"
    echo "  Unique users   : ${#user_count[@]}"
fi

echo ""
echo "============================================================"
