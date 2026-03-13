#!/usr/bin/env bash
#
# report-secure.sh - Analyze /var/log/secure for SSH session opened events
#
# Collates "session opened for user" events and reports on the list of users.
# Handles both current and older compressed logs.
# Suitable for running as a cron job.
#
# Usage: report-secure.sh [-l <log_dir>] [-d <days>] [-a] [-x] [-t] [-h]
#   -l <log_dir>  Directory containing secure logs (default: /var/log)
#   -d <days>     Only collate events from the last <days> days (default: all available logs)
#   -a            Also collate and report authentication type (Accepted events)
#   -x            Cross-tabulate authentication method by user (implies -a)
#   -t            Simple table output: tab-separated username and count per line, no decorations
#   -h            Show this help message
#
# Cron example (daily at 06:00):
#   0 6 * * * /usr/local/sbin/report-secure.sh | mail -s "SSH Session Report" root

set -euo pipefail

LOG_DIR="/var/log"
DAYS=0
DAYS_SET=0
AUTH_TYPE=0
CROSS_TAB=0
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

while getopts ":l:d:axth" opt; do
    case "$opt" in
        l) LOG_DIR="$OPTARG" ;;
        d) DAYS="$OPTARG"; DAYS_SET=1 ;;
        a) AUTH_TYPE=1 ;;
        x) CROSS_TAB=1; AUTH_TYPE=1 ;;
        t) TABLE_ONLY=1 ;;
        h) usage ;;
        :) die "Option -${OPTARG} requires an argument." ;;
        \?) die "Unknown option: -${OPTARG}" ;;
    esac
done

if [[ "$DAYS_SET" -eq 1 ]]; then
    [[ "$DAYS" =~ ^[1-9][0-9]*$ ]] || die "Option -d requires a positive integer."
fi

if [[ "$DAYS" -gt 0 ]]; then
    CUTOFF_EPOCH=$(date -d "${DAYS} days ago" '+%s') \
        || die "Option -d: failed to compute cutoff date."
fi

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

# Filter syslog-format lines to only those dated within the last DAYS days.
# Expects lines beginning with "Mon DD HH:MM:SS".  Lines that cannot be parsed
# are passed through unchanged so that no events are silently dropped.
filter_by_date() {
    local cutoff_epoch="$1"
    local current_year now_epoch
    current_year=$(date '+%Y')
    now_epoch=$(date '+%s')
    awk -v cutoff="$cutoff_epoch" -v year="$current_year" -v now="$now_epoch" '
    BEGIN {
        n = split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", a)
        for (i = 1; i <= n; i++) mon[a[i]] = i
    }
    {
        if (!($1 in mon)) { next }  # drop lines with no recognisable syslog timestamp
        split($3, t, ":")
        epoch = mktime(year " " mon[$1] " " int($2) " " t[1] " " t[2] " " t[3])
        if (epoch > now) {
            # Timestamp appears to be in the future: assume previous year (year rollover).
            epoch = mktime((year - 1) " " mon[$1] " " int($2) " " t[1] " " t[2] " " t[3])
        }
        if (epoch >= cutoff) print
    }'
}

# Parse all log files and build a sorted username frequency table.
declare -A user_count=()
declare -A auth_count=()
declare -A cross_count=()

while IFS= read -r line; do
    # Match lines such as:
    #   Mar 12 10:00:01 host sshd[123]: pam_unix(sshd:session): session opened for user alice by (uid=0)
    if [[ "$line" =~ session\ opened\ for\ user\ ([^[:space:]]+) ]]; then
        user="${BASH_REMATCH[1]}"
        user_count["$user"]=$(( ${user_count["$user"]:-0} + 1 ))
    fi
    # Match lines such as:
    #   Mar 12 10:00:01 host sshd[123]: Accepted publickey for alice from 192.168.1.1 port 22 ssh2
    if [[ "$AUTH_TYPE" -eq 1 ]] && [[ "$line" =~ Accepted[[:space:]]([^[:space:]]+)[[:space:]]for[[:space:]]([^[:space:]]+) ]]; then
        method="${BASH_REMATCH[1]}"
        auth_user="${BASH_REMATCH[2]}"
        auth_count["$method"]=$(( ${auth_count["$method"]:-0} + 1 ))
        [[ "$CROSS_TAB" -eq 1 ]] && cross_count["${auth_user}"$'\t'"${method}"]=$(( ${cross_count["${auth_user}"$'\t'"${method}"]:-0} + 1 ))
    fi
done < <(
    for f in "${LOG_FILES[@]}"; do
        extract_events "$f"
    done | if [[ "$DAYS" -gt 0 ]]; then filter_by_date "$CUTOFF_EPOCH"; else cat; fi
)

# Report
if [[ "$TABLE_ONLY" -eq 1 ]]; then
    # Simple table: one "USER COUNT" line per user, sorted by count desc then name asc
    for user in "${!user_count[@]}"; do
        printf "%d %s\n" "${user_count[$user]}" "$user"
    done | sort -k1,1rn -k2,2 | while read -r count user; do
        printf "%s\t%d\n" "$user" "$count"
    done

    if [[ "$AUTH_TYPE" -eq 1 ]] && [[ ${#auth_count[@]} -gt 0 ]]; then
        echo ""
        for method in "${!auth_count[@]}"; do
            printf "%d %s\n" "${auth_count[$method]}" "$method"
        done | sort -k1,1rn -k2,2 | while read -r count method; do
            printf "%s\t%d\n" "$method" "$count"
        done
    fi

    if [[ "$CROSS_TAB" -eq 1 ]] && [[ ${#cross_count[@]} -gt 0 ]]; then
        echo ""
        for key in "${!cross_count[@]}"; do
            xuser="${key%%$'\t'*}"
            xmethod="${key##*$'\t'}"
            printf "%s\t%s\t%d\n" "$xuser" "$xmethod" "${cross_count[$key]}"
        done | sort -k1,1 -k3,3rn -k2,2
    fi
    exit 0
fi

echo "============================================================"
echo " SSH Session Report"
echo " Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
if [[ "$DAYS" -gt 0 ]]; then
    echo " Period    : Last ${DAYS} day(s)"
fi
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

if [[ "$AUTH_TYPE" -eq 1 ]]; then
    echo ""
    echo "Authentication methods:"
    echo ""
    if [[ ${#auth_count[@]} -eq 0 ]]; then
        echo "  No 'Accepted' authentication events found."
    else
        printf "  %-30s  %s\n" "METHOD" "COUNT"
        printf "  %-30s  %s\n" "------------------------------" "-----"

        for method in "${!auth_count[@]}"; do
            printf "%s %s\n" "${auth_count[$method]}" "$method"
        done | sort -k1,1rn -k2,2 | while read -r count method; do
            printf "  %-30s  %d\n" "$method" "$count"
        done

        echo ""
        auth_total=0
        for c in "${auth_count[@]}"; do
            auth_total=$(( auth_total + c ))
        done
        echo "  Total authentications : ${auth_total}"
        echo "  Unique methods        : ${#auth_count[@]}"
    fi
fi

if [[ "$CROSS_TAB" -eq 1 ]]; then
    echo ""
    echo "Authentication methods by user:"
    echo ""
    if [[ ${#cross_count[@]} -eq 0 ]]; then
        echo "  No 'Accepted' authentication events found."
    else
        printf "  %-20s  %-30s  %s\n" "USER" "METHOD" "COUNT"
        printf "  %-20s  %-30s  %s\n" "--------------------" "------------------------------" "-----"

        for key in "${!cross_count[@]}"; do
            xuser="${key%%$'\t'*}"
            xmethod="${key##*$'\t'}"
            printf "%s\t%s\t%d\n" "$xuser" "$xmethod" "${cross_count[$key]}"
        done | sort -k1,1 -k3,3rn -k2,2 | while IFS=$'\t' read -r xuser xmethod xcount; do
            printf "  %-20s  %-30s  %d\n" "$xuser" "$xmethod" "$xcount"
        done
    fi
fi

echo ""
echo "============================================================"
