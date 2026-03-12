# report-secure

A Bash script that analyzes `/var/log/secure` for SSH session events and produces a
human-readable report.

## Features

* Collates all **"session opened for user"** events from `sshd`/PAM log lines.
* Reports the list of users and the number of sessions opened per user.
* Handles the **current log** as well as **older rotated and compressed logs**
  (`.gz`, numbered rotations, date-stamped rotations).
* Designed to run unattended as a **cron job** and email its output.

## Usage

```
report-secure.sh [-l <log_dir>] [-d <days>] [-t] [-h]

  -l <log_dir>   Directory containing secure logs (default: /var/log)
  -d <days>      Only collate events from the last <days> days (default: all available logs)
  -t             Simple table output: tab-separated username and count per line, no decorations
  -h             Show help message
```

### Examples

```bash
# Analyze the default /var/log/secure (and rotated copies)
sudo ./report-secure.sh

# Analyze logs in a custom directory
./report-secure.sh -l /var/log/secure-archive

# Only collate events from the last 7 days
./report-secure.sh -d 7

# Last 30 days, simple table output
./report-secure.sh -d 30 -t

# Output a simple table (user and session count only)
./report-secure.sh -t

# Show help
./report-secure.sh -h
```

### Sample output

```
============================================================
 SSH Session Report
 Generated: 2026-03-12 06:00:01 UTC
 Period    : Last 7 day(s)
 Log source: /var/log/secure{,.gz,.N,.N.gz,-YYYYMMDD{,.gz}}
============================================================

Sessions opened per user:

  USER                  COUNT
  --------------------  -----
  alice                 42
  bob                   17
  charlie               3

  Total sessions : 62
  Unique users   : 3

============================================================
```

When `-d` is omitted, all available log files are processed and the `Period` line is not shown.

### Simple table output (`-t`)

Use `-t` to get a compact, tab-separated list of users and session counts — useful
for piping into other tools or scripts:

```
alice	42
bob	17
charlie	3
```

## Installation

```bash
sudo cp report-secure.sh /usr/local/sbin/report-secure.sh
sudo chmod 750 /usr/local/sbin/report-secure.sh
```

## Running as a cron job

Add an entry to root's crontab (`sudo crontab -e`) to receive a daily report by email:

```cron
# SSH session report – every day at 06:00
0 6 * * * /usr/local/sbin/report-secure.sh | mail -s "SSH Session Report $(hostname)" root
```

Or redirect to a file:

```cron
0 6 * * * /usr/local/sbin/report-secure.sh > /var/log/ssh-session-report.log 2>&1
```

## Log files processed

The script discovers and processes (in sorted order) all files in the log directory
that match the following patterns:

| Pattern | Description |
|---|---|
| `secure` | Current log |
| `secure.N` | Numbered rotation (e.g. `secure.1`) |
| `secure-YYYYMMDD` | Date-stamped rotation |
| `secure.gz` | Compressed current log |
| `secure.N.gz` | Compressed numbered rotation |
| `secure-YYYYMMDD.gz` | Compressed date-stamped rotation |