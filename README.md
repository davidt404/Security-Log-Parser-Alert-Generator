Bash Security Audit Tool
Linux security baseline audit script that checks common security configurations and generates a report.
What It Checks

Failed login attempts
Firewall status (UFW/iptables)
Open listening ports
Users with empty passwords
World-writable files in critical directories
Last system update
SSH configuration (root login, password auth)
Running services

Usage
bashchmod +x security-audit.sh
sudo ./security-audit.sh
Generates a timestamped report: security_audit_YYYYMMDD_HHMMSS.txt
Output

[PASS] - Check passed
[FAIL] - Issue found
[WARN] - Review needed

Requirements

Linux (tested on Ubuntu/Debian and RHEL/CentOS)
Sudo access
