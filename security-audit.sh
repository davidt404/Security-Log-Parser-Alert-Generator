#!/bin/bash

# security-audit.sh
# Automated security baseline audit for Linux systems
# Checks common security configurations and generates a report

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Report file with timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="security_audit_${TIMESTAMP}.txt"

echo "================================================" | tee $REPORT_FILE
echo "    Linux Security Baseline Audit Report" | tee -a $REPORT_FILE
echo "    Date: $(date)" | tee -a $REPORT_FILE
echo "    Hostname: $(hostname)" | tee -a $REPORT_FILE
echo "================================================" | tee -a $REPORT_FILE
echo "" | tee -a $REPORT_FILE

# Function to print pass/fail
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $2" | tee -a $REPORT_FILE
    else
        echo -e "${RED}[FAIL]${NC} $2" | tee -a $REPORT_FILE
    fi
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a $REPORT_FILE
}

# Check 1: Failed Login Attempts
echo "Checking failed login attempts..." | tee -a $REPORT_FILE
if command -v lastb &> /dev/null; then
    FAILED_LOGINS=$(sudo lastb -n 10 2>/dev/null | wc -l)
    if [ $FAILED_LOGINS -gt 10 ]; then
        print_warning "Found $FAILED_LOGINS recent failed login attempts"
    else
        print_status 0 "Failed login attempts: $FAILED_LOGINS (acceptable)"
    fi
else
    print_warning "lastb command not available"
fi
echo "" | tee -a $REPORT_FILE

# Check 2: Firewall Status
echo "Checking firewall status..." | tee -a $REPORT_FILE
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(sudo ufw status | grep -i "Status: active")
    if [ -n "$UFW_STATUS" ]; then
        print_status 0 "UFW firewall is active"
    else
        print_status 1 "UFW firewall is NOT active"
    fi
elif command -v iptables &> /dev/null; then
    IPTABLES_RULES=$(sudo iptables -L | wc -l)
    if [ $IPTABLES_RULES -gt 8 ]; then
        print_status 0 "iptables firewall rules configured ($IPTABLES_RULES rules)"
    else
        print_status 1 "iptables firewall may not be properly configured"
    fi
else
    print_status 1 "No firewall detected (ufw or iptables)"
fi
echo "" | tee -a $REPORT_FILE

# Check 3: Open Ports
echo "Checking open listening ports..." | tee -a $REPORT_FILE
if command -v ss &> /dev/null; then
    LISTENING_PORTS=$(sudo ss -tuln | grep LISTEN | wc -l)
    echo "Open listening ports: $LISTENING_PORTS" | tee -a $REPORT_FILE
    sudo ss -tuln | grep LISTEN | head -10 | tee -a $REPORT_FILE
elif command -v netstat &> /dev/null; then
    LISTENING_PORTS=$(sudo netstat -tuln | grep LISTEN | wc -l)
    echo "Open listening ports: $LISTENING_PORTS" | tee -a $REPORT_FILE
    sudo netstat -tuln | grep LISTEN | head -10 | tee -a $REPORT_FILE
else
    print_warning "Neither ss nor netstat available"
fi
echo "" | tee -a $REPORT_FILE

# Check 4: Users with Empty Passwords
echo "Checking for users with empty passwords..." | tee -a $REPORT_FILE
EMPTY_PASS=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
if [ -z "$EMPTY_PASS" ]; then
    print_status 0 "No users with empty passwords found"
else
    print_status 1 "Users with empty passwords detected:"
    echo "$EMPTY_PASS" | tee -a $REPORT_FILE
fi
echo "" | tee -a $REPORT_FILE

# Check 5: World-Writable Files
echo "Checking for world-writable files in critical directories..." | tee -a $REPORT_FILE
WRITABLE_FILES=$(find /etc /usr/bin /usr/sbin -type f -perm -002 2>/dev/null | wc -l)
if [ $WRITABLE_FILES -eq 0 ]; then
    print_status 0 "No world-writable files in critical directories"
else
    print_status 1 "Found $WRITABLE_FILES world-writable files in critical directories"
    find /etc /usr/bin /usr/sbin -type f -perm -002 2>/dev/null | head -5 | tee -a $REPORT_FILE
fi
echo "" | tee -a $REPORT_FILE

# Check 6: System Updates
echo "Checking last system update..." | tee -a $REPORT_FILE
if [ -f /var/log/apt/history.log ]; then
    LAST_UPDATE=$(grep "Start-Date" /var/log/apt/history.log | tail -1 | cut -d' ' -f2)
    echo "Last APT update: $LAST_UPDATE" | tee -a $REPORT_FILE
elif [ -f /var/log/dnf.log ]; then
    LAST_UPDATE=$(tail -1 /var/log/dnf.log | cut -d' ' -f1-2)
    echo "Last DNF update: $LAST_UPDATE" | tee -a $REPORT_FILE
else
    print_warning "Unable to determine last system update"
fi
echo "" | tee -a $REPORT_FILE

# Check 7: SSH Configuration
echo "Checking SSH security configuration..." | tee -a $REPORT_FILE
if [ -f /etc/ssh/sshd_config ]; then
    ROOT_LOGIN=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
    PASS_AUTH=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
    
    if [ "$ROOT_LOGIN" = "no" ]; then
        print_status 0 "SSH root login disabled"
    else
        print_status 1 "SSH root login is enabled (PermitRootLogin: $ROOT_LOGIN)"
    fi
    
    if [ "$PASS_AUTH" = "no" ]; then
        print_status 0 "SSH password authentication disabled (key-based only)"
    else
        print_warning "SSH password authentication enabled (PasswordAuthentication: $PASS_AUTH)"
    fi
else
    print_warning "SSH configuration file not found"
fi
echo "" | tee -a $REPORT_FILE

# Check 8: Running Services
echo "Listing active services..." | tee -a $REPORT_FILE
if command -v systemctl &> /dev/null; then
    ACTIVE_SERVICES=$(systemctl list-units --type=service --state=running | grep ".service" | wc -l)
    echo "Active services: $ACTIVE_SERVICES" | tee -a $REPORT_FILE
    systemctl list-units --type=service --state=running --no-pager | head -15 | tee -a $REPORT_FILE
else
    print_warning "systemctl not available"
fi
echo "" | tee -a $REPORT_FILE

# Summary
echo "================================================" | tee -a $REPORT_FILE
echo "Audit complete. Report saved to: $REPORT_FILE" | tee -a $REPORT_FILE
echo "================================================" | tee -a $REPORT_FILE

# Provide recommendation
echo "" | tee -a $REPORT_FILE
echo "RECOMMENDATIONS:" | tee -a $REPORT_FILE
echo "- Review all [FAIL] items and remediate as needed" | tee -a $REPORT_FILE
echo "- Address [WARN] items based on your security policy" | tee -a $REPORT_FILE
echo "- Schedule regular security audits (weekly/monthly)" | tee -a $REPORT_FILE
echo "- Keep system packages up to date" | tee -a $REPORT_FILE
echo "" | tee -a $REPORT_FILE
