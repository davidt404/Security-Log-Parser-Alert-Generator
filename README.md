# Bash Security Audit Tool

Linux security baseline audit script that checks common security configurations and generates a report.

##  What It Checks
- Failed login attempts  
- Firewall status (UFW / iptables)  
- Open listening ports  
- Users with empty passwords  
- World-writable files in critical directories  
- Last system update  
- SSH configuration (root login, password authentication)  
- Running services  

##  Usage
```bash
chmod +x security-audit.sh
sudo ./security-audit.sh
