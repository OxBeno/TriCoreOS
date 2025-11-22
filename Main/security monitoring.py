#!/usr/bin/env python3
"""
OS Security Hardening Script
Simple security assessment and hardening tool
"""

import os
import sys
import subprocess
import platform
import getpass
from pathlib import Path

def run_command(cmd):
    """Execute a system command"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

def check_root():
    """Check for root privileges"""
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        print("Try: sudo python3 os_security.py")
        sys.exit(1)

def get_system_info():
    """Gather system information"""
    print("Collecting system information...")
    system = platform.system()
    
    try:
        with open('/etc/os-release', 'r') as f:
            lines = f.readlines()
            distro_info = {}
            for line in lines:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    distro_info[key] = value.strip('"')
        distro = distro_info.get('PRETTY_NAME', 'Unknown')
    except:
        distro = "Unknown"
    
    print(f"System: {system}")
    print(f"Distribution: {distro}")
    return system

def update_system():
    """Update the system packages"""
    print("Updating system...")
    
    code, out, err = run_command("apt update && apt upgrade -y")
    if code == 0:
        print("System updated successfully")
    else:
        print("Failed to update system")

def check_firewall():
    """Check firewall status"""
    print("Checking firewall...")
    
    code, out, err = run_command("ufw status")
    if "inactive" in out:
        print("Firewall is inactive")
        enable = input("Enable UFW? (y/n): ")
        if enable.lower() == 'y':
            run_command("ufw enable")
            print("Firewall enabled")
    else:
        print("Firewall is active")

def check_ssh_security():
    """Check SSH security settings"""
    print("Checking SSH configuration...")
    
    ssh_config = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config):
        with open(ssh_config, 'r') as f:
            content = f.read()
            
        security_settings = {
            "PasswordAuthentication": "no",
            "PermitRootLogin": "no", 
            "Protocol": "2"
        }
        
        for setting, expected in security_settings.items():
            if f"{setting} {expected}" in content or f"{setting}\t{expected}" in content:
                print(f"SSH setting correct: {setting} = {expected}")
            else:
                print(f"SSH setting needs review: {setting}")

def scan_open_ports():
    """Scan for open ports"""
    print("Scanning open ports...")
    
    code, out, err = run_command("netstat -tuln")
    if code == 0:
        lines = out.split('\n')
        open_ports = [line for line in lines if "LISTEN" in line]
        
        print(f"Open ports found: {len(open_ports)}")
        for port in open_ports[:5]:
            print(port)

def check_sudo_users():
    """Check sudo users"""
    print("Checking sudo users...")
    
    code, out, err = run_command("getent group sudo")
    if code == 0:
        print("Sudo users group:")
        print(out.strip())

def system_audit():
    """Perform system security audit"""
    print("Running system security audit...")
    
    audit_checks = [
        ("SUID files", "find / -perm -4000 2>/dev/null | head -10"),
        ("SGID files", "find / -perm -2000 2>/dev/null | head -10"),
        ("World-writable files", "find / -perm -o+w 2>/dev/null | head -10"),
        ("User cron jobs", "crontab -l 2>/dev/null || echo 'No user crontab'")
    ]
    
    for check_name, cmd in audit_checks:
        print(f"Checking: {check_name}")
        code, out, err = run_command(cmd)
        if out.strip():
            print(out.strip())
        else:
            print("No issues found")

def generate_report():
    """Generate security report"""
    print("Generating security report...")
    
    report = []
    report.append("=" * 50)
    report.append("System Security Report")
    report.append("=" * 50)
    
    system = platform.system()
    report.append(f"System: {system}")
    report.append(f"User: {getpass.getuser()}")
    
    code, out, err = run_command("apt list --upgradable 2>/dev/null | wc -l")
    updates = int(out.strip()) - 1 if out.strip().isdigit() else 0
    report.append(f"Available updates: {updates}")
    
    code, out, err = run_command("ufw status")
    firewall_status = "Active" if "active" in out else "Inactive"
    report.append(f"Firewall: {firewall_status}")
    
    report_path = "/tmp/security_report.txt"
    with open(report_path, 'w') as f:
        f.write('\n'.join(report))
    
    print(f"Report saved to: {report_path}")

def check_fail2ban():
    """Check if fail2ban is installed and running"""
    print("Checking fail2ban...")
    
    code, out, err = run_command("systemctl is-active fail2ban")
    if code == 0 and "active" in out:
        print("Fail2ban is running")
    else:
        print("Fail2ban is not installed or not running")

def check_automatic_updates():
    """Check if automatic updates are configured"""
    print("Checking automatic updates...")
    
    code, out, err = run_command("systemctl is-enabled unattended-upgrades")
    if code == 0 and "enabled" in out:
        print("Automatic updates are enabled")
    else:
        print("Automatic updates are not enabled")

def main():
    """Main function"""
    print("OS Security Hardening Tool")
    print("=" * 40)
    
    check_root()
    system_info = get_system_info()
    
    while True:
        print("\nAvailable actions:")
        print("1. Update system")
        print("2. Check firewall")
        print("3. Check SSH security")
        print("4. Scan open ports")
        print("5. Check sudo users")
        print("6. System security audit")
        print("7. Check fail2ban")
        print("8. Check automatic updates")
        print("9. Generate security report")
        print("10. Exit")
        
        choice = input("Enter your choice (1-10): ")
        
        if choice == '1':
            update_system()
        elif choice == '2':
            check_firewall()
        elif choice == '3':
            check_ssh_security()
        elif choice == '4':
            scan_open_ports()
        elif choice == '5':
            check_sudo_users()
        elif choice == '6':
            system_audit()
        elif choice == '7':
            check_fail2ban()
        elif choice == '8':
            check_automatic_updates()
        elif choice == '9':
            generate_report()
        elif choice == '10':
            print("Exiting...")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
