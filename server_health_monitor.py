#!/usr/bin/env python3

import subprocess

"""
server_health_monitor.py

This script scans "/var/log/auth.log" for

Author: Jacob Pruett
Date:
"""


def get_login_summary():
    """
    Receives: None
    Returns: dictionary of IP addresses
    Description: scans and parses auth.log. Tracks the number of
        successful and failed login attempts by IP.
    """
    ip_fails_and_success = {}

    with open("/var/log/auth.log", "r") as f:
        for newline in f:
            # filter for accepted/failed criteria
            if "Failed password" in newline or "Accepted password" in newline:
                words = newline.split()
                ip = words[8]
                # create dictionary entry
                if ip not in ip_fails_and_success:
                    ip_fails_and_success[ip] = {
                        "successful_logins": 0,
                        "failed_logins": 0
                    }
                # update failures or successes
                if "Failed password" in newline:
                    ip_fails_and_success[ip]["failed_logins"] += 1
                elif "Accepted password" in newline:
                    ip_fails_and_success[ip]["successful_logins"] += 1

        return ip_fails_and_success



def get_disk_usage():
    result = subprocess.run(["df", "-h"], capture_output=True, text=True)

    if result.returncode != 0:
        return None

    return result.stdout


def get_package_updates():
    result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)

    if result.returncode != 0:
        return None

    return result.stdout


def make_report():
    text = []
    summary = get_login_summary()
    disk_usage = get_disk_usage()
    package_updates = get_package_updates()

    if summary:
        for ip in summary:
            text.append(f"IP:{ip} registered {summary[ip]['successful_logins']} successful logins"
                        f" and {summary[ip]['failed_logins']} failed logins.")

    if disk_usage:
        text.append(f"---Disk Usage---\n {disk_usage}")

    if package_updates:
        text.append(f"---Package Updates---\n {package_updates}")

    return "\n".join(text)

report_object = make_report()
print(report_object)

with open("server_health_report.txt", "w") as f:
    f.write(report_object)
















