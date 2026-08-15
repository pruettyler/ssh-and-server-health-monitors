#!/usr/bin/env python3

import subprocess

"""
server_health_check.py

This script contains several functions for assessing the health of a server. 
get_ssh_login_summary scans "/var/log/auth.log" for successful and failed 
SSH login attempts,and aggregates this into a dictionary for compiling a report. 
There are also five subprocess functions that perform shell commands on standard
Linux Utilities (note: these functions assume Ubuntu OS/default Ubuntu AMI). These 
return the standard output on Linux systems for disk usage, package updates, uptime, 
memory usage, and CPU usage. There is a make_report() function that compiles this data 
into easy-to-read text output. The main() function runs once per script run, thus
providing a snapshot of the current health metrics of the network.

Author: Jacob Pruett
Date: 2026-08-04

"""

# ------------------------------------------------------------------------------------------
# DATA AGGREGATION & PARSING 
# ------------------------------------------------------------------------------------------

def get_ssh_login_summary():
    """
    Receives: None
    Returns: dictionary of IP addresses.
    Description: scans and parses auth.log. Tracks the number of
        successful and failed login attempts by IP.
    """
    ip_fails_and_success = {}

    with open("/var/log/auth.log", "r") as f:
        for newline in f:

            # filter for accepted/failed criteria
            if "Failed password" in newline:
                # account for "invalid user" case and additional newline elements
                if "invalid user" in newline:
                    words = newline.split()
                    ip = words[10]

                    # check if IP already in dictionary
                    if ip not in ip_fails_and_success:
                        ip_fails_and_success[ip] = {
                            "successful_logins": 0,
                            "failed_logins": 0
                        }

                else:
                    words = newline.split()
                    ip = words[8]
                    # check if IP already in dictionary
                    if ip not in ip_fails_and_success:
                          ip_fails_and_success[ip] = {
                            "successful_logins": 0,
                            "failed_logins": 0
                        }

                # update dictionary
                ip_fails_and_success[ip]["failed_logins"] += 1


            # note: "Accepted password", and "Accepted publickey" yield same IP index       
            elif "Accepted password" in newline or "Accepted publickey" in newline:
                words = newline.split()
                ip = words[8]

                if ip not in ip_fails_and_success:
                    ip_fails_and_success[ip] = {
                        "successful_logins": 0,
                        "failed_logins": 0
                    }
                ip_fails_and_success[ip]["successful_logins"] += 1

            else:
                continue

        return ip_fails_and_success

# ------------------------------------------------------------------------------------------
# SUBPROCESS FUNCTIONS FOR STANDARD LINUX UTILITIES  
# ------------------------------------------------------------------------------------------

def get_disk_usage():
    """
    Receives: None
    Returns: string (stdout for "df -h") or None if command fails.
    Description: uses subprocess for capturing the standard
        output for disk_usage command.
    """
    try:
        result = subprocess.run(
            ["df", "-h"],
            capture_output=True, text=True
            )
    except FileNotFoundError:
        return None
    
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def get_package_updates():
    """
    Receives: None
    Returns: string (stdout for "apt list --upgradable") or None if command fails.
    Description: uses subprocess for capturing the standard
        output for package updates command.
    """
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"], 
            capture_output=True, text=True
            )
    except FileNotFoundError:
        return None
    
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def get_uptime():
    """
    Receives: None
    Returns: string (stdout for "uptime -p") or None if command fails.
    Description: uses subprocess for capturing the standard
        output for uptime command.
    """
    try:
        result = subprocess.run(
            ["uptime", "-p"],
            capture_output=True, text=True
            )
    except FileNotFoundError:
        return None
    
    if result.returncode != 0:
        return None
    return result.stdout.strip()

def get_memory_usage():
    """
    Receives: None
    Returns: string (stdout for "free -h") or None if command fails.
    Description: uses subprocess for capturing the standard
        output for memory usage command.
    """
    try:
        result = subprocess.run(
            ["free", "-h"],
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        return None
    
    if result.returncode != 0:
        return None
    return result.stdout.strip()

def get_cpu_usage():
    """
    Receives: None
    Returns: string (stdout for "top -bn1") or None if command fails,
        or the expected CPU line is not found.
    Description: uses subprocess for capturing the standard
        output for CPU usage command. This stdout is filtered and only 
        the CPU usage line is returned.
    """
    try:
        result = subprocess.run(
            ["top", "-bn1"],
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        return None
    
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if "Cpu(s)" in line:
            return line
    return None


# ------------------------------------------------------------------------------------------
# REPORTING
# ------------------------------------------------------------------------------------------

def make_report():
    """
    Receives: None
    Returns: string -- text that combines all server health function results joined with newlines.
    Description: executes each of the six server health functions and appends the output to 
        a list, along with a contextualizing message for each result.
    """
    text = []
    summary = get_ssh_login_summary()
    disk_usage = get_disk_usage()
    package_updates = get_package_updates()
    uptime = get_uptime()
    memory_usage = get_memory_usage()
    cpu_usage = get_cpu_usage()

    if summary:
        for ip in summary:
            text.append(f"IP:{ip} registered {summary[ip]['successful_logins']} successful logins"
                        f" and {summary[ip]['failed_logins']} failed logins.")

    if disk_usage:
        text.append(f"---Disk Usage---\n {disk_usage}")

    if package_updates:
        text.append(f"---Package Updates---\n {package_updates}")

    if uptime:
        text.append(f"---Uptime---\n {uptime}")

    if memory_usage:
        text.append(f"---Memory Usage---\n {memory_usage}")

    if cpu_usage:
        text.append(f"---CPU Usage--- \n {cpu_usage}")

    return "\n".join(text)


# ------------------------------------------------------------------------------------------
# MAIN -- collect metrics and generate report (once per run)
# ------------------------------------------------------------------------------------------

def main():
    """
    Receives: None
    Returns: None
    Description: generates one health report per execution. It prints report_object
        and writes report_object to a text file "server_health_report.txt".
    """

    report_object = make_report()
    print(report_object)

    with open("server_health_report.txt", "w") as f:
        f.write(report_object)

if __name__ == "__main__":
    main()