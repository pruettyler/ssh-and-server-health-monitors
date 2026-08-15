# Project Title

"SSH Login and Server Health Monitors"

## Overview

This program consists of two scripts. 

"ssh_login_monitor.py" tracks ssh login attempts "continuously" via a while loop set to run for a specified amount of time. 
It parses the ssh authorization log and aggregates the data into relevant dictionaries and "event" lists that 
contain all of the raw login data. It then scans these dictionaries using four general detection patterns: 
(1) unusually high number of login failures
(2) a username paired with an unusually high number of unique IP addresses 
(3) an IP address connected to an unusually high number of unique usernames (i.e., password spraying) 
(4) "breakthrough logins" (i.e., successful logins from usernames that were also flagged for too many failures) 
During the monitoring window, it calls make_report() at regular intervals, thus providing regular snapshots of the network's SSH login
activity.

"server_health_check.py" also tracks login accepted/failed by IP, along with five basic Linux-system health metrics: disk usage,
package updates, uptime, memory usage, and CPU usage. The "server_health_check.py" runs once, per python execution. It's get_ssh_login_summary()
function scans the entire authorization log from top to bottom (thus providing a comprehensive view of IP accepted/failed), but its 
health metrics utilize Linux utility shell commands that describe only the most recent system states.  

## Architecture / Design

This program is divided into two areas of interest: server security, and server health.

"ssh_login_monitor.py" is the security engine. In addition to aggregating data into scoped dictionaries (failed_by_ip, failed_by_user, accepted_by_user). 
It also retains all the raw event data for use in future security detection/cross-referencing.
The overall goal of this parsing and aggregation logic is to process the data once, as the newline is read, rather than rescanning the raw "event" data every time. 
Thus, detection functions can perform their security logic via a single dictionary lookup rather than repeated O(n) scans. 

Every detection function utilizes the recent_filter() helper function, which limits the security checks to a specified 
time threshold. Every function follows the same structure: return None or return the raw data in the form of a set or a dictionary. 
make_report() is tasked with transforming this detection data into readable text output, thus keeping detection logic separate from presentation.

"server_health_check.py" has six functions in total. get_ssh_login_summary() aggregates the total number of failed and accepted 
logins by IP. This is data that could also be assembled via "ssh_login_monitor.py" but which is also valuable for a picture
of overall server health. The other five functions use subprocess() to perform shell commands on standard Linux utilities. The specific
commands are scoped to Ubuntu OS/AWS AMI. This script is designed as a static, one-shot complement to the continuous monitoring architecture 
of "ssh_login_monitor.py".

## Changes to Version 2:

Version 2 of "ssh_login_monitor.py" shifts from single execution to continuous monitoring. Parsing and aggregation of dictionaries 
was moved into scan_auth_log() which is now called iteratively in main(). make_report() was also moved into main() and 
is now called and written to an external file at regular intervals. Ongoing read/write actions are accomplished
via byte-offset tracking. The other major change involves the helper function recent_filter() which calculates the difference 
between a basetime object gathered from a dictionary and the current utc time and returns a 
Boolean based on whether that difference falls within a specified time threshold. recent_filter() is integrated into all the 
detection functions. This represents a substantial improvement on the security capabilities
of version 1, which had no way of determining time thresholds, or cross-referencing failed and accepted logins 
in breakthrough_logins(). 

Version 2 of "server_health_check.py" remains a single-run, static report, but adds three additional Linux utility metrics (uptime, memory 
usage and cpu usage). It also makes its Ubuntu OS scope explicit, while also baking in defensive try/except blocks to ensure more 
seamless reporting. 

## How to Run

Requirements:
- Python 3.10+ (no external packages — uses only Python's standard library: `datetime`, `subprocess`)
- A Linux system with `/var/log/auth.log` present (tested on Ubuntu Server 24.04)
- Read permissions on `/var/log/auth.log` (may require running with `sudo` depending on your system's log permissions)

### Option 1:

Setup:
- Copy both `ssh_login_monitor.py` and `server_health_check.py` onto the target server, e.g. via `scp`: 
```
scp ssh_login_monitor.py server_health_check.py user@your-server:~
```
Running:
- SSH into the server, then run either script directly:
```
python3 ssh_login_monitor.py
python3 server_health_monitor.py
```
### Option 2: (ssh_login_monitor only)

Setup:
- `ssh_login_monitor.py` is also designed to be run continuously on an EC2 instance via a systemd-managed daemon using
the included `ssh-monitor.service` file. See [aws-network-provisioning repo] for the Terraform user_data that installs 
and enables it automatically at boot.

Output:
- Each script prints its report to the console, and also writes the same report to a text file in the current directory:
- `ssh_login_monitor.py` → `ssh_login_report.txt`
- `server_health_check.py` → `server_health_report.txt`

## Example Output 

(1) from ssh_login_monitor.py

```
slothrop@ubuntu-lab-space:~/Python_Scripts$ python3 ssh_login_monitor.py
Users: bob registered more than 5 failures within a 5 minute window.
IPs: 10.0.2.2 registered more than 5 failures within a 5 minute window.

IPs: 10.0.2.2 registered more than 5 failures within a 5 minute window.

Users: slothrop registered more than 5 failures within a 5 minute window.
IPs: 10.0.2.2 registered more than 5 failures within a 5 minute window.
This IP: 10.0.2.2 is also linked to a username that broke through.
Users: slothrop registered more than 5 failures and then succeeded.

IPs: 10.0.2.2 registered more than 5 failures within a 5 minute window.
This flagged IP: 10.0.2.2 also registered more than 5 usernames: {'olive', 'jinna', 'jake', 'paz', 'kexin', 'jack'}.

Users: slothrop registered more than 5 failures within a 5 minute window.
IPs: 10.0.2.2 registered more than 5 failures within a 5 minute window.
```
(2) Example auth.log entry:
This does not fit the standard accepted/failed pattern; ssh_login_monitor.py will register this a "probe event"
```
2026-08-14T22:34:26.160339+00:00 ubuntu-lab-space sshd-session[2709]: Connection closed by authenticating user slothrop 10.0.2.2 port 59754 [preauth]
```

(3) from server_health_check.py

```
slothrop@ubuntu-lab-space:~/Python_Scripts$ python3 server_health_check.py
IP:10.0.2.2 registered 11 successful logins and 49 failed logins.
---Disk Usage---
 Filesystem                         Size  Used Avail Use% Mounted on
tmpfs                              329M  1.1M  328M   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv   12G  5.0G  5.7G  47% /
tmpfs                              822M     0  822M   0% /dev/shm
none                               1.0M     0  1.0M   0% /run/credentials/systemd-journald.service
none                               1.0M     0  1.0M   0% /run/credentials/systemd-resolved.service
tmpfs                              822M     0  822M   0% /tmp
/dev/sda2                          2.0G   96M  1.7G   6% /boot
none                               1.0M     0  1.0M   0% /run/credentials/systemd-networkd.service
none                               1.0M     0  1.0M   0% /run/credentials/getty@tty1.service
tmpfs                              165M  8.0K  165M   1% /run/user/1000
---Package Updates---
 Listing...
---Uptime---
 up 3 minutes
---Memory Usage---
 total        used        free      shared  buff/cache   available
Mem:           1.6Gi       349Mi       1.0Gi       1.0Mi       412Mi       1.3Gi
Swap:          2.0Gi          0B       2.0Gi
---CPU Usage---
 %Cpu(s):  0.0 us,  0.0 sy,  0.0 ni, 95.0 id,  0.0 wa,  0.0 hi,  5.0 si,  0.0 st
```

## Known Limitations / Future Work

One deliberate simplification: "too_many_unique_ips()" and "too_many_unique_usernames()" are structurally identical and
have been made separate to clarify the detection patterns. Thus, a shared helper function would reduce duplications in
future iterations of this script. Currently, the make_report() function does not output probe events. These probe events
(dictionaries) are currently parsed into a list, but not subjected to further detection logic. 

## Author

Jacob Pruett. These scripts were created as part of a self-directed cloud/DevOps project. 