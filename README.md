# Project Title

"SSH Login and Server Health Monitor"

## Overview

This program consists of two scripts. "ssh_login_monitor.py" tracks ssh login attempts by aggregating raw ssh-login-event
data and parsing that data into four general detection patterns: (1) unusually high number of login failures, (2) a
username paired with an unusually high number of unique IP addresses, (3) an IP address connected to an unusually high
number of unique usernames (i.e., password spraying) (4) "breakthrough logins" (i.e., successful logins from usernames
that were also flagged for too many failures). "server_health_monitor.py" tracks login successes/failures by IP,
along with two basic system health metrics: disk usage, and package updates. Each script outputs a report as text file.


## Architecture / Design

This program divides into two areas of interest: server security, and server health.

"ssh_login_monitor.py" is the security engine. It aggregates every unique login event in its own dictionary, and stores
these individual event dictionaries in a list. This list represents the "master" data repository. As each event is registered,
the login monitor also assembles one of three possible dictionaries (failed_by_user, failed_by_ip, and accepted_by_user).
This process aggregates the data once, during parsing, rather than rescanning the event list every time. This enables the
detection functions to answer their questions via a single dictionary lookup rather than repeated O(n) scans.

The four detection functions each check one specific pattern: too many failed logins, a user with too many unique IPs,
an IP spraying many usernames, and "breakthrough" logins in which a username that is associated with too many failures
also succeeds. Every function follows the same structure: return None or return the raw data which is either a set or 
dictionary. make_report() is tasked with transforming this detection data into readable text output, thus keeping detection
logic separate from presentation.

One deliberate simplification: "too_many_unique_ips()" and "too_many_unique_usernames()" are structurally identical and
have been made separate to clarify the detection patterns, although a shared helper function could reduce redundancy in
a future revision.

"server_health_monitor.py" has three functions. get_login_summary() aggregates the total number of failed and successful 
logins by IP. This is data that could also be assembled via "ssh_login_monitor.py" but which is also valuable for a picture
of overall server health. get_disk_usage() returns the terminal output for disk usage, while get_package_updates() returns the
output for pending or available updates.

## How to Run

Requirements:
- Python 3.10+ (no external packages — uses only Python's standard library: `datetime`, `subprocess`)
- A Linux system with `/var/log/auth.log` present (tested on Ubuntu Server 24.04)
- Read permissions on `/var/log/auth.log` (may require running with `sudo` depending on your system's log permissions)

Setup:
- Copy both scripts (`ssh_login_monitor.py`, `server_health_monitor.py`) onto the target server, e.g. via `scp`: 
```
scp ssh_login_monitor.py server_health_monitor.py user@your-server:~
```

Running:
- SSH into the server, then run either script directly:
```
python3 ssh_login_monitor.py
python3 server_health_monitor.py
```

Output:
- Each script prints its report to the console, and also writes the same report to a text file in the current directory:
- `ssh_login_monitor.py` → `ssh_login_report.txt`
- `server_health_monitor.py` → `server_health_report.txt`


## Example Output 

(1) from ssh_login_monitor.py

```
slothrop@ubuntu-lab-space:~$ python3 ssh_login_monitor.py
Users: slothrop registered more than 5 failures.
IPs: 10.0.2.2 registered more than 5 failures.
This IP: 10.0.2.2 is also linked to a username that broke through.
Users: slothrop registered more than 5 failures and then succeeded.

slothrop@ubuntu-lab-space:~$ cat ssh_login_report.txt
Users: slothrop registered more than 5 failures.
IPs: 10.0.2.2 registered more than 5 failures.
This IP: 10.0.2.2 is also linked to a username that broke through.
Users: slothrop registered more than 5 failures and then succeeded.
```

(2) from server_health_monitor.py

```
slothrop@ubuntu-lab-space:~$ cat server_health_report.txt
IP:10.0.2.2 registered 10 successful logins and 7 failed logins.
---Disk Usage---
 Filesystem                         Size  Used Avail Use% Mounted on
tmpfs                              329M  1.1M  328M   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv   12G  5.3G  5.5G  50% /
tmpfs                              822M     0  822M   0% /dev/shm
none                               1.0M     0  1.0M   0% /run/credentials/systemd-journald.service
tmpfs                              822M     0  822M   0% /tmp
/dev/sda2                          2.0G  183M  1.7G  10% /boot
none                               1.0M     0  1.0M   0% /run/credentials/getty@tty1.service
tmpfs                              165M  8.0K  165M   1% /run/user/1000
none                               1.0M     0  1.0M   0% /run/credentials/systemd-resolved.service
none                               1.0M     0  1.0M   0% /run/credentials/systemd-networkd.service

---Package Updates---
 Listing...
slothrop@ubuntu-lab-space:~$
```

## Known Limitations / Future Work

As mentioned earlier, "too_many_unique_ips()" and "too_many_unique_usernames()" share nearly identical logic. Thus, a shared
helper function would reduce duplications in future iterations of this script. Additionally, the "breakthrough_login()" functions 
does not check the timestamp differences between failure and success events, which would give a more accurate depiction of the 
breakthrough login event. 

## Author

Jacob Pruett. This script was created as part of a self-directed cloud/DevOps curriculum. 

