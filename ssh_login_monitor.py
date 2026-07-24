#!/usr/bin/env python3

from datetime import datetime 

"""
ssh_login_monitor.py

This script scans "/var/log/auth.log" for new ssh login attempts.
For each new login event, it creates a dictionary with a unique event_id,
the username, ip address, port, time_stamp, and result (whether accepted or failed).
It also defines four detection functions for sorting the logs into separate
security concerns: too_many_fails(), too_many_unique_ips(), too_many_unique_usernames(), 
breakthrough_login(). It also has a make_report() function that aggregates these concerns
and formats them for writing to a file.

Author: Jacob Pruett
Date: 2026-07-04
"""

event_list = []
failed_by_user = {}
failed_by_ip = {}
accepted_by_user = {}
event_id = 1

# store, scan, and parse login events
with open("/var/log/auth.log", "r") as f:
	
	for newline in f:

		# store raw event data in event dictionary
		if "Failed password" in newline:
			words = newline.split()
			result = "failed"
			timestamp = words[0]
			time_object = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
			username = words[6]
			ip = words[8]
			port = words[10]
			event = {
				"event_id": event_id,
				"username": username,
				"ip": ip,
				"port": port,
				"timestamp": timestamp,
				"result": result
			}
			event_id += 1
			event_list.append(event)


			# aggregate failures by user in separate dictionary
			if username not in failed_by_user:
				failed_by_user[username] = {
					"ips": {ip},
					"number_of_fails": 0,
					"failure_timestamps": []
				}
			failed_by_user[username]["ips"].add(ip),
			failed_by_user[username]["number_of_fails"] += 1
			failed_by_user[username]["failure_timestamps"].append(time_object)


			# aggregate failures by IP in separate dictionary
			if ip not in failed_by_ip:
				failed_by_ip[ip] = {
					"usernames": {username},
					"number_of_fails": 0,
					"failure_timestamps": []
				}
			failed_by_ip[ip]["usernames"].add(username)
			failed_by_ip[ip]["number_of_fails"] += 1
			failed_by_ip[ip]["failure_timestamps"].append(time_object)


		# store raw event data
		elif "Accepted password" in newline:
			words = newline.split()
			result = "accepted"
			timestamp = words[0]
			time_object = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
			username = words[6]
			ip = words[8]
			port = words[10]
			event = {
				"event_id": event_id,
				"username": username,
				"ip": ip,
				"port": port,
				"timestamp": timestamp,
				"result": result
			}
			event_id += 1
			event_list.append(event)

			# aggregate accepted users in a separate dictionary
			if username not in accepted_by_user:
				accepted_by_user[username] = {
					"ips": {ip},
					"accepted_timestamps": []
				}
			accepted_by_user[username]["ips"].add(ip)
			accepted_by_user[username]["accepted_timestamps"].append(time_object)


		else:
			continue 




def too_many_fails (threshold=5):
	"""
	Receives: threshold (integer)
	Returns: tuple containing two dictionaries, one containing failures
		by username, the other containing failures by IP.
	Description: searches the failed_by_user and failed_by_ip dictionaries,
	 	and if the number of failures exceeds the thresholds, it aggregates
		that information in an appropriate dictionary and returns those dictionaries.
	"""
	
	high_fail_users = {}
	for username in failed_by_user:
		if failed_by_user[username]["number_of_fails"] > threshold:
			high_fail_users[username] = failed_by_user[username]
	high_fail_ips = {}
	for ip in failed_by_ip:
		if failed_by_ip[ip]["number_of_fails"] > threshold:
			high_fail_ips[ip] = failed_by_ip[ip]
	return high_fail_users, high_fail_ips



def too_many_unique_ips (username, threshold):
	"""
	Receives: username (string), threshold (integer)
	Returns: a set of IPs
	Description: If a username is associated with > threshold
		IP addresses, it returns a set of all the IPs this
		username is associated with.
	"""
	if username not in failed_by_user:
		return
	elif len(failed_by_user[username]["ips"]) <= threshold:
		return
	else:
		ips = failed_by_user[username]["ips"]
		return set(ips)
		
		
def too_many_unique_usernames(ip, threshold=5):
	"""
	Receives: ip (string), threshold (integer)
	Returns: a set of usernames
	Description: If an IP address is associated with > threshold
		usernames, it returns a set of all the usernames this
		IP address is associated with.
	"""
	if ip not in failed_by_ip:
		return
	elif len(failed_by_ip[ip]["usernames"]) <= threshold:
		return
	else:
		usernames = failed_by_ip[ip]["usernames"]
		return set(usernames)


def breakthrough_login():
	"""
	Receives: None
	Returns: A dictionary of usernames.
	Description: Returns a dictionary of breakthrough usernames that have
	 	'broken through' (i.e., failed > threshold) and also succeeded at
	 	logging in. This function relies on too_many_fails() and the threshold
		parameter defined therein.
	"""
	breakthrough_users = {}
	high_fail_users, high_fail_ips = too_many_fails()
	if not high_fail_users:
		return
	for user in high_fail_users:
		if user in accepted_by_user:
			breakthrough_users[user] = high_fail_users[user]

	return breakthrough_users



def make_report():
	"""
	Receives: None
	Returns: Text
	Description: calls all the security functions and if these functions have
		generated values, it assembles this raw data into explanatory text suitable
		for giving a coherent security report.
	"""

	text = []
	threshold = 5
	high_fail_users, high_fail_ips = too_many_fails(threshold)
	breakthrough_users = breakthrough_login()

	breakthrough_ips = set()
	if breakthrough_users:
		for user in breakthrough_users:
			breakthrough_ips.update(failed_by_user[user]["ips"])

	if high_fail_users:
		for user in high_fail_users:
			text.append(f"Users: {user} registered more than {threshold} failures.")

	if high_fail_ips:
		for ip in high_fail_ips:
			text.append(f"IPs: {ip} registered more than {threshold} failures.")

			if ip in breakthrough_ips:
				text.append(f"This IP: {ip} is also linked to a username that broke through.")

			password_spray = too_many_unique_usernames(ip, threshold)
			if password_spray:
				text.append(f"This flagged IP: {ip} also registered more than {threshold} usernames: {password_spray}.")

	if breakthrough_users:
		for user in breakthrough_users:
			text.append(f"Users: {user} registered more than {threshold} failures and then succeeded.")
			if too_many_unique_ips(user, threshold):
				text.append(f"User: {user} showed activity on more than {threshold} IPs.")

	return "\n".join(text) + "\n"


# call make_report() and test output via print()
report_object = make_report()
print(report_object)


# write results to report file
with open("ssh_login_report.txt", "w") as f:
	f.write(report_object)