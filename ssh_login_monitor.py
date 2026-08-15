#!/usr/bin/env python3

from datetime import datetime, timezone, timedelta
import time

"""
ssh_login_monitor.py

This script scans "/var/log/auth.log" for new SSH login attempts.
For each new login event, it creates a dictionary with a unique event_id,
username, IP address, port, timestamp, and result (whether accepted or failed).
It also assembles a probe_event_list that contains a dictionary entry for all 
access attempts that fall outside the success/fail pattern.

After aggregation and parsing, there are four detection functions for sorting the 
logs into separate security concerns: too_many_fails(), too_many_unique_ips(), 
too_many_unique_usernames(), and breakthrough_logins(). There are two helper functions:
recent_filter() that filters for a relevant time threshold, and breakthrough_logins_helper()
that eliminates loop clutter. Finally, there is a make_report() function that aggregates
all the security patterns into an easy-to-read format for text-file output.

main() monitors the SSH authorization log "continuously" using a while loop 
set to run for (RUN_TIME) hours. It scans the authorization log every (SCAN_INTERVAL) 
seconds, and generates a report every (REPORT_INTERVAL) seconds. There is deliberate
overlap between the time_threshold used by the detection functions (currently hardcoded to
5 minutes) and the REPORT_INTERVAL (currently hardcoded to 4 minutes). This overlap ensures
that no suspicious activity goes unrecorded, but means there will most likely be redundant
entries in some of the generated reports. Each report is appended to an external file: 
"SSH_login_report.txt".

Author: Jacob Pruett
Date: 2026-08-04
"""

# ------------------------------------------------------------------------------------------
# GLOBAL DATA STRUCTURES
# ------------------------------------------------------------------------------------------

# accepted/failed-event variables
event_list = []
failed_by_user = {}
failed_by_ip = {}
accepted_by_user = {}
event_id = 1

# probe-event variables
probe_event_id = 1
probe_event_list = []


# ------------------------------------------------------------------------------------------
# DATA AGGREGATION & PARSING 
# ------------------------------------------------------------------------------------------

def scan_auth_log():
	"""
	Receives: None
	Returns: None
	Description: modifies event_list, failed_by_user, failed_by_ip, accepted_by_user in place and 
		probe_event_list in place. At the end of iteration, this function saves/writes the current 
		byte offset to "login_offset.txt" for future, targeted iteration through the authorization log.
	"""

	global event_list, failed_by_user, failed_by_ip, accepted_by_user, event_id, probe_event_id, probe_event_list

	try:
		with open("login_offset.txt", "r") as offset_file:
			contents = offset_file.read().strip()
			if contents:
				offset = int(contents)
			else:
				offset = 0

	except FileNotFoundError:
		offset = 0


	# read and parse auth.log, starting at offset
	try:
		with open("/var/log/auth.log", "r") as login_file:

			login_file.seek(offset)
			for newline in login_file:

				# store generic attempts to probe the network (i.e., attemps that fall outside failure/success events )
				if "authenticating user" in newline:
					words = newline.split()
					timestamp = words[0]
					time_object = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
					username = words[8]
					ip = words[9]
					port = words[11]
					probe_event = {
						"event_id": probe_event_id,
						"username": username,
						"ip": ip,
						"port": port,
						"timestamp": time_object
					}
					# store each probe_event dictionary in master list
					probe_event_id += 1
					probe_event_list.append(probe_event)

				# store raw event data in event dictionary
				if "Failed password" in newline:
					# account for "invalid user" case and additional newline elements
					if "invalid user" in newline:
						words = newline.split()
						result = "failed username"
						timestamp = words[0]
						time_object = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
						username = words[8]
						ip = words[10]
						port = words[12]
						event = {
							"event_id": event_id,
							"username": username,
							"ip": ip,
							"port": port,
							"timestamp": time_object,
							"result": result
						}
						event_id += 1
						event_list.append(event)

					elif "Failed password" in newline:					
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
							"timestamp": time_object,
							"result": result
						}
						event_id += 1
						event_list.append(event)

					# aggregate failures by user in separate dictionary
					if username not in failed_by_user:
						failed_by_user[username] = {
							"ips": [],
							"number_of_fails": 0,
							"failure_timestamps": []
						}
					failed_by_user[username]["ips"].append((ip, time_object))
					failed_by_user[username]["number_of_fails"] += 1
					failed_by_user[username]["failure_timestamps"].append(time_object)

					# aggregate failures by IP in separate dictionary
					if ip not in failed_by_ip:
						failed_by_ip[ip] = {
							"usernames": [],
							"number_of_fails": 0,
							"failure_timestamps": []
						}
					failed_by_ip[ip]["usernames"].append((username, time_object))
					failed_by_ip[ip]["number_of_fails"] += 1
					failed_by_ip[ip]["failure_timestamps"].append(time_object)

				# store raw event data
				elif "Accepted password" in newline or "Accepted publickey" in newline:
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
						"timestamp": time_object,
						"result": result
					}
					event_id += 1
					event_list.append(event)

					# aggregate accepted users in a separate dictionary
					if username not in accepted_by_user:
						accepted_by_user[username] = {
							"ips": [],
							"accepted_timestamps": []
						}
					accepted_by_user[username]["ips"].append((ip, time_object))
					accepted_by_user[username]["accepted_timestamps"].append(time_object)

				else:
					continue 

			# save byte offset after each iteration
			current_offset = login_file.tell()

	except PermissionError:
				print("Error: Cannot read /var/log/auth.log. Check group membership (requires adm).")
				raise

	# save the byte offset into offset_file for the next monitoring session
	with open("login_offset.txt", "w") as offset_file:
		offset_file.write(str(current_offset))	

	

# ------------------------------------------------------------------------------------------
# DETECTION FUNCTIONS 
# ------------------------------------------------------------------------------------------

def recent_filter(time, base_time, time_threshold):
	"""
	Receives: 
		time -- a datetime object from dictionaries
		base_time -- a datetime object that must be determined by the caller
			and validated before calling the helper, via 'datetime.now(timezone.utc)'
		time_threshold (integer)
	Returns: Boolean
	Description: helper function for all subsequent security functions.
		Returns True if the difference between time and base_time <= threshold,
	 	else returns False.
	"""
	threshold = timedelta(minutes=time_threshold)
	time = time.astimezone(timezone.utc)
	base_time = base_time.astimezone(timezone.utc)
	difference = abs(base_time - time)
	if difference <= threshold:
		return True
	return False



def too_many_fails (fail_threshold=5, time_threshold=5):
	"""
	Receives: 
		fail_threshold (integer), default param
		time_threshold (integer), default param
	Returns: tuple containing two dictionaries, one containing failures
		by username, the other containing failures by IP.
	Description: searches the failed_by_user and failed_by_ip dictionaries;
		a failure is counted if it occurs within the time_threshold, if the
		number of failures exceeds the fail_threshold, this function aggregates
		that information in the appropriate dictionary and returns those dictionaries.
	"""

	now = datetime.now(timezone.utc)
	high_fail_users = {}

	for username in failed_by_user:
		count1 = 0
		for time in failed_by_user[username]["failure_timestamps"]:
			if recent_filter(time, now, time_threshold):
				count1 += 1
			if count1 > fail_threshold:
				high_fail_users[username] = failed_by_user[username]
				break
	
			 
	high_fail_ips = {}

	for ip in failed_by_ip:
		count2 = 0
		for time in failed_by_ip[ip]["failure_timestamps"]:
			if recent_filter(time, now, time_threshold):
				count2 += 1
			if count2 > fail_threshold:
				high_fail_ips[ip] = failed_by_ip[ip]
				break
			
		
	return high_fail_users, high_fail_ips



def too_many_unique_ips (username, fail_threshold=5, time_threshold=5):
	"""
	Receives: 
		username (string), 
		fail_threshold (integer), default param,
		time_threshold (integer), default param
	Returns: a set of IPs
	Description: if a failed login attemp falls within the given
	 	time_threshold, the IP associated with that failure is 
		accumulated. If that list of IPs exceeds a fail_threshold,
		this function returns a set of those unique IPs.
	"""
	now = datetime.now(timezone.utc)
	accum = []

	if username not in failed_by_user:
		return
	
	for tup in failed_by_user[username]["ips"]:
		ip, time = tup
		if recent_filter(time, now, time_threshold):
			accum.append(ip)

	if len(set(accum)) > fail_threshold:
		return set(accum)
	return

		
		
def too_many_unique_usernames(ip, fail_threshold=5, time_threshold=5):
	"""
	Receives: 
		ip (string),
		fail_threshold (integer), default param,
		time_threshold (integer), default param, 
	Returns: a set of usernames
	Description: if a failed login attemp falls within the given
	 	time_threshold, the username associated with that failure is 
		accumulated. If that list of usernames exceeds a fail_threshold,
		this function returns a set of those unique usernames.
	"""
	now = datetime.now(timezone.utc)
	accum =[]

	if ip not in failed_by_ip:
		return

	for tup in failed_by_ip[ip]["usernames"]:
		username, time = tup
		if recent_filter(time, now, time_threshold):
			accum.append(username)

	if len(set(accum)) > fail_threshold:
		return set(accum)
	return



def breakthrough_logins(fail_threshold=5, time_threshold=5):
	"""
	Receives: 
		fail_threshold (integer), default param,
		time_threshold (integer), default param,
	Returns: A dictionary of usernames.
	Description: Returns a dictionary of usernames that have
	 	'broken through' (i.e., failed > fail_threshold) and then succeeded at
	 	logging in. This function calls on too_many_fails() and the dictionary
		it returns. It outsources the loop structure to a helper.

	"""
	breakthrough_users = {}
	high_fail_users, high_fail_ips = too_many_fails(fail_threshold, time_threshold)

	if not high_fail_users:
		return

	for user in high_fail_users:
		if user in accepted_by_user:
			if breakthrough_logins_helper(user, high_fail_users, time_threshold):
				breakthrough_users[user] = high_fail_users[user]
	return breakthrough_users

	

def breakthrough_logins_helper(user, high_fail_users, time_threshold):
	"""
	Receives: 
		user -- a dictionary entry extracted from high_fail_users,
		high_fail_users -- the dictionary returned by the function too_many_fails(),
		time_threshold (integer)
	Returns: Boolean
	Description: loops over all the timestamps in accepted_by_user and checks if they
		fall within the valid time threshold (via recent_filter() helper function).
		It then loops over the failed_timestamps in high_fail_users dictionary and 
		checks whether the difference in accepted_timestamps and failure_timestamps
		for this user also fall within the time threshold. This helper logic reduces
		loop clutter in main function by returning True or False values.
	"""

	now = datetime.now(timezone.utc)
	threshold = timedelta(minutes=time_threshold)

	for accepted_time in accepted_by_user[user]["accepted_timestamps"]:

		# check if the accepted times fall within threshold
		if recent_filter(accepted_time, now, time_threshold):

			for failed_time in high_fail_users[user]["failure_timestamps"]:
				# check the difference between accepted time and failed time
				diff = accepted_time - failed_time 
				
				if diff > timedelta(0) and diff < threshold:
					return True
	return False

					
# ------------------------------------------------------------------------------------------
# REPORTING 
# ------------------------------------------------------------------------------------------

def make_report():
	"""
	Receives: None
	Returns: string -- text that combines all detection function results joined with newlines.
	Description: executes each of the detection functions and appends the output to 
        a list, along with a contextualizing message for each result.
	"""

	text = []
	fail_threshold = 5
	time_threshold = 5
	high_fail_users, high_fail_ips = too_many_fails(fail_threshold, time_threshold)
	breakthrough_users = breakthrough_logins(fail_threshold, time_threshold)

	breakthrough_ips = set()
	if breakthrough_users:
		for user in breakthrough_users:
			breakthrough_ips.update(ip for ip, timestamp in failed_by_user[user]["ips"])

	if high_fail_users:
		for user in high_fail_users:
			text.append(f"Users: {user} registered more than {fail_threshold} failures within a {time_threshold} minute window.")

	if high_fail_ips:
		for ip in high_fail_ips:
			text.append(f"IPs: {ip} registered more than {fail_threshold} failures within a {time_threshold} minute window.")

			if ip in breakthrough_ips:
				text.append(f"This IP: {ip} is also linked to a username that broke through.")

			password_spray = too_many_unique_usernames(ip, fail_threshold, time_threshold)
			if password_spray:
				text.append(f"This flagged IP: {ip} also registered more than {fail_threshold} usernames: {password_spray}.")

	if breakthrough_users:
		for user in breakthrough_users:
			text.append(f"Users: {user} registered more than {fail_threshold} failures and then succeeded.")
			if too_many_unique_ips(user, fail_threshold, time_threshold):
				text.append(f"User: {user} showed activity on more than {fail_threshold} IPs.")

	return "\n".join(text) + "\n"


# ------------------------------------------------------------------------------------------
# CONTINOUS MONITORING LOOP & GENERATING REPORT
# ------------------------------------------------------------------------------------------

def main():
	"""
	Receives: None
	Returns: None
	Description: monitors an SSH authorization log "continuously" using a while loop 
		set to run for (RUN_TIME) hours. It scans the authorization log every (SCAN_INTERVAL)
		seconds, and generates a report every (REPORT_INTERVAL) seconds. There is deliberate
		overlap between the time_threshold used by the detection functions (currently hardcoded to
		5 minutes) and the REPORT_INTERVAL (currently hardcoded to 4 minutes). This overlap ensures
		that no suspicious activity goes unrecorded, but means there will most likely be redundant
		entries in some of the generated reports. Each report is appended to an external file: 
		"SSH_login_report.txt".
	"""

	RUN_TIME = 10 * 60 * 60		# in seconds (10 hours)
	end_time = time.time() + RUN_TIME
	SCAN_INTERVAL = 5			# in seconds
	REPORT_INTERVAL = 4 * 60    # in seconds (i.e., every four minutes)
	next_report_time = time.time() + REPORT_INTERVAL

	while time.time() < end_time:
		scan_auth_log()

		if time.time() >= next_report_time:		

			# call make_report(), display output	
			report_object = make_report()
			print(report_object)

			# append make_report() output to the text file for this RUN_TIME session
			with open("SSH_login_report.txt", "a") as report_file:
				report_file.write(report_object)

			next_report_time = time.time() + REPORT_INTERVAL

		time.sleep(SCAN_INTERVAL)


if __name__ == "__main__": 
	main()