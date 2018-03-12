import re
import json
import jinja2



def usage_analysis(lines, pattern, namepos, fname, rmod=None):
	alldata = {}
	used = {}
	unused = {}
	###############################
	#### GET ALL NAME INSTANCES ###
	lindex = 0
	for line in lines:
		search = re.match(pattern, line)
		if search:
			words = search.string.split(" ")
			name = words[namepos]
			if name in alldata: # Found pattern a second time
				mems = get_indented_members(lines, lindex+1)
				alldata[name]["members"] += mems
			else:
				mems = get_indented_members(lines, lindex+1)
				check = "show run | in " + name
				if rmod:
					remove = rmod(line)
				else:
					remove = "no "+ line
				alldata.update({name: {"original": line,
						"uses":[], "count": 0, "members": mems, "line": lindex, "check": check, "remove": remove}})
		lindex += 1
	###############################
	####### FIND USAGE #######
	for name in alldata:
		lindex = 0
		for line in lines:
			words = line.split(" ")
			for word in words:
				if name == word:
					if lindex == alldata[name]["line"]:
						# Don't inventory original match as usage
						break
					elif re.match(pattern, line): # May be ACL lines or Object nat
						if line == alldata[name]["original"]: # Likely Obj
							# Don't inventory if it matches original PATTERN
							# But mark it as a use (needed to detect an object NAT)
							alldata[name]["count"] += 1
							pass
						else: # Likely multi-line ACL
							# Don't inventory
							pass
						break
					else:
						alldata[name]["count"] += 1
						parent = get_parent(lines, lindex)
						use = {"value": line, "parent": parent}
						alldata[name]["uses"].append(use)
						break
			lindex += 1
		if alldata[name]["count"] == 0:
			unused.update({name: alldata[name]})
		else:
			used.update({name: alldata[name]})
	rpath = fname+" Usage"
	reporting.update({rpath: {
			"Total": len(alldata),
			"Used": len(used),
			"Unused": len(unused)
		}})
	return {"used": used, "unused": unused, "alldata": alldata}



def acl_hit_analysis(lines):
	alldata = {}
	used = {}
	unused = {}
	###############################
	#### GET ALL NAME INSTANCES ###
	lindex = 0
	for line in lines:
		search = re.match("^access-list ", line)
		if search:
			words = line.split(" ")
			name = words[1]
			if ";" in line:
				pass
			elif "remark" in line:
				pass
			elif words[3] == "log":
				pass
			else:
				if name not in alldata:
					alldata.update({name: {"aces": {}, "hits": 0}})
				try:
					acenum = int(words[3])
				except Exception as e:
					print("ERROR! Input must be the output of 'show access-list'")
					print("    --"+str(e))
					quit()
				config = rebuild_acl_config(line)
				if "(hitcnt=" in line:  # No members will exist
					hits = get_hits(line)
					alldata[name]["hits"] += hits
					members = get_indented_members(lines, lindex+1)
					ace = {"config": config, "hits": hits, "members": members}
					alldata[name]["aces"].update({acenum: ace})
				else:
					hits = 0
					members = get_indented_members(lines, lindex+1)
					for member in members:
						hits += get_hits(member)
					alldata[name]["hits"] += hits
					ace = {"config": config, "hits": hits, "members": members}
					alldata[name]["aces"].update({acenum: ace})
		lindex += 1
	totals = []
	for acl in alldata:
		totals.append({"Name": acl, "Total Hits": alldata[acl]["hits"]})
		if alldata[acl]["hits"] == 0:
			unused.update({acl: alldata[acl]})
		else:
			used.update({acl: alldata[acl]})
	table = make_table(["Name", "Total Hits"], sort_by_hits(totals))
	rpath = "Access-List ACE Stats"
	reporting.update({rpath: {
			"Total": len(alldata),
			"Used": len(used),
			"Unused": len(unused)
		}})
	return {"alldata": alldata, "used": used, "unused": unused, "totals": totals, "table": table}



def get_hits(line):
	words = line.split(" ")
	for word in words:
		if "(hitcnt=" in word:
			word = word.replace("(hitcnt=", "")
			word = word.replace(")", "")
			return int(word)



def rebuild_acl_config(line):
	result = ""
	search = re.findall("( line [0-9]+)|( \(.+\))|( 0x[0-9a-f]+)", line)
	for matchtup in search:
		for each in matchtup:
			if each != "":
				line = line.replace(each, "")
	return line



def sort_by_hits(totals):
	result = []
	for nacl in totals:
		inserted = False
		if len(result) == 0:
			result.append(nacl)
		else:
			index = 0
			for xacl in result:
				if nacl["Total Hits"] <= xacl["Total Hits"]:
					result.insert(index, nacl)
					inserted = True
					break
				index += 1
			if not inserted:
				result.insert(index, nacl)
	return result



def get_indented_members(lines, start):
	mems = []
	for line in lines[start:]:
		if not re.match("(^ )|(^\t)", line):
			return mems
		else:
			mems.append(line)
	return mems



def get_parent(lines, start):
	if re.match("^ ", lines[start]):  # If this is a child item
		while True:
			start -= 1
			if not re.match("^ ", lines[start]):
				return lines[start]
	else:
		return None



def acl_removal_modifier(data):
	words = data.split(" ")
	return "clear configure %s %s" % (words[0], words[1]) 



default_usage_j2 = """
{% for search in data %}
{% set header = "############### "+search|upper+" ANALYSIS ###############" %}
{% set hblock = header|length*"#" %}
{{header}}
{{hblock}}



### USED {{search|upper}} BREAKDOWN:
{% for item in data[search].used %}{{item}}
	>> Usage Count: {{data[search].used[item].count}}\
{%if options.members%}
	>> Members:\
{% for member in data[search].used[item].members %}
		  {{member}}\
{% endfor %}\
{% endif %}\
{%if options.usage%}
	>> Usage:\
{% for use in data[search].used[item].uses %}\
{%if use.parent%}
		  {{use.parent}}
			  {{use.value}}\
{%else%}
		  {{use.value}}\
{% endif %}\
{% endfor %}\
{% endif %}
{% endfor %}


### UNUSED {{search|upper}}:
{% for item in data[search].unused %}    {{item}}
{% endfor %}


### DOUBLE CHECK UNUSED {{search|upper}}:
{% for item in data[search].unused %}    {{data[search].unused[item].check}}
{% endfor %}


### REMOVE UNUSED {{search|upper}}:
{% for item in data[search].unused %}    {{data[search].unused[item].remove}}
{% endfor %}



{{hblock}}
{{hblock}}\
{% endfor %}
"""



default_hits_j2 = """
{% set header = "############### ACCESS-LIST HITS ANALYSIS ###############" %}
{% set hblock = header|length*"#" %}
{{header}}
{{hblock}}

{{data.table}}

### ACL HITS BREAKDOWN:
{% for acl in data.alldata %}\
{%if data.alldata[acl].hits==0%}\
{%if not options.hide_unused_acls%}\
{{acl}}
	>> Total ACL Hits: {{data.alldata[acl].hits}}
	>> ACEs:
{% for ace in data.alldata[acl].aces %}\
		{{ace}}: {{data.alldata[acl].aces[ace].config}}
{%if options.ace_hits%}\
			>> Total ACE Hits: {{data.alldata[acl].aces[ace].hits}}
{% endif %}\
{%if options.ace_children and data.alldata[acl].aces[ace].members%}\
			>> ACE Children:
{% for child in data.alldata[acl].aces[ace].members %}\
				{{child}}
{% endfor %}\
{% endif %}\
{% endfor %}\
{% endif %}\
{%else%}\
{%if not options.hide_used_acls%}\
{{acl}}
	>> Total ACL Hits: {{data.alldata[acl].hits}}
	>> ACEs:
{% for ace in data.alldata[acl].aces %}\
		{{ace}}: {{data.alldata[acl].aces[ace].config}}
{%if options.ace_hits%}\
			>> Total ACE Hits: {{data.alldata[acl].aces[ace].hits}}
{% endif %}\
{%if options.ace_children and data.alldata[acl].aces[ace].members%}\
			>> ACE Children:
{% for child in data.alldata[acl].aces[ace].members %}\
				{{child}}
{% endfor %}\
{% endif %}\
{% endfor %}\
{% endif %}\
{% endif %}\
{% endfor %}\


### ACES WITH NO HITS:
{% for acl in data.alldata %}\
{% for ace in data.alldata[acl].aces %}\
{%if data.alldata[acl].aces[ace].hits==0%}\
{%if data.alldata[acl].hits==0%}\
{%if not options.hide_unused_acls%}\
	{{data.alldata[acl].aces[ace].config}}
{% endif %}\
{% else %}\
{%if not options.hide_used_acls%}\
	{{data.alldata[acl].aces[ace].config}}
{% endif %}\
{% endif %}\
{% endif %}\
{% endfor %}\
{% endfor %}\


### DOUBLE CHECK ACE HITS:
{% for acl in data.alldata %}\
{% for ace in data.alldata[acl].aces %}\
{%if data.alldata[acl].aces[ace].hits==0%}\
{%if data.alldata[acl].hits==0%}\
{%if not options.hide_unused_acls%}\
	show access-list {{acl}} | in line {{ace}} 
{% endif %}\
{% else %}\
{%if not options.hide_used_acls%}\
	show access-list {{acl}} | in line {{ace}} 
{% endif %}\
{% endif %}\
{% endif %}\
{% endfor %}\
{% endfor %}\


### UNUSED ACE REMOVAL:
{% for acl in data.alldata %}\
{% for ace in data.alldata[acl].aces %}\
{%if data.alldata[acl].aces[ace].hits==0%}\
{%if data.alldata[acl].hits==0%}\
{%if not options.hide_unused_acls%}\
	no {{data.alldata[acl].aces[ace].config}}
{% endif %}\
{% else %}\
{%if not options.hide_used_acls%}\
	no {{data.alldata[acl].aces[ace].config}}
{% endif %}\
{% endif %}\
{% endif %}\
{% endfor %}\
{% endfor %}\



{{hblock}}
{{hblock}}\
"""



def format_data(data, options, j2format):
	if options.format:
		f = open(options.format)
		j2format = f.read().replace("\\\n", "")
		f.close()
	template = jinja2.Template(j2format)
	return template.render(data=data, options=options)



def get_printable_report(data, result="\n", depth=0):
	for each in data:
		if type(data[each]) == type({}):
			result += each+":\n"+get_printable_report(data[each], "", depth+1)
		else:
			result += "    "*depth+"%s: %s\n" % (str(each), str(data[each]))
	return result



def make_table(columnorder, tabledata):
	##### Check and fix input type #####
	if type(tabledata) != type([]): # If tabledata is not a list
		tabledata = [tabledata] # Nest it in a list
	##### Set seperators and spacers #####
	tablewrap = "#" # The character used to wrap the table
	headsep = "=" # The character used to seperate the headers from the table values
	columnsep = "|" # The character used to seperate each value in the table
	columnspace = "  " # The amount of space between the largest value and its column seperator
	##### Generate a dictionary which contains the length of the longest value or head in each column #####
	datalengthdict = {} # Create the dictionary for storing the longest values
	for columnhead in columnorder: # For each column in the columnorder input
		datalengthdict.update({columnhead: len(columnhead)}) # Create a key in the length dict with a value which is the length of the header
	for row in tabledata: # For each row entry in the tabledata list of dicts
		for item in columnorder: # For column entry in that row
			if len(re.sub(r'\x1b[^m]*m', "",  str(row[item]))) > datalengthdict[item]: # If the length of this column entry is longer than the current longest entry
				datalengthdict[item] = len(row[item]) # Then change the value of entry
	##### Calculate total table width #####
	totalwidth = 0 # Initialize at 0
	for columnwidth in datalengthdict: # For each of the longest column values
		totalwidth += datalengthdict[columnwidth] # Add them all up into the totalwidth variable
	totalwidth += len(columnorder) * len(columnspace) * 2 # Account for double spaces on each side of each column value
	totalwidth += len(columnorder) - 1 # Account for seperators for each row entry minus 1
	totalwidth += 2 # Account for start and end characters for each row
	##### Build Header #####
	result = tablewrap * totalwidth + "\n" + tablewrap # Initialize the result with the top header, line break, and beginning of header line
	columnqty = len(columnorder) # Count number of columns
	for columnhead in columnorder: # For each column header value
		spacing = {"before": 0, "after": 0} # Initialize the before and after spacing for that header value before the columnsep
		spacing["before"] = int((datalengthdict[columnhead] - len(columnhead)) / 2) # Calculate the before spacing
		spacing["after"] = int((datalengthdict[columnhead] - len(columnhead)) - spacing["before"]) # Calculate the after spacing
		result += columnspace + spacing["before"] * " " + columnhead + spacing["after"] * " " + columnspace # Add the header entry with spacing
		if columnqty > 1: # If this is not the last entry
			result += columnsep # Append a column seperator
		del spacing # Remove the spacing variable so it can be used again
		columnqty -= 1 # Remove 1 from the counter to keep track of when we hit the last column
	del columnqty # Remove the column spacing variable so it can be used again
	result += tablewrap + "\n" + tablewrap + headsep * (totalwidth - 2) + tablewrap + "\n" # Add bottom wrapper to header
	##### Build table contents #####
	result += tablewrap # Add the first wrapper of the value table
	for row in tabledata: # For each row (dict) in the tabledata input
		columnqty = len(columnorder) # Set a column counter so we can detect the last entry in this row
		for column in columnorder: # For each value in this row, but using the correct order from column order
			spacing = {"before": 0, "after": 0} # Initialize the before and after spacing for that header value before the columnsep
			spacing["before"] = int((datalengthdict[column] - len(re.sub(r'\x1b[^m]*m', "",  str(row[column])))) / 2) # Calculate the before spacing
			spacing["after"] = int((datalengthdict[column] - len(re.sub(r'\x1b[^m]*m', "",  str(row[column])))) - spacing["before"]) # Calculate the after spacing
			result += columnspace + spacing["before"] * " " + str(row[column]) + spacing["after"] * " " + columnspace # Add the entry to the row with spacing
			if columnqty == 1: # If this is the last entry in this row
				result += tablewrap + "\n" + tablewrap # Add the wrapper, a line break, and start the next row
			else: # If this is not the last entry in the row
				result += columnsep # Add a column seperator
			del spacing # Remove the spacing settings for this entry
			columnqty -= 1 # Keep count of how many row values are left so we know when we hit the last one
	result += tablewrap * (totalwidth - 1) # When all rows are complete, wrap the table with a trailer
	return result



def get_creds(options, args):
	# Example: "user:password@host:port"
	if (":" not in args[0]) or ("@" not in args[0]):
		print("Device info/credentials malformed")
		print("Use the '-h' option to see examples")
		quit()
	else:
		sup = args[0].split("@")
		up = sup[0].split(":")
		hp = sup[1].split(":")
		username = up[0]
		password = up[1]
		if len(up) > 2:
			secret = up[2]
		else:
			secret = password
		host = hp[0]
		if len(hp) > 1:
			port = int(hp[1])
		else:
			port = 22
		if options.type:
			dtype = options.type
		else:
			dtype = "cisco_asa"
		result = {
			"device_type": dtype,
			"username": username,
			"password": password,
			"secret": secret,
			"ip": host,
			"port": port
		}
		return result



def get_file(options, args):
	(options, args)
	lines = []
	f = open(args[0], "r")
	templines = f.readlines()
	f.close()
	for line in templines:
		line = line.replace("\n", "")
		line = line.replace("\r", "")
		lines.append(line)
	return lines



def get_data(options, args, cmd="show run"):
	if len(args) == 0:
		parser.print_help()
		quit()
	else:
		if not options.device:  # Use arg as filename
			return get_file(options, args)
		else:
			creds = get_creds(options, args)
			from netmiko import ConnectHandler
			creds = get_creds(options, args)
			if not options.json:
				print("Connecting to %s:%s (%s) with:" % (creds["ip"], creds["port"], creds["device_type"]))
				print("    Username: " + creds["username"])
				print("    Password: " + creds["password"])
				print("    Enable Secret: " + creds["secret"])
			device = ConnectHandler(**get_creds(options, args))
			if not options.json:
				print("Connected! Pulling and Parsing Data...\n")
			config = device.send_command(cmd)
			device.disconnect()
			return config.split("\n")



if __name__ == "__main__":
	from optparse import OptionParser,OptionGroup
	examples = """%prog [options] FILE/DEVICE_INFO
	Examples:
		- Check usage of objects in a file containing an ASA's "show run" output
			>>> %prog -o CONFIGFILE.txt
			- Show more detailed usage information
				>>> %prog -muo CONFIGFILE.txt
			- Check usage of objects, names and object-groups and show detailed usage and members
				>>> %prog -muong CONFIGFILE.txt
			- Pull running-config using SSH and check object-group usage
				>>> %prog -gd admin:password123:secret@192.168.1.1:22
			- Perform a custom usage analysis on VPN tunnel-groups
				>>> %prog -c '^tunnel-group ' -p 1 CONFIGFILE.txt

		- Analyze ACL hit-counts on a file containing a 'show access-list' output
			>>> %prog -l SHOWACL.txt
			- Show hits per ACE and all ACE children
				>>> %prog -lei SHOWACL.txt
			- Hide any ACL with no hits on any of it's ACEs
				>>> %prog -lx SHOWACL.txt
			- Pull access-list hits from SSH
				>>> %prog -ld admin:password123:secret@192.168.1.1:22

		- Get object-group usage and output as raw JSON data
			>>> %prog -gj CONFIGFILE.txt
		- Get object-group usage and use a custom Jinja2 template to output data
			>>> %prog -f MYTEMPLATE.j2 -g CONFIGFILE.txt
"""
	global parser
	parser = OptionParser(examples)
	upattgrp = OptionGroup(parser, "Pre-Built Usage Patterns",
		"Pre-built ASA config patterns you can easily enable")
	cpattgrp = OptionGroup(parser, "Custom Usage Pattern Options",
		"Specify your own regex pattern and word position for usage analysis (must provide regex pattern AND position)")
	uverbgrp = OptionGroup(parser, "Usage Breakdown Verbosity",
		"Switch on to see more usage detail")
	hitsgrp = OptionGroup(parser, "ACL Hit-Count Analysis",
		"Access-List hit count analysis (ASA Only)")
	fmtgrp = OptionGroup(parser, "Output Formatting",
		"Customize the output with a Jinja2 template, or output raw JSON")
	devgrp = OptionGroup(parser, "Direct Data Pull",
		"Use SSH to pull needed data ('show run' or 'show access-list') directly from a device instead of from a file")
	parser.add_option_group(upattgrp)
	parser.add_option_group(cpattgrp)
	parser.add_option_group(uverbgrp)
	parser.add_option_group(hitsgrp)
	parser.add_option_group(fmtgrp)
	parser.add_option_group(devgrp)
	upattgrp.add_option("-n", "--names",
		action="store_true", dest="check_names", default=False,
		help="Check Name usage in ASA config (-c '^name ' -p 2)")
	upattgrp.add_option("-o", "--objects",
		action="store_true", dest="check_objects", default=False,
		help="Check Object Usage in ASA config (-c '^object ' -p 2)")
	upattgrp.add_option("-g", "--object-groups",
		action="store_true", dest="check_object_groups", default=False,
		help="Check Object-Group usage in ASA config (-c '^object-group ' -p 2)")
	upattgrp.add_option("-a", "--access-lists",
		action="store_true", dest="check_access_lists", default=False,
		help="Check Access-List object usage in ASA config")
	uverbgrp.add_option("-u", "--usage",
		action="store_true", dest="usage", default=False,
		help="Include lines of usage")
	uverbgrp.add_option("-m", "--members",
		action="store_true", dest="members", default=False,
		help="Include indented members")
	hitsgrp.add_option("-l", "--acl_hits",
		action="store_true", dest="check_acl_hits", default=False,
		help="Perform a hit-count analysis on a 'show access-list' output")
	hitsgrp.add_option("-x", "--hide_unused_acls",
		action="store_true", dest="hide_unused_acls", default=False,
		help="Hide ACLs with no hits on any ACEs")
	hitsgrp.add_option("-y", "--hide_used_acls",
		action="store_true", dest="hide_used_acls", default=False,
		help="Hide ACLs with one or more hits on any ACEs")
	hitsgrp.add_option("-e", "--ace_hits",
		action="store_true", dest="ace_hits", default=False,
		help="Breakdown hit-counts for each ACE")
	hitsgrp.add_option("-i", "--ace_children",
		action="store_true", dest="ace_children", default=False,
		help="Breakdown ACE children under each ACE")
	fmtgrp.add_option("-j", "--json",
		action="store_true", dest="json", default=False,
		help="Dump all data out as JSON")
	fmtgrp.add_option("-f", "--format", dest="format",
		help="Use a custom Jinja2 formatting template", metavar="FILE")
	cpattgrp.add_option("-c", "--custom", dest="custom",
		help="Search a custom regex usage pattern (requires a word position)", metavar="'some_regex'")
	cpattgrp.add_option("-p", "--position", dest="position", type="int",
		help="Position of word (in regex matched line) to find in config", metavar="INTEGER")
	devgrp.add_option("-d", "--device",
		action="store_true", dest="device", default=False,
		help="Pull data/config directly from a device via SSH instead of a file")
	devgrp.add_option("-t", "--type", dest="type",
		help="Set the Netmiko device type (default is 'cisco_asa')", metavar="TYPE")
	uverbgrp.add_option("-r", "--report",
		action="store_true", dest="report", default=False,
		help="Display a report of processed items")
	(options, args) = parser.parse_args()
	global usage
	global members
	global reporting
	usage = options.usage
	members = options.members
	reporting = {}
	if options.check_acl_hits:
		lines = get_data(options, args, "show access-list")
		hdata = acl_hit_analysis(lines)
		if options.json:
			print(json.dumps(hdata, indent=4, sort_keys=True))
		else:
			print(format_data(hdata, options, default_hits_j2))
	else:
		lines = get_data(options, args)
		queue = {}
		if options.check_names:
			queue.update({"Names":{
				"regex": "^name ", 
				"position": 2, 
				"fname": "Names",
				"rmod": None}})
		if options.check_objects:
			queue.update({"Objects":{
				"regex": "^object ", 
				"position": 2, 
				"fname": "Objects",
				"rmod": None}})
		if options.check_object_groups:
			queue.update({"Object-Groups":{
				"regex": "^object-group ", 
				"position": 2, 
				"fname": "Object-Groups",
				"rmod": None}})
		if options.check_access_lists:
			queue.update({"Access-Lists":{
				"regex": "^access-list ", 
				"position": 1, 
				"fname": "Access-Lists",
				"rmod": acl_removal_modifier}})
		if options.custom:
			fname = options.custom.replace("^", "")
			fname = fname.replace("$", "")
			if not options.position:
				print("Position missing!")
				print("Custom Example: usage_check -c '^object-group ' -p 2 CONFIG.txt")
				print("Use the '-h' option to see examples")
				quit()
			else:
				queue.update({fname:{
					"regex": options.custom, 
					"position": options.position, 
					"fname": fname,
					"rmod": None}})
		data = {}
		for each in queue:
			udata = usage_analysis(lines, queue[each]["regex"], queue[each]["position"], queue[each]["fname"], rmod=queue[each]["rmod"])
			data.update({queue[each]["fname"]: udata})
		if options.json:
			print(json.dumps(data, indent=4, sort_keys=True))
		else:
			print(format_data(data, options, default_usage_j2))
	if options.report:
		if options.json:
			pass
		else:
			print(get_printable_report(reporting))