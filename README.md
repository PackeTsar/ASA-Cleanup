# ASA-Cleanup ![ASA-Cleanup][logo]

A Cisco ASA config and ACL analysis tool to help identify unused configuration items


-----------------------------------------
## VERSION
The version of ASA-Cleanup documented here is: **v1.0.1**



-----------------------------------------
## TABLE OF CONTENTS
1. [How To Use](#how-to-use)
2. [Example Output](#example-output)
3. [How It Works](#how-it-works)
3. [Hackability](#hackability)
3. [Compile](#compile)



-----------------------------------------
## HOW TO USE
ASA-Cleanup is run from the command line with typical switches and parameters to tell it what to do. It processes the config-file, "show access list" file, or device-direct SSH login and then displays its output.

### Basic Usage Example
If you download the whole repository, navigate to the **Binaries** folder and run the binary. The switches used here, in order, are (-n: Analyze Name Usage), (-o: Analyze Object Usage), (-g: Analyze Object-Group Usage), (-a: Analyze Access-List Usage), (-m: Show Members in the Breakdown), (-u: Show Detailed Usage in the Breakdown).
  - MacOS/Linux: `./ASA-Cleanup -nogamu ../Examples/ASA_CONFIG.txt`
  - Windows: `ASA-Cleanup.exe -nogamu ../Examples/ASA_CONFIG.txt`

An example of an analysis of Access-List hits can be seen below. The switches used here, in order, are (-l: Analyze Access-List Hits), (-i: Show children under each ACE in Breakdown), (-e: Show Hit-Counts for each ACE in each ACL in Breakdown).
  - MacOS/Linux: `ASA-Cleanup.exe -lie ../Examples/SHOW_ACCESS_LIST.txt`
  - Windows: `ASA-Cleanup.exe -lie ../Examples/SHOW_ACCESS_LIST.txt`

### Default Output Format
The output is typically displayed in four sections:
1. Item Breakdown
	- A breakdown of all found items; listing any children/members they might have and anywhere else in the config where they were found
	- The verbosity of this breakdown can be adjusted using the switches listed in command-line guide
2. Unused Item List
	- A simple list of the names of all the items found which can potentially be removed
3. Double Check Quick Commands
	- Pre-formatted commands you can copy/paste into the device to make sure you can safely remove the unused items
4. Removal Quick Commands
	- Pre-formatted commands you can copy/paste into your device to remove the unused items

### Device-Direct Mode
ASA-Cleanup (when used with the `-d` switch) can leverage Netmiko to pull down a config or 'show access-list' directly from your device over SSH. Examples of this usage can be seen below.

The simplest device info input format is `username:password@HOSTNAMEorIP`. By default ASA-Cleanup will assume that the enable secret is the same as the password and that we are using TCP port 22. Those can be changed using the format `username:password:secret@HOSTNAMEorIP:22`

An example config analysis using a direct config pull: `ASA-Cleanup.exe -nogamud username:password:secret@HOSTNAMEorIP:22`

By default, we assume the Netmiko device type is 'cisco_asa', but this can be changed using the `-t` switch



-----------------------------------------
## EXAMPLE OUTPUT


### Command Guide
```
> ./ASA-Cleanup
Usage: ASA-Cleanup [options] FILE/DEVICE_INFO
	Examples:
		- Check usage of objects in a file containing an ASA's "show run" output
			>>> ASA-Cleanup -o CONFIGFILE.txt
			- Show more detailed usage information
				>>> ASA-Cleanup -muo CONFIGFILE.txt
			- Check usage of objects, names and object-groups and show detailed usage and members
				>>> ASA-Cleanup -muong CONFIGFILE.txt
			- Pull running-config using SSH and check object-group usage
				>>> ASA-Cleanup -gd admin:password123:secret@192.168.1.1:22
			- Perform a custom usage analysis on VPN tunnel-groups
				>>> ASA-Cleanup -c '^tunnel-group ' -p 1 CONFIGFILE.txt

		- Analyze ACL hit-counts on a file containing a 'show access-list' output
			>>> ASA-Cleanup -l SHOWACL.txt
			- Show hits per ACE and all ACE children
				>>> ASA-Cleanup -lei SHOWACL.txt
			- Hide any ACL with no hits on any of it's ACEs
				>>> ASA-Cleanup -lx SHOWACL.txt
			- Pull access-list hits from SSH
				>>> ASA-Cleanup -ld admin:password123:secret@192.168.1.1:22

		- Get object-group usage and output as raw JSON data
			>>> ASA-Cleanup -gj CONFIGFILE.txt
		- Get object-group usage and use a custom Jinja2 template to output data
			>>> ASA-Cleanup -f MYTEMPLATE.j2 -g CONFIGFILE.txt


Options:
  -h, --help            show this help message and exit

  Pre-Built Usage Patterns:
    Pre-built ASA config patterns you can easily enable

    -n, --names         Check Name usage in ASA config (-c '^name ' -p 2)
    -o, --objects       Check Object Usage in ASA config (-c '^object ' -p 2)
    -g, --object-groups
                        Check Object-Group usage in ASA config (-c '^object-
                        group ' -p 2)
    -a, --access-lists  Check Access-List object usage in ASA config

  Custom Usage Pattern Options:
    Specify your own regex pattern and word position for usage analysis
    (must provide regex pattern AND position)

    -c 'some_regex', --custom='some_regex'
                        Search a custom regex usage pattern (requires a word
                        position)
    -p INTEGER, --position=INTEGER
                        Position of word (in regex matched line) to find in
                        config

  Usage Breakdown Verbosity:
    Switch on to see more usage detail

    -u, --usage         Include lines of usage
    -m, --members       Include indented members
    -r, --report        Display a report of processed items

  ACL Hit-Count Analysis:
    Access-List hit count analysis (ASA Only)

    -l, --acl_hits      Perform a hit-count analysis on a 'show access-list'
                        output
    -x, --hide_unused_acls
                        Hide ACLs with no hits on any ACEs
    -y, --hide_used_acls
                        Hide ACLs with one or more hits on any ACEs
    -e, --ace_hits      Breakdown hit-counts for each ACE
    -i, --ace_children  Breakdown ACE children under each ACE

  Output Formatting:
    Customize the output with a Jinja2 template, or output raw JSON

    -j, --json          Dump all data out as JSON
    -f FILE, --format=FILE
                        Use a custom Jinja2 formatting template

  Direct Data Pull:
    Use SSH to pull needed data ('show run' or 'show access-list')
    directly from a device instead of from a file

    -d, --device        Pull data/config directly from a device via SSH
                        instead of a file
    -t TYPE, --type=TYPE
                        Set the Netmiko device type (default is 'cisco_asa')
> 
```


### Config Usage Analysis
```
> ./ASA-Cleanup -nogamu ../Examples/ASA_CONFIG.txt




############### OBJECTS ANALYSIS ###############
################################################



### USED OBJECTS BREAKDOWN:
USED_OBJECT_1
	>> Usage Count: 1
	>> Members:
		   host 10.0.0.2
	>> Usage:
		  object-group network USED_OBJECT-GROUP_1
			   network-object object USED_OBJECT_1



### UNUSED OBJECTS:
    UNUSED_OBJECT_2
    UNUSED_OBJECT_3
    UNUSED_OBJECT_1



### DOUBLE CHECK UNUSED OBJECTS:
    show run | in UNUSED_OBJECT_2
    show run | in UNUSED_OBJECT_3
    show run | in UNUSED_OBJECT_1



### REMOVE UNUSED OBJECTS:
    no object network UNUSED_OBJECT_2
    no object network UNUSED_OBJECT_3
    no object network UNUSED_OBJECT_1




################################################
################################################


############### NAMES ANALYSIS ###############
##############################################



### USED NAMES BREAKDOWN:
USED_NAME_1
	>> Usage Count: 1
	>> Members:
	>> Usage:
		  object-group network USED_OBJECT-GROUP_2
			   network-object host USED_NAME_1



### UNUSED NAMES:
    UNUSED_NAME_1
    UNUSED_NAME_2
    UNUSED_NAME_3



### DOUBLE CHECK UNUSED NAMES:
    show run | in UNUSED_NAME_1
    show run | in UNUSED_NAME_2
    show run | in UNUSED_NAME_3



### REMOVE UNUSED NAMES:
    no name 1.1.1.1 UNUSED_NAME_1
    no name 1.1.1.2 UNUSED_NAME_2
    no name 1.1.1.3 UNUSED_NAME_3




##############################################
##############################################


############### ACCESS-LISTS ANALYSIS ###############
#####################################################



### USED ACCESS-LISTS BREAKDOWN:
USED_ACL
	>> Usage Count: 1
	>> Members:
	>> Usage:
		  access-group USED_ACL in interface TEMP



### UNUSED ACCESS-LISTS:
    UNUSED_ACL



### DOUBLE CHECK UNUSED ACCESS-LISTS:
    show run | in UNUSED_ACL



### REMOVE UNUSED ACCESS-LISTS:
    clear configure access-list UNUSED_ACL




#####################################################
#####################################################


############### OBJECT-GROUPS ANALYSIS ###############
######################################################



### USED OBJECT-GROUPS BREAKDOWN:
USED_OBJECT-GROUP_2
	>> Usage Count: 1
	>> Members:
		   description Using a name here
		   network-object host USED_NAME_1
	>> Usage:
		  access-list USED_ACL extended permit ip object-group USED_OBJECT-GROUP_1 object-group USED_OBJECT-GROUP_2 
USED_OBJECT-GROUP_1
	>> Usage Count: 1
	>> Members:
		   network-object host 5.5.5.5
		   network-object object USED_OBJECT_1
	>> Usage:
		  access-list USED_ACL extended permit ip object-group USED_OBJECT-GROUP_1 object-group USED_OBJECT-GROUP_2 



### UNUSED OBJECT-GROUPS:
    UNUSED_OBJECT-GROUP_2
    UNUSED_OBJECT-GROUP_1



### DOUBLE CHECK UNUSED OBJECT-GROUPS:
    show run | in UNUSED_OBJECT-GROUP_2
    show run | in UNUSED_OBJECT-GROUP_1



### REMOVE UNUSED OBJECT-GROUPS:
    no object-group network UNUSED_OBJECT-GROUP_2
    no object-group network UNUSED_OBJECT-GROUP_1




######################################################
######################################################
```



### ACL Hit-Count Analysis
```
> ./ASA-Cleanup -lie ../Examples/SHOW_ACCESS_LIST.txt



############### ACCESS-LIST HITS ANALYSIS ###############
#########################################################

###############################
#     Name     |  Total Hits  #
#=============================#
#  UNUSED_ACL  |      0       #
#   USED_ACL   |     110      #
###############################

### ACL HITS BREAKDOWN:
UNUSED_ACL
	>> Total ACL Hits: 0
	>> ACEs:
		1: access-list UNUSED_ACL extended permit ip any any 
			>> Total ACE Hits: 0
USED_ACL
	>> Total ACL Hits: 110
	>> ACEs:
		1: access-list USED_ACL extended permit ip object-group USED_OBJECT-GROUP_1 object-group USED_OBJECT-GROUP_2 
			>> Total ACE Hits: 110
			>> ACE Children:
				  access-list USED_ACL line 1 extended permit ip host 5.5.5.5 host 10.0.0.1 (hitcnt=50) 0xcbf6c0d8 
				  access-list USED_ACL line 1 extended permit ip host 10.0.0.2 host 10.0.0.1 (hitcnt=60) 0xd971f9f2 


### ACES WITH NO HITS:
	access-list UNUSED_ACL extended permit ip any any 


### DOUBLE CHECK ACE HITS:
	show access-list UNUSED_ACL | in line 1 


### UNUSED ACE REMOVAL:
	no access-list UNUSED_ACL extended permit ip any any 



#########################################################
#########################################################
```



--------------------------------------
## HOW IT WORKS

#### Config Usage Analysis
ASA-Cleanup performs the config usage analysis with a multi-level search through the configuration using a regular expression and a unique word position. These two inputs will look something like `("^object-group ", 2)` and they are used to match a line containing the unique word, and find that unique word using its position in the line, and also inventory any child lines (members). Once all of the unique words have been inventoried, ASA-Cleanup re-searches the configuration for any instance of the unique words in a different location. When found, the config lines are added to the inventory along with any parent config lines they might have.

The switches you use to search names, objects, object-groups, and access-lists are all small deviations on this same search algorithm. The search can also be run using a custom input by using the `-c` and `-p` switches (see the 'Hackability' section)




--------------------------------------
## HACKABILITY
ASA-Cleanup is designed to be hackable: able to output raw JSON data to use somewhere else, use custom Jinja2 formatting, or run customized searches for different config items

#### Custom Searches
The `-c` switch allows you to specify a custom regular expression for the search and it requires you to also input a word position using the `-p` switch. The command guide shows examples of the usage of a custom search y giving you the values used to search for names, objects, object-groups, and access-lists.

#### JSON Output
ASA-Cleanup will output formatted JSON data containing all of the analysis and usage data. This is a simple JSON dump of the main data dictionary which is used by the default Jinja2 template to format the data into what you see by default.

#### Jinja2 Custom Format
The `-f` switch allows you to input the filename of a Jinja2 template. This template file will be used to format the analysis data and display it in the terminal. The default Jinja2 templates are in the Templates folder and can be copied/modified to provide the specific output you want.



--------------------------------------
## COMPILE
If you want to compile it yourself instead of using the included binaries, ASA-Cleanup can be compiled with Python 2.7+ or Python 3.6+

#### Windows
  1. Install Python 2.7.X interpreter from the [Python Website][python_website]
  2. Download "pip-Win" from its [download site][pip_win]
	  - Upgrade pip-Win by running the command `upgrade`
	    - You may get a SSL error and need to download get-pip.py from https://pip.pypa.io/en/stable/installing/ and place it in the correct folder. The folder will be displayed in one of the errors.
  3. Open pip-Win and start a virtual environment with `venv -c -i ASA-Cleanup`
	  - If successful, you will get a prompt starting with `(ASA-Cleanup) C:\...`
  4. Install PyInstaller with command `pip install PyInstaller`
	  - You will also need to `pip install netmiko` and `pip install jinja2`
  5. Navigate to the folder with the ASA-Cleanup.py file
  6. Run command to compile: `pyinstaller --onefile --clean ASA-Cleanup.py`

#### MacOS/Linux
  1. Install Python 2.7.X and set as default interpreter
	  - Install [Homebrew][homebrew]
	  - Open Terminal and use Homebrew to install updated Python: `brew install python`
	  - Open the bash_profile in VI and add the new Python path: `more .bash_profile`
	    - Insert the line at the bottom: `export PATH="/usr/local/Cellar/python/2.7.14/bin:${PATH}"`
	  - Close Terminal and reopen it, type `python --version` and make sure it shows version 2.7.13 or greater
  2. Install Pip with command `sudo easy_install pip`
  3. Use Pip to install PyInstaller `pip install pyinstaller`
	  - You will also need to `pip install netmiko` and `pip install jinja2`
  4. Navigate to the folder with the ASA-Cleanup.py file
  5. Run command to compile: `pyinstaller --onefile --clean ASA-Cleanup.py`



[logo]: /ASA-Cleanup-Log-100.png
[python_website]: https://www.python.org/
[pip_win]: https://sites.google.com/site/pydatalog/python/pip-for-windows
[homebrew]: https://brew.sh/
