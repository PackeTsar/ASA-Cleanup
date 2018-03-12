# ASA-Cleanup

A config and ACL hits analysis tool to help identify unused configuration items


-----------------------------------------
## VERSION
The version of ASA-Cleanup documented here is: **v1.0.0**



-----------------------------------------
## TABLE OF CONTENTS
1. [How To Use](#what-is-radiuid)



-----------------------------------------
## HOW TO USE
ASA-Cleanup is run from the command line with typical switches and parameters to tell it what to do. It processes the config-file, "show access list" file, or device-direct SSH login and then displays its output.

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


### Basic Use on MacOS/Linux
If you download the whole repository, navigate to the **Binaries** folder and run the binary `./ASA-Cleanup -nogamu ../Examples/ASA_CONFIG.txt`. The switches used here, in order, are (-n: Analyze Name Usage), (-o: Analyze Object Usage), (-g: Analyze Object-Group Usage), (-a: Analyze Access-List Usage), (-m: Show Members in the Breakdown), (-u: Show Detailed Usage in the Breakdown).

An example of an analysis of Access-List hits can be seen with `./ASA-Cleanup -lie ../Examples/SHOW_ACCESS_LIST.txt`. The switches used here, in order, are (-l: Analyze Access-List Hits), (-i: Show children under each ACE in Breakdown), (-e: Show Hit-Counts for each ACE in each ACL in Breakdown)



-----------------------------------------
## EXAMPLE OUTPUT


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
## COMPILE
ASA-Cleanup can be compiled with Python 2.7+ or Python 3.6+

##### Windows
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

##### MacOS/Linux
  1. Install Python 2.7.X and set as default interpreter
	  - Install [Homebrew][homebrew]
	  - Open Terminal and use Homebrew to install updated Python: `brew install python`
	  - Open the bash_profile in VI and add the new Python path: `more .bash_profile`
	    - Insert the line at the bottom: `export PATH="/usr/local/Cellar/python/2.7.13/bin:${PATH}"`
	  - Close Terminal and reopen it, type `python --version` and make sure it shows version 2.7.13 or greater
  2. Install Pip with command `sudo easy_install pip`
  3. Use Pip to install PyInstaller `pip install pyinstaller`
    - You will also need to `pip install netmiko` and `pip install jinja2`
  4. Run command to compile: `pyinstaller --onefile --windowed --clean ASA-Cleanup.py`



[python_website]: https://www.python.org/
[pip_win]: https://sites.google.com/site/pydatalog/python/pip-for-windows
[homebrew]: https://brew.sh/