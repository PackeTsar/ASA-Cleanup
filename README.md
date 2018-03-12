# ASA-Cleanup

A config and ACL hits analysis tool to help identify unused configuration items



## VERSION
-----------------------------------------
The version of ASA-Cleanup documented here is: **v1.0.0**



## TABLE OF CONTENTS
-----------------------------------------
1. [How To Use](#what-is-radiuid)



## HOW TO USE
-----------------------------------------









--------------------------------------
## COMPILE
ASA-Cleanup can be compiled with Python 2.7+ or Python 3.6+

##### Windows
  1. Install Python interpreter from the [Python Website][python_website]
  2. Download "pip-Win" from its [download site][pip_win]
  3. Open pip-Win and run with command `venv -c -i  pyi-env-name`
  4. Install PyInstaller with command `pip install PyInstaller`
    - You will also need to `pip install netmiko` and `pip install netaddr`
  5. Navigate a folder with AutoCRT.py
  6. Run command to compile: `pyinstaller --onefile AutoCRT.py`

##### MacOS/Linux
  1. Install Python 2.7.X and set as default interpreter
	  - Install [Homebrew][homebrew]
	  - Open Terminal and use Homebrew to install updated Python: `brew install python`
	  - Open the bash_profile in VI and add the new Python path: `more .bash_profile`
	    - Insert the line at the bottom: `export PATH="/usr/local/Cellar/python/2.7.13/bin:${PATH}"`
	  - Close Terminal and reopen it, type `python --version` and make sure it shows version 2.7.13 or greater
  2. Install Pip with command `sudo easy_install pip`
  3. Use Pip to install PyInstaller `pip install pyinstaller`
    - You will also need to `pip install netmiko` and `pip install netaddr`
  4. Run command to compile: `pyinstaller --onefile --windowed --icon=acid.ico --clean Acid.py`



[python_website]: https://www.python.org/
[pip_win]: https://sites.google.com/site/pydatalog/python/pip-for-windows
[homebrew]: https://brew.sh/