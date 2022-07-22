# Windows-Deployment

### Overview

This repo is a collection of scripts that work in conjunction to provision Windows 10/11 machines.
This project is FOSS and licensed under the GPL 3 license. Contributions and collaboration is always appreciated.

These scripts configure a lot within Windows and are very malleable to suit any need. These scripts will strip out a lot of vendor installed software like Spotify, MSOffice 365, Netflix and all the other XApps that come pre-installed. These programs do not exist in the base, fresh Windows install.

Make sure to read the comments. They explain a lot of what is going on in the code.

### Install.ps1

This is the base script that sets the stage for the rest of the scripts.
The username and password in this script are in PLAIN TEXT.
If you plan to use/forkthis project it is HIGHLY SUGGESTED that you CHANGE these values and ONLY use a file stored on a secure network storage or a local file on your machine. DO NOT USE THE DEFAULT VALUES!!!
Install does the following:

- Creates Directories on C to store working files.
- Creates a log file
- Downloads cleanup and Windows-Setup scripts from Github
- Sets a local admin with password that does not expire.
- Disables all privacy switches at the end of the OOBE,
- Sets registry keys for AutoLogon to improve automation
- Runs Cleanup script

### Cleanup.ps1

This script is called from Install.ps1 and does some cleanup from Install.ps1 and calls the Windows-Setup Script.
The following is executed:

- Creates a Log file
- Sleeps for 1 minute to let registry populate after login
- Diables AutoLogon
- Removes stored credentials
- Runs Windows-Setup
- Prints a message that the window will close

### Windows-Setup.ps1

This is the meat and potatoes (yum!) of the deployment and does the most configuration and heavy lifting.
If you're using this project you'll most likely be editing and tweaking this script the most.
This script could also be used after initial login independently of the other scripts.
The following is executed:

- A log file is created
- The computer name is set and asked for verification. This requires user input
- The admin password is reset. This requires user input
- Initial variables are set
- F8 to boot into Safe Mode is enabled
- System Restore size is set to 5%
- TRIM over provisioning is enabled for SSD protection
- System Restore is enabled and a restore point is created
- Power Options are set and a Time Zone is set as well
- .NET Framework is enabled
- LLMNR is disableed
- NBT-NS is disabled
- SMB signing as 'always' is set.
- Group Policy is edited to include:
    * Password History of 10
    * Unlimited Maximum password age
    * Minimum password age of 0 days
    * Minimum password length of 12 charcters
    * Password Complexity requriements must be met (Read the comment on this one at line 139)
    * Sets lockout threshold to 5 attemtps
    * Sets lockout counter to reset after 30 minutes. Lockout duration is also set to 30 minutes
    * Enables teh screen saver with a timeout of 15 minutes
    * Sets Screen Saver to scrnsave.scr (blank screen)
    * Password protects Screen Saver
    * Prevents changing of Screen Saver
    * Enables Bitlocker and exports the key to the external device this is running off (see Usage Section)
- Creates a local user and sets as admin
- Locks the system from auto upgrading to Windows 11 (This has no effect on Windows 11 fresh installs)
- Installs Chocolatey
    * Chocolatey installs the following:
        - Java
        - Firefox
        - Chrome
        - Adobe Reader
        - 7-zip
 - 
