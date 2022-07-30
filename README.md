# Windows-Deployment

## Overview

### Description

This repo is a collection of scripts that work in conjunction to provision Windows 10/11 machines.
The whole process of provisioning takes about 20 minutes from OOBE to rebooting after completion.
This does use Windows Configuration Designer from the Windows Store.
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
- Enables RDP
- Runs O&O Shutup with a custom CFG file
- Disables Telemetry
- Diables Wi-Fi Sense
- Diables Application Suggestions
- Disables Comsumer Features (Ads)
- Disables Location Tracking
- Disables Maps updates
- Diables Feedback
- Disables Tailored Experiences
- Disables Adbertising ID
- Disables Error reporting
- Disables Windows Update P2P
- Disables Diagnostics Tracking
- Disables WAP Push
- Disables Homegroup
- Disables Remote Assistance
- Disables Superfetch
- Disables Hibernation
- Shows Task Manager Details by default
- Shows File Explorer Details
- Hides Task View
- Hides People Icon
- Enables NumLock on Startup
- Changes default File Explorer view to This PC
- Hides 3D objects icon from This PC
- Installs Windows Media Player
- Disables News and Interests
- Removes AutoLogger file
- Turns 68 services from Automatic to Manual (can be expanded to 86. See lines 400-487)
- Disables Bing Search in Start Menu
- Disables Cortana
- Hides Search
- Removes Start Menu Tiles
- Removes 89 XApps (can be expanded to 95 XApps. See lines 578-676)
- Disables drivers through Windows Update
- Disables Windows Update Automatic Restart (This change and the last means Windows will only get security updates).
- Disables Action Center
- Adjusts visual effects for performance
- Shows Tray Icons
- Reboots the computer

## Usage

### Building the PPKG with Windows Configuation Designer

1. If you don't already have it, Go to the Microsoft Store on a Windows Machine and Install the Windows Configuration Designer.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_22.png?raw=true" />
2. In Windows Configuration Designer, Select Advanced Provisioning.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_8.png?raw=true" />
3. Enter a name, project folder (I use the default for almost all selections), enter a description if you like, click 'Next'.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_9.png?raw=true" />
4. Select 'All Windows desktop editions', and 'Next'.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_10.png?raw=true" />
5. Don't import a provisioning package, just click 'Finish'.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_11.png?raw=true" />
6. In the left pane, expand 'Runtime settings', expand 'ProvisioningCommands', and 'PrimaryContext', highlight 'Command'.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_12.png?raw=true" />
7. In the middle pane, enter a name for your command, click 'Add', notice you have a new command in the list.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_13.png?raw=true" />
8. Back in the left pane, you'll have some new options under Install (or your command name). We're only concerned about 'CommandFile' and 'CommandLine'. Browse for and select your iteration of the 'install.ps1' file. Then enter `PowerShell -ExecutionPolicy Bypass -File .\install.ps1` into the 'CommandLine' selection. This is the command you would use to run the file from PowerShell.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_14.png?raw=true" />
9. At the top right, select 'Export', and 'Provisioning Package'.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_15.png?raw=true" />
10. Choose a name and click 'Next'. If you ever re-build your ppkg (provisoning package) the minor number in the version will iterate automatically.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_16.png?raw=true" />
11. You can encrypt the package with a password or sign it with a certificate if you have one. I don't use either of these options so that's up to you.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_17.png?raw=true" />
12. Select a folder to save the package if you want to export it somewhere else.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_18.png?raw=true" />
13. Select 'Build' after reviewing your settings
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_19.png?raw=true" />
14. DON'T CLICK FINISH. Click the path in the 'Output Location'. This will open your File Explorer.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_20.png?raw=true" />
15. Insert a blank USB device into your computer. Copy the <PPKGNAME>.cat and <PPKGNAME>.ppkg to the usb.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Screenshot_21.png?raw=true" />
   
### Using the PPKG during installation

1. When you first boot a computer to provison, you're greeted with the 'Select Your Region' page. Insert the USB that contains the PPKG, enter a password if you used one and let it run, it will reboot a couple times.
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/Windows-10-Creators-Update-Setup-1.jpg" />
OR
<img src="https://github.com/colebermudez/Windows-Deployment/blob/main/PPKG%20Screenshots/windows-11-setup-screen-country-region-mrnoob-768x578.png" />
2. There will be some, but very little user interaction needed. You will need to enter the computer name, reset the admin password, and create a local user (if you left this code uncommented).
3. The computer will reboot after the script finishes.

## License

- [GNU General Public License (GPL) v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Special Thanks

- [khaosnmt](https://github.com/khaosnmt)
