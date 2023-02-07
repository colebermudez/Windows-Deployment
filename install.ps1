<#
Author: Cole Bermudez
Company: Self
Contact: colebermudezpro@startmail.com
Created: October 15, 2021
Last Modified: October 18, 2021

Credits:

Last updated: 3/19/20212

Description:
Originally used while present at the machine or after
Automate/ScreenConnect had been manually installed.


Limitations:
  installer which will also need to be manually replaced when it expires.
* autoLogon credentials are stored in plaintext.
** The deployment package is encrypted to reduce any risks.

TO DO:
* Encrypt the value for DefaultPassword.
* Prompt for the PC name in OOBE BEFORE running the deployment package.
#>

# Create working directory
New-Item -ItemType Directory -Force -Path C:\Support
New-Item -ItemType Directory -Force -Path C:\Support\Scripts
New-Item -ItemType Directory -Force -Path C:\Support\Logs

# Start a transcript session for debug logging
Start-Transcript -Append C:\Support\Logs\PSScriptLog.txt

<#
Set the variable runOnceScript to contain the actual script.
Windows wants to do all runOnce commands at the same time.
This causes issues during cleanup after deployment.
Mainly, the privacy settings block is undone before profile
creation is completed which breaks the Automate installer.

This script waits 5 minutes after autoLogon executes and
displays a progress bar "countdown" before it cleans up the
autoLogon and stored credential regkeys.
#>

# Download needed scripts
Invoke-WebRequest "https://raw.githubusercontent.com/cole-bermudez/Windows-Deployment/main/cleanup.ps1" -OutFile C:\Support\Scripts\cleanup.ps1
Invoke-WebRequest "https://raw.githubusercontent.com/cole-bermudez/Windows-Deployment/main/Windows-Setup.ps1" -OutFile C:\Support\Scripts\WindowsSetup.ps1

# Set admin user PasswordExpires to never
New-LocalUser -Name "admin" -PasswordNeverExpires 1

# Disable Privacy Settings after Deployment reboot
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1

# Enable Autologon after deployment reboot
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /t REG_SZ /d . /f
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d admin /f
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d 'admin' /f

# Remove autologon after Automate installs
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v !cleanup /t REG_SZ /d 'PowerShell -ExecutionPolicy Bypass -File C:\Support\Scripts\cleanup.ps1' /f

# Close debugging log Transcript
Stop-Transcript
