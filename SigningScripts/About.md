# Instructions and Information about Signing PS1 Scripts

## What does it mean to have an Unsigned Script?
Unsigned scripts are ps1 scripts that have not been signed by a verified publisher. As a result your operating system
may block a script from executing depending on your network/organizations policies. 

## Why Does it Matter?

## Windows Execution Policies
Windows Execution Policies Ordered from Most to Least Secure:
1. Restricted - No Scripts, Configuration Files, Module Script Files, or PowerShell Profile Can Execute
2. Undefined - Default Policy for Windows 11, Reverts the Policy to Restricted
3. All Signed - All Scripts and Configuration Files Must be Signed by a Trusted Publisher. Including Locally Written Scripts 
4. Remote Signed - Execution of Unsigned Scripts for Other Sources than the Internet and Signed Malicious Scripts are Allowed
5. Unrestricted - Provides a Security Warning But You Still Have the Option to Run a Script
6. Bypass - No Script Will Be Blocked and No Warnings Will Be Displayed

# Sources/References
https://codesigningstore.com/powershell-script-is-not-digitally-signed-error
https://codesigningstore.com/how-to-sign-a-powershell-script
https://codesigningstore.com/how-to-create-self-signed-code-signing-certificate-with-powershell
https://codesigningstore.com/what-is-a-digital-certificate
https://www.netiq.com/documentation/appmanager-modules/appmanagerforwindows/data/b116b7hm.html