# Instructions and Information about Signing PS1 Scripts

## What does it mean to have an Unsigned Script?
Unsigned scripts are PowerShell scripts that have not been signed by a verified publisher. As a result your operating 
system may block a script from executing depending on your network/organizations policies. You can see the list of 
execution policies below to determine your need for a Signed script. 

Essentially, Unsigned scripts do not have a digital signature attached to it. These scripts have not been verified by a 
trusted authority or certificate.

## Why Does it Matter?

## Windows Execution Policies
Windows Execution Policies Ordered from Most to Least Secure:
1. Restricted - No Scripts, Configuration Files, Module Script Files, or PowerShell Profile Can Execute
2. Undefined - Default Policy for Windows 11, Reverts the Policy to Restricted
3. All Signed - All Scripts and Configuration Files Must be Signed by a Trusted Publisher. Including Locally Written Scripts 
4. Remote Signed - Execution of Unsigned Scripts for Other Sources than the Internet and Signed Malicious Scripts are Allowed
5. Unrestricted - Provides a Security Warning But You Still Have the Option to Run a Script
6. Bypass - No Script Will Be Blocked and No Warnings Will Be Displayed

## Signed Scripts
Signed Scripts have been digitally signed using a certificate. The certificate can be issued by a trusted certificate 
authority or a self-signed certificate. 

### Certificate Authorities (CA)
CA-issues certificates are digital certificates provided by trusted, third-party organizations. \
CAs include:
- VeriSign
- DigiCert
- GlobalSign

These certifications are widely trusted across major operating systems. CAs cost money and the price varies depending on
the level of validation required

### Self-Signed Certificates
SSCs are certificates that are signed by the same person as the one who created the script. 

Essentially, the creator of the certificate vouches for their scripts' validity. 

Self-Signed Certificates are free since they are signed by the user of their organization.

# Sources/References
https://codesigningstore.com/powershell-script-is-not-digitally-signed-error
https://codesigningstore.com/how-to-sign-a-powershell-script
https://codesigningstore.com/how-to-create-self-signed-code-signing-certificate-with-powershell
https://codesigningstore.com/what-is-a-digital-certificate
https://www.netiq.com/documentation/appmanager-modules/appmanagerforwindows/data/b116b7hm.html