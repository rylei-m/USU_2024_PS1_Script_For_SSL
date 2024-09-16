# Execution Policy Bypass

Set-ExecutionPolicy is a cmdlet and Bypass is an execution policy. Both are used to manage script execution with 
powershell. 

## Execution Policies
Purpose: To Determine Which Scripts Can Run and Under What Conditions.

Main Policies:
- Restricted
- AllSigned
- RemoteSigned
- Unrestricted
- Bypass

Reference About.md for More Information

## Set-ExecutionPolicy cmdlet
Example Usage: > Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

## Bypass Policy
Bypassing: This Policy Allows Scripts to Run Without Restriction. Typically Used for Temporary or Emergency Situations. 
This Should Be Used With Caution to Avoid Security Issues.

Example Usage With Bypass: > powershell.exe -ExecutionPolicy Bypass -File "C:\Path\To\YourScript.ps1"

