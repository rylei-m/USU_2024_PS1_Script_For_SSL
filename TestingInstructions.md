# This script is designed to enhance the security of a Windows devices by configuring various settings related to encryption protocols, ciphers, and hashes. 
### These Steps have the Potential to harm your computer. Only perform the following in a controlled environment

Here’s a step-by-step guide on how to test this script effectively in a Windows 10 VM:

## Preparation
- Backup Your VM: Before running any script that makes extensive changes to system settings, create a snapshot or backup of your VM. This ensures you can revert to a previous state if something goes wrong.
- Open PowerShell with Administrative Rights: The script requires administrative privileges to modify system settings. Right-click the PowerShell icon and select "Run as administrator."

## Testing the Script

- Double-Check Paths and Keys: Ensure that all registry paths and keys used in the script are correct and applicable to your environment.
- Error Handling: The script has some error handling in place (e.g., -ErrorAction SilentlyContinue), but consider adding more robust error checks if needed.

## Running the Script:

- Copy the Script: Copy the script into a .ps1 file (e.g., Configure-Security.ps1).
- Execute the Script: Run the script in PowerShell by navigating to the directory where your script is located and executing it with powershell

## Verify the Changes:

- Check Registry Keys: After running the script, use the Registry Editor (regedit) or PowerShell commands to verify that the changes have been applied correctly.
- Verify Protocols and Ciphers: Use tools like IIS Crypto or PowerShell commands to confirm that the SSL/TLS protocols and cipher suites have been configured as expected.

## Check Application Functionality:

- Test Applications: Ensure that all applications relying on SSL/TLS for secure communications are still functioning correctly.
- Browser and System Checks: Verify that browsers and other network-dependent applications are working as expected with the new security settings.
- System Reboot: The script prompts for a reboot at the end. Reboot the system to apply all changes and check if everything is functioning correctly after the reboot.

## Post-Test Steps
- Monitor System Performance: After applying the changes and rebooting, monitor system performance and application behavior to ensure there are no adverse effects from the changes.
- Document Changes: Document the changes made to the system for future reference. This is useful for troubleshooting and for audit purposes.
- Review Security Impact: Assess the impact of the changes on the overall security posture of your VM and verify that it aligns with your security policies.

## Troubleshooting
- Script Failures: If the script fails, check for error messages in the PowerShell window and review the specific lines in the script causing the issue.
- Rollback: If needed, use the VM snapshot or backup to revert to the previous state.

This approach should help you safely and effectively test your security configuration script. If you encounter specific issues during testing, feel free to ask for further assistance.
