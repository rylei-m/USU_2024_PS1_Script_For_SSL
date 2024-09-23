# Potential Future Additions
Optional: Re-create ciphers key if needed (example placeholder) \
$ciphersRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers" \
New-Item -Path $ciphersRegPath -Force | Out-Null \
Write-Host "Ciphers key has been re-created."



$ngcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC"
if (Test-Path -Path $ngcPath) {
   try {
       Remove-Item -Path $ngcPath -Recurse -Force
       Write-Host "NGC folder has been removed."
   } catch [System.UnauthorizedAccessException] {
       Write-Warning "Access denied to remove NGC folder at $ngcPath. Run PowerShell as administrator."
   } catch {
       Write-Warning "Failed to remove NGC folder at $ngcPath"
   }
} else {
    Write-Host "NGC folder does not exist."
}

Optional: Disable old PCT protocols