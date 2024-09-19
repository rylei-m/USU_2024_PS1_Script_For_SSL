PS C:\Users\rymin\Downloads> powershell.exe -ExecutionPolicy Bypass -File "C:\Users\rymin\Downloads\ScriptV2.ps1"
SSL 2.0 has been disabled \
SSL 3.0 has been disabled \
TLS 1.0 has been disabled \
TLS 1.2 has been enabled \
TLS 1.3 has been disabled \
TLS 1.1 has been disabled \
RC2 40/128 cipher path does not exist. \
RC2 56/128 cipher path does not exist. \
RC4 40/128 cipher path does not exist. \
RC4 56/128 cipher path does not exist. \
RC4 64/128 cipher path does not exist. \
DES 56/56 cipher path does not exist. \
3DES 168/168 cipher path does not exist. \
SHA1 hash path does not exist. \
Remove-Item : Access to the path 'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC' is denied. \
At C:\Users\rymin\Downloads\ScriptV2.ps1:91 char:9 \
\+         Remove-Item -Path $ngcPath -Recurse -Force \
\+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \
&nbsp; \+ CategoryInfo          : PermissionDenied: (C:\Windows\Serv...l\Microsoft\NGC:String) [Remove-Item], Unauthorized AccessException \
&nbsp; \+ FullyQualifiedErrorId : RemoveItemUnauthorizedAccessError,Microsoft.PowerShell.Commands.RemoveItemCommand

NGC folder has been removed. \
PCT 1.0 has been disabled. \
Script execution completed. Please restart your system to apply changes
