PS C:\Users\rymin\Downloads> powershell.exe -ExecutionPolicy Bypass -File "C:\Users\rymin\Downloads\ScriptV2.ps1"
SSL 2.0 has been disabled
SSL 3.0 has been disabled
TLS 1.0 has been disabled
TLS 1.2 has been enabled
TLS 1.3 has been disabled
TLS 1.1 has been disabled
Remove-Item : Cannot find path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40\128'
because it does not exist.
At C:\Users\rymin\Downloads\ScriptV2.ps1:57 char:9
+         Remove-Item -Path $regPath -Recurse -Force | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (HKLM:\SYSTEM\Cu...hers\RC2 40\128:String) [Remove-Item], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand

RC2 40/128 cipher has been removed.
Remove-Item : Cannot find path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56\128'
because it does not exist.
At C:\Users\rymin\Downloads\ScriptV2.ps1:57 char:9
+         Remove-Item -Path $regPath -Recurse -Force | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (HKLM:\SYSTEM\Cu...hers\RC2 56\128:String) [Remove-Item], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand

RC2 56/128 cipher has been removed.
Remove-Item : Cannot find path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40\128'
because it does not exist.
At C:\Users\rymin\Downloads\ScriptV2.ps1:57 char:9
+         Remove-Item -Path $regPath -Recurse -Force | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (HKLM:\SYSTEM\Cu...hers\RC4 40\128:String) [Remove-Item], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand

RC4 40/128 cipher has been removed.
Remove-Item : Cannot find path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56\128'
because it does not exist.
At C:\Users\rymin\Downloads\ScriptV2.ps1:57 char:9
+         Remove-Item -Path $regPath -Recurse -Force | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (HKLM:\SYSTEM\Cu...hers\RC4 56\128:String) [Remove-Item], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand

RC4 56/128 cipher has been removed.
Remove-Item : Cannot find path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64\128'
because it does not exist.
At C:\Users\rymin\Downloads\ScriptV2.ps1:57 char:9
+         Remove-Item -Path $regPath -Recurse -Force | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (HKLM:\SYSTEM\Cu...hers\RC4 64\128:String) [Remove-Item], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand

RC4 64/128 cipher has been removed.
Remove-Item : Cannot find path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56\56'
because it does not exist.
At C:\Users\rymin\Downloads\ScriptV2.ps1:57 char:9
+         Remove-Item -Path $regPath -Recurse -Force | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (HKLM:\SYSTEM\Cu...phers\DES 56\56:String) [Remove-Item], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand

DES 56/56 cipher has been removed.
Remove-Item : Cannot find path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\3DES
168\168' because it does not exist.
At C:\Users\rymin\Downloads\ScriptV2.ps1:57 char:9
+         Remove-Item -Path $regPath -Recurse -Force | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (HKLM:\SYSTEM\Cu...rs\3DES 168\168:String) [Remove-Item], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand

3DES 168/168 cipher has been removed.
Remove-Item : Cannot find path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA1' because
it does not exist.
At C:\Users\rymin\Downloads\ScriptV2.ps1:71 char:9
+         Remove-Item -Path $regPath -Recurse -Force | Out-Null
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (HKLM:\SYSTEM\Cu...NEL\Hashes\SHA1:String) [Remove-Item], ItemNotFoundEx
   ception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.RemoveItemCommand

SHA1 hash has been removed.
Remove-Item : Access to the path 'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC' is denied.
At C:\Users\rymin\Downloads\ScriptV2.ps1:81 char:9
+         Remove-Item -Path $ngcPath -Recurse -Force
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Windows\Serv...l\Microsoft\NGC:String) [Remove-Item], Unauthorized
   AccessException
    + FullyQualifiedErrorId : RemoveItemUnauthorizedAccessError,Microsoft.PowerShell.Commands.RemoveItemCommand

NGC folder has been removed.
Optional: : The term 'Optional:' is not recognized as the name of a cmdlet, function, script file, or operable
program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At C:\Users\rymin\Downloads\ScriptV2.ps1:88 char:1
+ Optional: Disable old PCT protocols
+ ~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Optional::String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PCT 1.0 has been disabled.
Script execution completed. Please restart your system to apply changes.
