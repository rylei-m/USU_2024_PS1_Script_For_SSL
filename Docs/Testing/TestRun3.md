PS C:\Windows\system32> powershell.exe -ExecutionPolicy Bypass -File "C:\Users\rymin\Downloads\Script.ps1" \
Set-ItemProperty : Cannot find path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' because it does not exist. \
At C:\Users\rymin\Downloads\Script.ps1:9 char:1 \
\+ Set-ItemProperty HKLM:\SOFTWARE\Microsoft\PolicyManager\current\devic ... \
\+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \
&nbsp;&nbsp;&nbsp;&nbsp; + CategoryInfo          : ObjectNotFound: (HKLM:\SOFTWARE\...device\Settings:String) [Set-ItemProperty], ItemNotFoundException \
&nbsp;&nbsp;&nbsp;&nbsp; + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.SetItemPropertyCommand 

SSL 2.0 Disabled \
SSL 3.0 Disabled \
Out-Null : A positional parameter cannot be found that accepts argument 'New-ItemProperty'. \
At C:\Users\rymin\Downloads\Script.ps1:50 char:112 \
\+ ... r' -Force | Out-Null New-ItemProperty -path 'HKLM:\SYSTEM\CurrentCont ... \
\+ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \
&nbsp;&nbsp;&nbsp;&nbsp; + CategoryInfo          : InvalidArgument: (:) [Out-Null], ParameterBindingException \
&nbsp;&nbsp;&nbsp;&nbsp; + FullyQualifiedErrorId : PositionalParameterNotFound,Microsoft.PowerShell.Commands.OutNullCommand

TLS 1.3 has been disabled for Windows 10/2016/2019. \
Weak cipher DES 56/56 has been disabled. \
Weak cipher NULL has been disabled. \
Weak cipher RC2 128/128 has been disabled. \
Weak cipher RC2 40/128 has been disabled. \
Weak cipher RC2 56/128 has been disabled. \
Strong cipher AES 128/128 has been enabled. \
Strong cipher AES 256/256 has been enabled. \
Strong cipher RC4 40/128 has been enabled. \
Strong cipher RC4 56/128 has been enabled. \
Strong cipher RC4 64/128 has been enabled. \
Strong cipher RC4 128/128 has been enabled. \
Strong cipher Triple DES 168 has been enabled. \
Hash SHA has been enabled. \
Hash SHA256 has been enabled. \
Hash SHA384 has been enabled. \
Hash SHA512 has been enabled. \
KeyExchangeAlgorithm Diffie-Hellman has been enabled. \
KeyExchangeAlgorithm ECDH has been enabled. \
KeyExchangeAlgorithm PKCS has been enabled. \
Configure longer DHE key shares for TLS servers. \
Use cipher suites order for Windows 10/2016/2019. \
Enable TLS 1.2 for .NET 3.5 and .NET 4.x \
WinHTTP: Minimum system requirements are met. \
WinHTTP: Activate TLS 1.2+ only. \
Windows Internet Explorer: Activate TLS 1.2 only. \
A computer restart is required to apply settings. Restart computer now? 

Confirm \
Are you sure you want to perform this action? \
Performing the operation "Enable the Local shutdown access rights and restart the computer." on target "localhost (DESKTOP-UIKQB43)". \
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): L \