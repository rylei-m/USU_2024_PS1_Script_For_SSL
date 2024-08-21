# Win2012R2 and higher may use 'Get-CimInstance -Class Win32_OperatingSystem' as 'Get-WmiObject' is deprecated in Powershell 6.2+. Win2008R2 does not support 'Get-CimInstance'.
try {
  $os = Get-CimInstance -Class Win32_OperatingSystem
} catch {
  $os = Get-WmiObject -class Win32_OperatingSystem
}

# Disable Multi-Protocol Unified Hello
Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name "AllowDomainPINLogon" -Value 0
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings -Name "AllowSignInOptions" -Value 0

# Possible TODO: Remove NGC Folder

# TODO: Disable PCT 1.0

# Disable SSL 2.0 (PCI Compliance)
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 2.0 Disabled'

# Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 3.0 Disabled'

# NOTE: If you disable SSL 3.0 the you may lock out some people still using
# Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
# for these people to fall back. Safer shopping certifications may require that
# you disable SSLv3.


# Disable TLS 1.0 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null

# Add and Disable TLS 1.1 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null

# Add and Enable TLS 1.2 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null


if ([System.Version]$os.Version -lt [System.Version]'10.0.20348') {
  # Microsoft integrated TLS 1.3 as a preview in Windows 10, but this code seems to be unstable and is causing malfunctions.
  Remove-Item -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3' -Recurse -ErrorAction SilentlyContinue
  Write-Host 'TLS 1.3 has been disabled for Windows 10/2016/2019.'
} else {
  # Add and Enable TLS 1.3 for client and server SCHANNEL communications
  New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
  New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'Enabled' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
  Write-Host 'TLS 1.3 has been enabled for Windows 11/2022 and later.'
}

# TODO: Re-create the ciphers key.

# Disable insecure/weak ciphers.
$insecureCiphers = @(
  'DES 56/56',
  'NULL',
  'RC2 128/128',
  'RC2 40/128',
  'RC2 56/128'#,
  # 'RC4 40/128',
  # 'RC4 56/128',
  # 'RC4 64/128',
  # 'RC4 128/128'#,
  # 'Triple DES 168'
)
Foreach ($insecureCipher in $insecureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
  $key.SetValue('Enabled', 0, 'DWord')
  $key.close()
  Write-Host "Weak cipher $insecureCipher has been disabled."
}

# TODO: Enable new secure ciphers.
# - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
# - 3DES: It is recommended to disable these in near future. This is the last cipher supported by Windows XP.
# - Windows Vista and before 'Triple DES 168' was named 'Triple DES 168/168' per https://support.microsoft.com/en-us/kb/245030
$secureCiphers = @(
  'AES 128/128',
  'AES 256/256',
  'RC4 40/128',
  'RC4 56/128',
  'RC4 64/128',
  'RC4 128/128',
  'Triple DES 168'
)
Foreach ($secureCipher in $secureCiphers) {
}

# TODO: Set hashes configuration.

$secureHashes = @(

)

Foreach ($secureHash in $secureHashes) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "Hash $secureHash has been enabled."
}

# TODO: Set KeyExchangeAlgorithms configuration.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
$secureKeyExchangeAlgorithms = @(
)

Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
}

# Microsoft Security Advisory 3174644 - Updated Support for Diffie-Hellman Key Exchange
# https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3174644

# https://support.microsoft.com/en-us/help/3174644/microsoft-security-advisory-updated-support-for-diffie-hellman-key-exc

# TODO: Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).

if ([System.Version]$os.Version -lt [System.Version]'10.0') {
  Write-Host 'Use cipher suites order for Windows 2008/2008R2/2012/2012R2.'
} elseif ([System.Version]$os.Version -lt [System.Version]'10.0.20348') {
  Write-Host 'Use cipher suites order for Windows 10/2016/2019.'
} else {
  Write-Host 'Use cipher suites order for Windows 11/2022 and later.'
}

# One user reported this key does not exists on Windows 2012R2. Cannot repro myself on a brand new Windows 2012R2 core machine. Adding this just to be save.

# Exchange Server TLS guidance Part 2: Enabling TLS 1.2+ and Identifying Clients Not Using It
# https://blogs.technet.microsoft.com/exchange/2018/04/02/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and-identifying-clients-not-using-it/
# New IIS functionality to help identify weak TLS usage
# https://cloudblogs.microsoft.com/microsoftsecure/2017/09/07/new-iis-functionality-to-help-identify-weak-tls-usage/

if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
}

# DefaultSecureProtocols Value	Decimal value  Protocol enabled
# 0x00000008                                8  Enable SSL 2.0 by default
# 0x00000020                               32  Enable SSL 3.0 by default
# 0x00000080                              128  Enable TLS 1.0 by default
# 0x00000200                              512  Enable TLS 1.1 by default
# 0x00000800                             2048  Enable TLS 1.2 by default
# 0x00002000                             8192  Enable TLS 1.3 by default


# TODO: Update to enable TLS 1.2+ as a default secure protocols in WinHTTP in Windows
# https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in

# TODO: Verify if hotfix KB3140245 is installed.

if ([System.Version]$file_version_winhttp_dll -lt [System.Version]"6.1.7601.23375" -or [System.Version]$file_version_webio_dll -lt [System.Version]"6.1.7601.23375") {
} else {

  if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
    # WinHttp key seems missing in Windows 2019 for unknown reasons.
  }
}

Write-Host -ForegroundColor Red 'A computer restart is required to apply settings. Restart computer now?'
Restart-Computer -Force -Confirm