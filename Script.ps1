try {
    $os = Get-CimInstance -Class Win32_OperatingSystem
} catch {
    $os = Get-WmiObject -class Win32_OperatingSystem
}

function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    try {
        New-Item -Path $Path -Force | Out-Null
        Set-ItemProperty -Path $Path -Name $Name -Value $Value | Out-Null
    } catch {
        Write-Warning "Failed to set registry value at $Path\$Name: $_"
    }
}

$protocols = @{
    'SSL 2.0' = $false
    'SSL 3.0' = $false
    'TLS 1.0' = $false
    'TLS 1.1' = $false
    'TLS 1.2' = if ([System.Version]$os.Version -lt [System.Version]'10.0.20348') { $true } else { $false }
    'TLS 1.3' = if ([System.Version]$os.Version -ge [System.Version]'10.0.20348') { $true } else { $false }
}

foreach ($protocol in $protocols.Keys) {
    $enabled = $protocols[$protocol]
    $regPathClient = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
    $regPathServer = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"

    if ($protocols[$protocol] == $false) {
        Set-RegistryValue -Path $regPathClient -Name 'Disabled' -Value (3)
        Set-RegistryValue -Path $regPathServer -Name 'Disabled' -Value (5)

    } else {
        Set-RegistryValue -Path $regPathClient -Name 'Enabled' -Value (4)
        Set-RegistryValue -Path $regPathServer -Name 'Enabled' -Value (2)
    }
    Write-Host "$protocol has been $(if ($enabled) { 'enabled' } else { 'disabled' })"
}

$insecureCiphers = @(
    'RC2 40/128',
    'RC2 56/128',
    'RC4 40/128',
    'RC4 56/128',
    'RC4 64/128',
    'DES 56/56',
    '3DES 168/168'
)

foreach ($cipher in $insecureCiphers) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
    if (Test-Path $regPath) {
        try {
            Remove-Item -Path $regPath -Recurse -Force | Out-Null
            Write-Host "$cipher cipher has been removed."
        }
        catch {
            Write-Warning "Failed to remove cipher $cipher from $regPath"
        }
    } else {
            Write-Host "$cipher cipher path does not exist."
    }
}

$insecureHashes = @(
    'SHA1'
)

foreach ($hash in $insecureHashes) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$hash"
    if (Test-Path $regPath) {
        try {
            Remove-Item -Path $regPath -Recurse -Force | Out-Null
            Write-Host "$hash hash has been removed."
        }
        catch {
            Write-Warning "Failed to remove hash $hash from $regPath"
        }
    } else {
        Write-Host "$hash hash path does not exist."
    }
}

$oldProtocols = @(
    'PCT 1.0'
)

foreach ($protocol in $oldProtocols) {
    $regPathClient = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
    $regPathServer = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"

    Set-RegistryValue -Path $regPathClient -Name 'Disabled' -Value 0
    Set-RegistryValue -Path $regPathServer -Name 'Disabled' -Value 0

    Write-Host "$protocol has been disabled."
}

Write-Host "Script execution completed. Please restart your system to apply changes."

$restartPrompt = Read-Host -ForegroundColor Red 'A computer restart is required to apply settings. Restart computer now?'
if ($restartPrompt -eq 'Y') {
    Restart-Computer -Force -Confirm
}
