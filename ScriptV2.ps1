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
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force | Out-Null
    } catch {
        Write-Warning "Failed to set registry value at $Path\$Name"
    }
}

$protocols = @{
    'SSL 2.0' = $false
    'SSL 3.0' = $false
    'TLS 1.0' = $false
    'TLS 1.1' = $false
    'TLS 1.2' = $true
    'TLS 1.3' = if ([System.Version]$os.Version -ge [System.Version]'10.0.20348') { $true } else { $false }
}

foreach ($protocol in $protocols.Keys) {
    $enabled = $protocols[$protocol]
    $regPathClient = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
    $regPathServer = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"

    Set-RegistryValue -Path $regPathClient -Name 'Enabled' -Value ([int][bool]$enabled)
    Set-RegistryValue -Path $regPathClient -Name 'DisabledByDefault' -Value ([int](-not $enabled))
    Set-RegistryValue -Path $regPathServer -Name 'Enabled' -Value ([int][bool]$enabled)
    Set-RegistryValue -Path $regPathServer -Name 'DisabledByDefault' -Value ([int](-not $enabled))

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

    # Create registry paths if not exist
    Set-RegistryValue -Path $regPathClient -Name 'Enabled' -Value 0
    Set-RegistryValue -Path $regPathServer -Name 'Enabled' -Value 0

    Write-Host "$protocol has been disabled."
}

Write-Host "Script execution completed. Please restart your system to apply changes."
