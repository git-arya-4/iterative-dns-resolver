[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Restore,
    [string]$InterfaceAlias = "",
    [string]$BackupPath = ".\experiments\os_integration\windows_dns_backup.json"
)

$ErrorActionPreference = "Stop"

if ($Apply -and $Restore) { throw "Choose either -Apply or -Restore, not both." }
if (-not $Apply -and -not $Restore) {
    throw "This script changes system DNS settings only with explicit -Apply or -Restore."
}

if ($Restore) {
    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) { throw "DNS backup not found: $BackupPath" }
    $backup = Get-Content -Raw -LiteralPath $BackupPath | ConvertFrom-Json
    $restoreAlias = [string]$backup.InterfaceAlias
    if ([string]::IsNullOrWhiteSpace($restoreAlias)) {
        throw "DNS backup does not contain an interface alias: $BackupPath"
    }
    if (-not [string]::IsNullOrWhiteSpace($InterfaceAlias) -and $InterfaceAlias -ine $restoreAlias) {
        throw "The backup is for '$restoreAlias', not '$InterfaceAlias'."
    }

    $dhcpProperty = $backup.PSObject.Properties["Dhcp"]
    if ($null -eq $dhcpProperty -or [string]::IsNullOrWhiteSpace([string]$dhcpProperty.Value)) {
        # Backups written by the original script did not record the DNS mode.
        $ipInterface = @(Get-NetIPInterface -InterfaceAlias $restoreAlias -AddressFamily IPv4)
        if ($ipInterface.Count -ne 1) {
            throw "Could not determine DHCP state for interface '$restoreAlias'."
        }
        $dhcpMode = [string]$ipInterface[0].Dhcp
    } else {
        $dhcpMode = [string]$dhcpProperty.Value
    }

    if ($dhcpMode -ieq "Enabled") {
        Set-DnsClientServerAddress -InterfaceAlias $restoreAlias -ResetServerAddresses
    } elseif ($dhcpMode -ieq "Disabled") {
        if ($null -eq $backup.PSObject.Properties["ServerAddresses"]) {
            throw "DNS backup does not contain server addresses: $BackupPath"
        }
        $serverAddresses = [string[]]$backup.ServerAddresses
        if ($null -eq $serverAddresses -or $serverAddresses.Count -eq 0) {
            throw "DNS backup contains no static server addresses: $BackupPath"
        }
        Set-DnsClientServerAddress -InterfaceAlias $restoreAlias -ServerAddresses $serverAddresses
    } else {
        throw "DNS backup contains an unknown DHCP state: $dhcpMode"
    }

    # Leave the backup in place so a repeated -Restore is safe and idempotent.
    Write-Output "Restored DNS servers for $restoreAlias."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($InterfaceAlias)) {
    $active = @(Get-NetAdapter | Where-Object Status -eq "Up")
    if ($active.Count -ne 1) { throw "Specify -InterfaceAlias when zero or multiple adapters are active." }
    $InterfaceAlias = $active[0].Name
}

if (Test-Path -LiteralPath $BackupPath -PathType Leaf) {
    $existingBackup = Get-Content -Raw -LiteralPath $BackupPath | ConvertFrom-Json
    $existingAlias = [string]$existingBackup.InterfaceAlias
    if ([string]::IsNullOrWhiteSpace($existingAlias)) {
        throw "DNS backup does not contain an interface alias: $BackupPath"
    }
    if ($existingAlias -ine $InterfaceAlias) {
        throw "DNS backup is for '$existingAlias'; refusing to overwrite it for '$InterfaceAlias'."
    }
} else {
    $ipInterface = @(Get-NetIPInterface -InterfaceAlias $InterfaceAlias -AddressFamily IPv4)
    if ($ipInterface.Count -ne 1) {
        throw "Could not determine DHCP state for interface '$InterfaceAlias'."
    }
    $dhcpMode = [string]$ipInterface[0].Dhcp
    if ($dhcpMode -notin @("Enabled", "Disabled")) {
        throw "Could not determine DHCP state for interface '$InterfaceAlias'."
    }

    $current = Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4
    $backup = [ordered]@{
        InterfaceAlias = $InterfaceAlias
        Dhcp = $dhcpMode
        ServerAddresses = @($current.ServerAddresses)
    }
    $backupDirectory = Split-Path -Parent $BackupPath
    if ($backupDirectory -and -not (Test-Path -LiteralPath $backupDirectory)) {
        New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
    }
    $backup | ConvertTo-Json | Set-Content -LiteralPath $BackupPath -Encoding utf8
}

Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses "127.0.0.1"
Write-Output "Configured $InterfaceAlias to use 127.0.0.1. Backup: $BackupPath"
