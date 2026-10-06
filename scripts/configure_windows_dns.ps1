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
    if (-not (Test-Path -LiteralPath $BackupPath)) { throw "DNS backup not found: $BackupPath" }
    $backup = Get-Content -Raw -LiteralPath $BackupPath | ConvertFrom-Json
    Set-DnsClientServerAddress -InterfaceAlias $backup.InterfaceAlias -ServerAddresses $backup.ServerAddresses
    Write-Output "Restored DNS servers for $($backup.InterfaceAlias)."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($InterfaceAlias)) {
    $active = @(Get-NetAdapter | Where-Object Status -eq "Up")
    if ($active.Count -ne 1) { throw "Specify -InterfaceAlias when zero or multiple adapters are active." }
    $InterfaceAlias = $active[0].Name
}

$current = Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4
$backup = [ordered]@{ InterfaceAlias = $InterfaceAlias; ServerAddresses = @($current.ServerAddresses) }
$backup | ConvertTo-Json | Set-Content -LiteralPath $BackupPath -Encoding utf8
Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses "127.0.0.1"
Write-Output "Configured $InterfaceAlias to use 127.0.0.1. Backup: $BackupPath"
