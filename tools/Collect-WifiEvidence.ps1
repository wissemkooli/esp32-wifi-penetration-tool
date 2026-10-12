# Windows 10/11, Windows PowerShell 5.1+. Read-only connection observations.
# Does not start an ESP32 job, change Wi-Fi configuration, or capture raw frames.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]+$')][string]$Scenario,
    [ValidateRange(30,900)][int]$Seconds = 180,
    [string]$Gateway = '',
    [string]$OutputRoot = "$env:USERPROFILE\Desktop\WiFiEvidence"
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this collector on Windows.' }
if ($Gateway) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Gateway, [ref]$parsed)) {
        throw 'Gateway must be an IP address from ipconfig, not a host name or command.'
    }
}
$start = Get-Date
$folder = Join-Path $OutputRoot ($Scenario + '-' + $start.ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
function Save-Command([string]$Name, [string]$Program, [string[]]$Arguments) {
    try {
        $output = & $Program @Arguments 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $output | Out-File -LiteralPath (Join-Path $folder $Name) -Encoding utf8
        "$( [DateTime]::UtcNow.ToString('o') ) $Program exit=$exitCode" |
            Add-Content -LiteralPath (Join-Path $folder 'collector-status.txt') -Encoding utf8
    } catch {
        $_ | Out-String | Add-Content -LiteralPath (Join-Path $folder 'collector-status.txt') -Encoding utf8
    }
}
[ordered]@{
    schema_version = 1; scenario = $Scenario; started_utc = $start.ToUniversalTime().ToString('o')
    planned_seconds = $Seconds; gateway = $Gateway; powershell = $PSVersionTable.PSVersion.ToString()
    computer_role = 'FILL IN: client / hotspot host / ESP32 dashboard'
    target_bssid = 'FILL IN'; target_channel = 'FILL IN'; phone_role = 'FILL IN'
    firmware_commit = 'FILL IN'; boot_id = 'FILL IN'; job_id = 'FILL IN'
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'manifest.json') -Encoding utf8
@'
Record UTC action times here (PowerShell: [DateTime]::UtcNow.ToString('o')):
baseline_start:
manual_disconnect_or_network_switch:
manual_reconnect:
job_start:
job_stop_or_deadline:
dashboard_reconnected:
observed_wifi_disconnect:
observed_reconnect:
result: software_error / capture_observed / disconnect_observed / no_effect_observed / inconclusive
Notes: distinguish Wi-Fi association, local ping, Internet access, and dashboard availability.
'@ | Set-Content -LiteralPath (Join-Path $folder 'notes.txt') -Encoding utf8
Save-Command 'drivers.txt' 'netsh.exe' @('wlan','show','drivers')
Save-Command 'ipconfig.txt' 'ipconfig.exe' @('/all')
Save-Command 'windows-version.txt' 'cmd.exe' @('/c','ver')
Write-Host "Saving evidence to $folder"
Write-Host 'Keep this running through baseline, test and recovery. Sampling is approximate, not per-frame.'
$deadline = $start.AddSeconds($Seconds)
try {
    while ((Get-Date) -lt $deadline) {
        $sample = [ordered]@{ utc = [DateTime]::UtcNow.ToString('o') }
        try {
            $sample.interfaces = (& netsh.exe wlan show interfaces 2>&1 | Out-String)
            $sample.interfaces_exit = $LASTEXITCODE
        } catch { $sample.interfaces_error = $_.Exception.Message }
        if ($Gateway) {
            $sample.ping_started_utc = [DateTime]::UtcNow.ToString('o')
            try {
                $sample.ping = (& ping.exe -n 1 -w 1000 $Gateway 2>&1 | Out-String)
                $sample.ping_exit = $LASTEXITCODE
            } catch { $sample.ping_error = $_.Exception.Message }
        }
        $sample.finished_utc = [DateTime]::UtcNow.ToString('o')
        $sample | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $folder 'samples.jsonl') -Encoding utf8
        Start-Sleep -Seconds 2
    }
} finally {
    $end = Get-Date
    $end.ToUniversalTime().ToString('o') | Set-Content -LiteralPath (Join-Path $folder 'ended-utc.txt') -Encoding utf8
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; StartTime = $start; EndTime = $end
        } -ErrorAction Stop | Sort-Object TimeCreated | ForEach-Object {
            [ordered]@{ utc = $_.TimeCreated.ToUniversalTime().ToString('o'); id = $_.Id
                provider = $_.ProviderName; message = $_.Message; xml = $_.ToXml()
            } | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $folder 'wlan-events.jsonl') -Encoding utf8
        }
    } catch {
        "WLAN event export unavailable or empty: $($_.Exception.Message)" |
            Add-Content -LiteralPath (Join-Path $folder 'collector-status.txt') -Encoding utf8
    }
    Write-Host "Finished: $folder"
    Write-Host 'Add the ESP32 device log, screenshots, captures, and action times to this folder.'
}
# Individual native-command errors are recorded in the bundle. Only a collector
# exception should fail the script; do not leak the last netsh/ping exit code.
exit 0
