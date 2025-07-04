<#
.SYNOPSIS
    Attempts to detect the presence of EDR, Antivirus, and SIEM agents on a Windows system.

.DESCRIPTION
    This script utilizes common Living Off The Land (LOTL) techniques to identify
    security products by checking running processes, installed services, driver files,
    registry keys, and installed programs. It specifically targets well-known
    commercial EDR and AV solutions.

.NOTES
    - Requires (Administrator) privileges for comprehensive detection (e.g., driver listing, some service details).
    - Detection is based on known patterns and strings; new versions or custom configurations might evade detection.
    - Designed for authorized red teaming and penetration testing. Use responsibly.

CAN Detect : 
    EDRs: CrowdStrike Falcon , Windows Defender , SentinalOne , Carbon Black , Sophos , Cortex XDR , Symantec , Trend Micro Apexone
    SIEMs: Splunk , Elastic , NXLog , Wazuh , 
    AVs: McAfee , Kaspersky , ESET , Avast , Bitdefender , ZoneAlarm
#>

# --- Configuration ---
$outputFile = "C:\Windows\Temp\security_detection_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$captureToFile = $false # Set to $true to output to a file, otherwise prints to console.

# --- Helper Function for Consistent Output ---
function Write-SectionHeader {
    param (
        [string]$Title
    )
    Write-Host "`n============== $Title ==============`n" -ForegroundColor Green
}

function Add-Output {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

Write-Host "Starting Security Product Detector..." -ForegroundColor Yellow

# Redirect output to file if $captureToFile is true
if ($captureToFile) {
    # Check if we have permission to write to the specified path
    try {
        Set-Content -Path $outputFile -Value "" -ErrorAction Stop # Attempt to create/clear file
        Start-Transcript -Path $outputFile -NoClobber
        Write-Host "Output redirected to: $outputFile" -ForegroundColor Yellow
    } catch {
        Write-Host "WARNING: Could not write to $outputFile. Output will be displayed on console only. Error: $($_.Exception.Message)" -ForegroundColor Red
        $captureToFile = $false # Disable file capture if failed
    }
}


# ===================================================================
# EDR / Endpoint Protection Detection
# ===================================================================
Write-SectionHeader "EDR / Endpoint Protection Detection"

# Common EDR/AV Process Names (case-insensitive)
$edrAvProcesses = @(
    "MsMpEng.exe", "SenseNdr.exe", "NisSrv.exe", "msseces.exe", "MRT.exe", # Windows Defender/MSE
    "csagent.exe", "CSFalconService.exe", "CylanceSvc.exe", "CylanceUI.exe", # CrowdStrike, Cylance
    "MsSense.exe", "SenseCnc.exe", "SenseIR.exe", "MsSenseBC.exe", # Microsoft Defender ATP (MDE)
    "symantec.exe", "ccSvcHst.exe", "SavService.exe", # Symantec
    "SophosLiveProtection.exe", "SophosMessageRelay.exe", "SSPService.exe", # Sophos
    "CarbonBlack.exe", "EvoClient.exe", "RepMgr.exe", # Carbon Black (VMware Carbon Black)
    "wscsvc.exe", "FortiClient.exe", # Fortinet
    "McAfee*.exe", "mcagent.exe", "macmnsvc.exe", # McAfee (Wildcard for common executables)
    "VzUpdate.exe", "vrmem.exe", "vsmon.exe", # Trend Micro
    "SentinelAgent.exe", "SentinelOne.exe", # SentinelOne
    "Elastic Agent.exe", "endpoint.exe", # Elastic Security
    "bdagent.exe", "bdredlineclient.exe", # Bitdefender
    "eset.exe", "ekrn.exe", # ESET
    "cyserver.exe", "psprotect.exe", # Palo Alto Networks Cortex XDR
    "AvastSvc.exe", "avgidsagent.exe", # Avast, AVG
    "Kaspersky*.exe", "kavsvc.exe", # Kaspersky (Wildcard for common executables)
    "Defender*.exe", # Generic MS Defender processes
    "Wd*.exe" # Generic MS Defender processes
)
Add-Output "`n[+] Checking Running Processes for EDR/AV Indicators..." -Color Yellow
$runningProcesses = Get-Process -ErrorAction SilentlyContinue | Select-Object ProcessName, Id, Path
foreach ($proc in $runningProcesses) {
    if ($edrAvProcesses -contains $proc.ProcessName -or $edrAvProcesses -like $proc.ProcessName) { # Handles wildcards with -like
        Add-Output "  DETECTED (Process): $($proc.ProcessName) (PID: $($proc.Id)) - Path: $($proc.Path)" -Color Red
    }
}

# Common EDR/AV Service Names
$edrAvServices = @(
    "MsSense", "Sense", "WdBoot", "WdNisOVC", "WinDefend", "SenseCnc", # Microsoft Defender ATP
    "FalconService", "CrowdStrike", "Falcon Agent", "CSAgent", # CrowdStrike Falcon
    "CylanceSvc", "CylanceUI", "Cylance", # Cylance PROTECT
    "Symantec Endpoint Protection", "SepService", "ccSvcHst", # Symantec
    "Sophos Agent", "Sophos Anti-Virus", "Sophos Endpoint", "SophosSSP", # Sophos
    "CbDefense", "Carbon Black", "rep_mgr", "CarbonBlackEvo", # Carbon Black
    "FortiClient Service", # Fortinet
    "McAfee Agent", "McAfee Framework", "McAfeeESM", # McAfee
    "TmWSCSvc", "VzApplog", "VzLpc", # Trend Micro
    "SentinelAgent", "Sentinel One Service", # SentinelOne
    "Elastic Endpoint", "Elastic Agent", # Elastic Security
    "Bitdefender Agent", "bdcontrolcenter", # Bitdefender
    "ESET Service", "ESET Security", # ESET
    "Palo Alto Networks Cortex XDR", # Palo Alto Cortex XDR
    "AvastSvc", "AVG", # Avast, AVG
    "Kaspersky Lab", "Kaspersky Anti-Virus" # Kaspersky
)

Add-Output "`n[+] Checking Installed Services for EDR/AV Indicators..." -Color Yellow
# Use Get-CimInstance for services as it's more stable remotely
$installedServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, PathName
foreach ($svc in $installedServices) {
    $found = $false
    foreach ($keyword in $edrAvServices) {
        if ($svc.Name -like "*$keyword*" -or $svc.DisplayName -like "*$keyword*" -or $svc.PathName -like "*$keyword*") {
            Add-Output "  DETECTED (Service): $($svc.DisplayName) (Name: $($svc.Name)) - State: $($svc.State) - Path: $($svc.PathName)" -Color Red
            $found = $true
            break
        }
    }
}

# Common EDR/AV Driver Files (checking presence in System32\drivers)
$edrAvDrivers = @(
    "sense.sys", "cscore.sys", "sensecfs.sys", "sensecsa.sys", # Microsoft Defender for Endpoint
    "cyguard.sys", "cyvrfsps.sys", # Cylance
    "falcon.sys", "csfalconstore.sys", "csagent.sys", # CrowdStrike
    "symantec*.sys", "bh*.sys", # Symantec
    "sophos*.sys", "ssp*.sys", # Sophos
    "cbr*.sys", "carbonblack*.sys", # Carbon Black
    "fctap.sys", "fclwfp.sys", # Fortinet
    "mfe*.sys", "oas*.sys", # McAfee
    "tmum*.sys", "tmtdi.sys", # Trend Micro
    "senst.sys", "sentinel*.sys", # SentinelOne
    "ephc.sys", "elastic*.sys", # Elastic Security
    "epfw.sys", "epdrv.sys", # ESET
    "bdfilt.sys", "bdard.sys" # Bitdefender
)

Add-Output "`n[+] Checking Driver Files for EDR/AV Indicators..." -Color Yellow
$driversPath = "$env:SystemRoot\System32\drivers"
if (Test-Path $driversPath) {
    foreach ($driverWildcard in $edrAvDrivers) {
        $foundDrivers = Get-ChildItem -Path $driversPath -Filter $driverWildcard -Recurse -ErrorAction SilentlyContinue
        if ($foundDrivers) {
            foreach ($driver in $foundDrivers) {
                Add-Output "  DETECTED (Driver): $($driver.Name) - Path: $($driver.FullName)" -Color Red
            }
        }
    }
} else {
    Add-Output "  [!] Drivers path not found: $driversPath" -Color Yellow
}
# Common EDR/AV Registry Keys (Installed Programs)
$edrAvRegKeys = @(
    "Microsoft\\Sense", # Microsoft Defender for Endpoint
    "CrowdStrike\\Falcon", # CrowdStrike
    "Cylance\\PROTECT", # Cylance
    "Symantec\\Symantec Endpoint Protection", # Symantec
    "Sophos\\Sophos Anti-Virus", # Sophos
    "CarbonBlack\\*", # Carbon Black
    "Fortinet\\FortiClient", # Fortinet
    "McAfee\\*", # McAfee
    "TrendMicro\\*", # Trend Micro
    "SentinelOne\\*", # SentinelOne
    "Elastic\\Endpoint", # Elastic Security
    "Bitdefender\\Endpoint Security" # Bitdefender
    # ESET, Kaspersky, Avast often use specific paths or GUIDs in Uninstall key.
)

Add-Output "`n[+] Checking Installed Software Registry Keys for EDR/AV Indicators..." -Color Yellow
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($uninstallPath in $uninstallPaths) {
    if (Test-Path $uninstallPath) {
        Get-ChildItem -Path $uninstallPath -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
            if ($displayName) {
                foreach ($keyword in $edrAvRegKeys) {
                    if ($displayName -like "*$keyword*") {
                        Add-Output "  DETECTED (Installed Program): $($displayName)" -Color Red
                        break
                    }
                }
            }
        }
    } else {
        Add-Output "  [!] Registry path not found: $uninstallPath" -Color Yellow
    }
}

# ===================================================================
# SIEM Agent Detection
# ===================================================================
Write-SectionHeader "SIEM Agent Detection"

# Common SIEM Agent Process/Service Names (case-insensitive)
$siemIndicators = @(
    "LogRhythm Syslog Agent", "LogRhythm*", # LogRhythm
    "Splunk Universal Forwarder", "splunkd.exe", "splunklicenser.exe", # Splunk
    "ElasticBeat.exe", "winlogbeat.exe", "filebeat.exe", # Elastic Beats (for Elastic SIEM/Stack)
    "ArcSight Logger", "ArcSight SmartConnector", # ArcSight
    "QRadar Agent", "QRadar*", # IBM QRadar
    "AgentSvc.exe", "syslog-agent.exe", # Generic Syslog Agents
    "NXLog*", # NXLog
    "OSQuery", "osqueryd.exe" # OSQuery (often used for endpoint logging to SIEM)
)

Add-Output "`n[+] Checking Processes and Services for SIEM Indicators..." -Color Yellow
# Re-use already gathered processes and services lists
foreach ($proc in $runningProcesses) {
    foreach ($indicator in $siemIndicators) {
        if ($proc.ProcessName -like "*$indicator*") {
            Add-Output "  DETECTED (SIEM Process): $($proc.ProcessName) (PID: $($proc.Id)) - Path: $($proc.Path)" -Color Red
        }
    }
}

foreach ($svc in $installedServices) {
    foreach ($indicator in $siemIndicators) {
        if ($svc.Name -like "*$indicator*" -or $svc.DisplayName -like "*$indicator*") {
            Add-Output "  DETECTED (SIEM Service): $($svc.DisplayName) (Name: $($svc.Name)) - State: $($svc.State) - Path: $($svc.PathName)" -Color Red
        }
    }
}


# ===================================================================
# General Security Posture Checks
# ===================================================================
Write-SectionHeader "General Security Posture Checks"
Add-Output "`n[+] Checking Windows Defender Status..." -Color Yellow
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    Add-Output "  AntiSpywareEnabled: $($defenderStatus.AntiSpywareEnabled)"
    Add-Output "  AntivirusEnabled: $($defenderStatus.AntivirusEnabled)"
    Add-Output "  RealTimeProtectionEnabled: $($defenderStatus.RealTimeProtectionEnabled)"
    Add-Output "  TamperProtectionEnabled: $($defenderStatus.TamperProtectionEnabled)"
    Add-Output "  BehaviorMonitorEnabled: $($defenderStatus.BehaviorMonitorEnabled)"
    Add-Output "  IoavProtectionEnabled: $($defenderStatus.IoavProtectionEnabled)" # Mark of the Web
} catch {
    Add-Output "  [!] Could not get Windows Defender Status. Error: $($_.Exception.Message)" -Color Yellow
}

Add-Output "`n[+] Firewall Status (Windows Defender Firewall)..." -Color Yellow
try {
    $firewallStatus = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    $firewallStatus | Format-List | ForEach-Object {Add-Output "  $_"}
} catch {
    Add-Output "  [!] Could not get Firewall Status. Error: $($_.Exception.Message)" -Color Yellow
}

# ===================================================================
# Finalization
# ===================================================================
Write-Host "`nSecurity Product Detection Complete." -ForegroundColor Yellow

if ($captureToFile) {
    Stop-Transcript
    Write-Host "Output saved to: $outputFile" -ForegroundColor Yellow
}
