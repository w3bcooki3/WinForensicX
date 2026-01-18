<#
.SYNOPSIS
    Windows Event Log Security Analyzer - Mini SIEM/DFIR Toolkit with Sigma/YARA Integration
.DESCRIPTION
    Advanced security analysis tool for Windows Event Logs with threat hunting,
    IOC detection, Sigma rule matching, YARA scanning, and HTML reporting capabilities.
.PARAMETER Mode
    Operation mode: QuickScan, DeepAnalysis, LiveMonitor, ThreatHunt, Interactive, SigmaHunt
.PARAMETER EvtxPath
    Path to offline .evtx files (supports wildcards)
.PARAMETER Hours
    Number of hours to look back (default: 24)
.PARAMETER ExportJSON
    Export findings to JSON file
.PARAMETER ExportHTML
    Export findings to HTML report (default: enabled)
.PARAMETER IOC
    Search for specific IOC (IP, domain, hash, username, process)
.PARAMETER IOCFile
    Path to file containing list of IOCs (one per line)
.PARAMETER SigmaPath
    Path to Sigma rule file or directory containing Sigma rules (.yml/.yaml)
.PARAMETER YaraPath
    Path to YARA rule file for memory/process scanning
.PARAMETER ScanMemory
    Enable memory scanning with YARA rules
.PARAMETER ScanProcesses
    Enable process scanning with YARA rules
.EXAMPLE
    .\WinForensicX.ps1 -Mode QuickScan
    .\WinForensicX.ps1 -Mode DeepAnalysis -Hours 48 -ExportHTML
    .\WinForensicX.ps1 -Mode ThreatHunt -IOCFile "C:\iocs.txt"
    .\WinForensicX.ps1 -Mode SigmaHunt -SigmaPath "C:\sigma-rules\"
    .\WinForensicX.ps1 -YaraPath "C:\rules.yar" -ScanProcesses
    .\WinForensicX.ps1 -Mode Interactive -SigmaPath "rules.yml" -IOCFile "iocs.txt"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("QuickScan","DeepAnalysis","LiveMonitor","ThreatHunt","Interactive","SigmaHunt")]
    [string]$Mode = "Interactive",
    
    [Parameter(Mandatory=$false)]
    [string]$EvtxPath,
    
    [Parameter(Mandatory=$false)]
    [int]$Hours = 24,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportJSON,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportHTML = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$IOC,
    
    [Parameter(Mandatory=$false)]
    [string]$IOCFile,
    
    [Parameter(Mandatory=$false)]
    [string]$SigmaPath,
    
    [Parameter(Mandatory=$false)]
    [string]$YaraPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$ScanMemory,
    
    [Parameter(Mandatory=$false)]
    [switch]$ScanProcesses
)

#Requires -RunAsAdministrator

$script:Version = "3.0"
$script:StartTime = Get-Date
$script:IOCList = @()
$script:SigmaRules = @()
$script:YaraRules = $null
$script:Findings = @{
    Authentication = @()
    ProcessActivity = @()
    PowerShellActivity = @()
    NetworkActivity = @()
    SystemChanges = @()
    PrivilegeEscalation = @()
    SysmonActivity = @()
    DefenderEvents = @()
    SuspiciousIndicators = @()
    Timeline = @()
    SecurityStatus = @{}
    IOCMatches = @()
    SigmaMatches = @()
    YaraMatches = @()
}

# Suspicious indicators
$script:SuspiciousCommands = @(
    'mimikatz','powerkatz','invoke-mimikatz','dumpcreds','procdump','pwdump',
    'net user','net localgroup','net group','add-localgroupmember',
    'invoke-webrequest','downloadfile','iwr','wget','curl',
    'invoke-expression','iex','invoke-command',
    'encodedcommand','-enc','-e ','bypass','noprofile',
    'psexec','wmic','mshta','regsvr32','rundll32','certutil',
    'bitsadmin','reg add','reg save','vssadmin','bcdedit',
    'disable-windowsdefender','set-mppreference','exclusion',
    'invoke-shellcode','empire','covenant','meterpreter','metasploit',
    'rubeus','kerberoast','asreproast','bloodhound','sharphound',
    'new-service','sc create','schtasks /create','at ','cron',
    'localaccounttokenfilterpolicy','disableuac'
)

$script:SuspiciousDomains = @(
    '.onion','.duckdns.org','.ngrok.io','pastebin.com','hastebin.com',
    'paste.ee','discord.com/api/webhooks','githubusercontent.com',
    'bit.ly','tinyurl.com','shorturl.at','rebrand.ly'
)

$script:SuspiciousProcesses = @(
    'mimikatz','procdump','pwdump','gsecdump','wce.exe',
    'psexec','paexec','remcom','winexe',
    'nmap','masscan','angry ip','netcat','nc.exe','ncat',
    'cobalt','beacon','meterpreter','empire','covenant',
    'lazagne','nirsoft','mailpv','browserpv','netpass'
)

function Write-ColorOutput {
    param([string]$Message, [string]$Level = "INFO")
    
    $color = switch ($Level) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "INFO" { "Cyan" }
        "DETAIL" { "Gray" }
        default { "White" }
    }
    
    $prefix = "[$Level]"
    Write-Host $prefix -ForegroundColor $color -NoNewline
    Write-Host " $Message"
}

function Show-Banner {
    Clear-Host
    $banner = @"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     Windows Event Log Security Analyzer v$script:Version     ║
║     Mini SIEM/DFIR Toolkit + Sigma/YARA Threat Hunting       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

# Load IOC File
function Load-IOCFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Host "[WARNING] IOC file not found: $FilePath" -ForegroundColor Yellow
        return
    }
    
    Write-Host "[INFO] Loading IOCs from: $FilePath" -ForegroundColor Cyan
    
    try {
        $iocs = Get-Content $FilePath -ErrorAction Stop | Where-Object { 
            $_.Trim() -ne "" -and -not $_.StartsWith("#") 
        }
        
        $script:IOCList = @()
        
        foreach ($ioc in $iocs) {
            $ioc = $ioc.Trim()
            
            # Determine IOC type
            $type = "Unknown"
            if ($ioc -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $type = "IP"
            }
            elseif ($ioc -match '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$') {
                $type = "Hash"
            }
            elseif ($ioc -match '^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$') {
                $type = "Domain"
            }
            elseif ($ioc -match '\.exe$|\.dll$|\.sys$|\.ps1$') {
                $type = "File"
            }
            else {
                $type = "String"
            }
            
            $script:IOCList += [PSCustomObject]@{
                Value = $ioc
                Type = $type
                Regex = [regex]::Escape($ioc)
            }
        }
        
        Write-Host "[SUCCESS] Loaded $($script:IOCList.Count) IOCs" -ForegroundColor Green
        
        # Show IOC breakdown
        $breakdown = $script:IOCList | Group-Object Type
        foreach ($group in $breakdown) {
            Write-Host "    $($group.Name): $($group.Count)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[WARNING] Error loading IOC file: $_" -ForegroundColor Yellow
    }
}

#Load Sigma Rules
function Load-SigmaRules {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Host "[WARNING] Sigma path not found: $Path" -ForegroundColor Yellow
        return
    }
    
    Write-Host "[INFO] Loading Sigma rules from: $Path" -ForegroundColor Cyan
    
    try {
        $sigmaFiles = @()
        
        if ((Get-Item $Path).PSIsContainer) {
            $sigmaFiles = Get-ChildItem -Path $Path -Filter "*.yml" -Recurse -ErrorAction SilentlyContinue
            $sigmaFiles += Get-ChildItem -Path $Path -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue
        }
        else {
            $sigmaFiles = @(Get-Item $Path)
        }
        
        # Limit to prevent overflow
        if ($sigmaFiles.Count -gt 100) {
            Write-Host "[WARNING] Found $($sigmaFiles.Count) Sigma files. Limiting to first 100 to prevent overflow." -ForegroundColor Yellow
            $sigmaFiles = $sigmaFiles | Select-Object -First 100
        }
        
        $script:SigmaRules = @()
        $loaded = 0
        
        foreach ($file in $sigmaFiles) {
            try {
                $content = Get-Content $file.FullName -Raw -ErrorAction Stop
                $rule = Parse-SigmaRule -Content $content -FilePath $file.FullName
                
                if ($rule) {
                    $script:SigmaRules += $rule
                    $loaded++
                }
            }
            catch {
                Write-Host "[WARNING] Failed to parse: $($file.Name)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "[SUCCESS] Loaded $loaded Sigma rules" -ForegroundColor Green
    }
    catch {
        Write-Host "[WARNING] Error loading Sigma rules: $_" -ForegroundColor Yellow
    }
}

# Parse Sigma Rule (simplified YAML parser for Sigma)
function Parse-SigmaRule {
    param([string]$Content, [string]$FilePath)
    
    $lines = $Content -split "`n"
    $rule = @{
        FilePath = $FilePath
        Title = ""
        Description = ""
        Level = "medium"
        Status = "experimental"
        LogSource = @{}
        Detection = @{}
        Fields = @()
        FalsePositives = @()
    }
    
    $currentSection = ""
    $detectionKey = ""
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        
        if ($line -match '^title:\s*(.+)$') {
            $rule.Title = $matches[1].Trim()
        }
        elseif ($line -match '^description:\s*(.+)$') {
            $rule.Description = $matches[1].Trim()
        }
        elseif ($line -match '^level:\s*(.+)$') {
            $rule.Level = $matches[1].Trim()
        }
        elseif ($line -match '^status:\s*(.+)$') {
            $rule.Status = $matches[1].Trim()
        }
        elseif ($line -match '^logsource:') {
            $currentSection = "logsource"
        }
        elseif ($line -match '^detection:') {
            $currentSection = "detection"
        }
        elseif ($currentSection -eq "logsource" -and $line -match '^\s+(\w+):\s*(.+)$') {
            $rule.LogSource[$matches[1]] = $matches[2].Trim()
        }
        elseif ($currentSection -eq "detection" -and $line -match '^\s+(\w+):') {
            $detectionKey = $matches[1]
            if ($detectionKey -ne "condition") {
                $rule.Detection[$detectionKey] = @()
            }
        }
        elseif ($currentSection -eq "detection" -and $line -match '^\s+condition:\s*(.+)$') {
            $rule.Detection["condition"] = $matches[1].Trim()
        }
        elseif ($currentSection -eq "detection" -and $detectionKey -and $line -match '^\s+-\s*(.+)$') {
            $rule.Detection[$detectionKey] += $matches[1].Trim()
        }
        elseif ($currentSection -eq "detection" -and $detectionKey -and $line -match '^\s+(\w+):\s*(.+)$') {
            $field = $matches[1]
            $value = $matches[2].Trim().Trim("'").Trim('"')
            $rule.Detection[$detectionKey] += "$field=$value"
        }
    }
    
    if ($rule.Title) {
        return $rule
    }
    
    return $null
}

# Match Event Against Sigma Rules
function Test-SigmaMatch {
    param($Event, $SigmaRule)
    
    # Check if log source matches
    $logSourceMatch = $true
    
    if ($SigmaRule.LogSource.product -and $Event.LogName -notmatch $SigmaRule.LogSource.product) {
        $logSourceMatch = $false
    }
    
    if ($SigmaRule.LogSource.service -and $Event.LogName -notmatch $SigmaRule.LogSource.service) {
        $logSourceMatch = $false
    }
    
    if (-not $logSourceMatch) {
        return $false
    }
    
    # Simple detection logic
    $matches = 0
    $requiredMatches = 0
    
    foreach ($key in $SigmaRule.Detection.Keys) {
        if ($key -eq "condition") { continue }
        
        $requiredMatches++
        $patterns = $SigmaRule.Detection[$key]
        
        foreach ($pattern in $patterns) {
            if ($pattern -match '=') {
                $field, $value = $pattern -split '=', 2
                
                # Try to find matching field in event
                $eventData = $Event.Message + " " + ($Event.Properties.Value -join " ")
                
                if ($eventData -match [regex]::Escape($value)) {
                    $matches++
                    break
                }
            }
            else {
                # Simple string match
                $eventData = $Event.Message + " " + ($Event.Properties.Value -join " ")
                if ($eventData -match [regex]::Escape($pattern)) {
                    $matches++
                    break
                }
            }
        }
    }
    
    # Basic condition evaluation
    if ($SigmaRule.Detection.condition) {
        $condition = $SigmaRule.Detection.condition
        
        if ($condition -match 'all of') {
            return $matches -eq $requiredMatches
        }
        elseif ($condition -match '1 of|any of') {
            return $matches -gt 0
        }
    }
    
    return $matches -gt 0
}

# Hunt IOCs in Events
function Hunt-IOCsInEvents {
    param([datetime]$StartTime, [string]$EvtxFile)
    
    if ($script:IOCList.Count -eq 0) {
        return
    }
    
    Write-Host "[INFO] Hunting for $($script:IOCList.Count) IOCs in event logs..." -ForegroundColor Cyan
    
    $logNames = @("Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational",
                  "Microsoft-Windows-PowerShell/Operational")
    
    $allEvents = @()
    $maxEventsPerLog = 2000  # Limit to prevent overflow
    
    foreach ($logName in $logNames) {
        try {
            $events = Get-WinEvent -LogName $logName -MaxEvents $maxEventsPerLog -ErrorAction SilentlyContinue |
                      Where-Object { $_.TimeCreated -gt $StartTime }
            if ($events) {
                $allEvents += $events
            }
        }
        catch {
            continue
        }
    }
    
    Write-Host "[INFO] Scanning $($allEvents.Count) events..." -ForegroundColor Gray
    
    $matchCount = 0
    foreach ($event in $allEvents) {
        $eventData = "$($event.Message) $($event.Properties.Value -join ' ')"
        
        foreach ($ioc in $script:IOCList) {
            if ($eventData -match $ioc.Regex) {
                $finding = @{
                    Type = "IOC Match"
                    IOC = $ioc.Value
                    IOCType = $ioc.Type
                    EventID = $event.Id
                    LogName = $event.LogName
                    Message = $event.Message.Substring(0, [Math]::Min(500, $event.Message.Length))
                    Timestamp = $event.TimeCreated
                    Severity = "CRITICAL"
                }
                
                $script:Findings.IOCMatches += $finding
                $script:Findings.SuspiciousIndicators += $finding
                $matchCount++
                
                Write-Host "[CRITICAL] IOC MATCH: $($ioc.Type) - $($ioc.Value) in Event $($event.Id)" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "[WARNING] Found $matchCount IOC matches" -ForegroundColor Yellow
}

# Sigma Rule Hunting
function Hunt-SigmaRules {
    param([datetime]$StartTime, [string]$EvtxFile)
    
    if ($script:SigmaRules.Count -eq 0) {
        return
    }
    
    Write-Host "[INFO] Running Sigma rule detection..." -ForegroundColor Cyan
    
    $logNames = @("Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational",
                  "Microsoft-Windows-PowerShell/Operational")
    
    $allEvents = @()
    $maxEventsPerLog = 1000  # Reduced limit
    
    foreach ($logName in $logNames) {
        try {
            $events = Get-WinEvent -LogName $logName -MaxEvents $maxEventsPerLog -ErrorAction SilentlyContinue |
                      Where-Object { $_.TimeCreated -gt $StartTime }
            if ($events) {
                $allEvents += $events
            }
        }
        catch {
            continue
        }
    }
    
    Write-Host "[INFO] Matching $($allEvents.Count) events against $($script:SigmaRules.Count) rules..." -ForegroundColor Gray
    
    $matchCount = 0
    # Limit rule checking to prevent overflow
    $rulesToCheck = $script:SigmaRules | Select-Object -First 50
    
    foreach ($rule in $rulesToCheck) {
        foreach ($event in $allEvents) {
            if (Test-SigmaMatch -Event $event -SigmaRule $rule) {
                $severity = switch ($rule.Level) {
                    "critical" { "CRITICAL" }
                    "high" { "WARNING" }
                    default { "INFO" }
                }
                
                $finding = @{
                    Type = "Sigma Rule Match"
                    RuleTitle = $rule.Title
                    RuleDescription = $rule.Description
                    RuleLevel = $rule.Level
                    EventID = $event.Id
                    LogName = $event.LogName
                    Message = $event.Message.Substring(0, [Math]::Min(500, $event.Message.Length))
                    Timestamp = $event.TimeCreated
                    Severity = $severity
                }
                
                $script:Findings.SigmaMatches += $finding
                $script:Findings.SuspiciousIndicators += $finding
                $matchCount++
                
                $color = if ($severity -eq "CRITICAL") { "Red" } else { "Yellow" }
                Write-Host "[$severity] SIGMA MATCH: $($rule.Title) - Level: $($rule.Level)" -ForegroundColor $color
            }
        }
    }
    
    Write-Host "[WARNING] Found $matchCount Sigma rule matches" -ForegroundColor Yellow
}

# YARA Process Scanning
function Scan-ProcessesWithYara {
    param([string]$YaraRulePath)
    
    Write-ColorOutput "Scanning running processes..." "INFO"
    
    if (-not (Test-Path $YaraRulePath)) {
        Write-ColorOutput "YARA rule file not found: $YaraRulePath" "WARNING"
        return
    }
    
    # Check if YARA is available
    $yaraExe = Get-Command yara64.exe -ErrorAction SilentlyContinue
    if (-not $yaraExe) {
        $yaraExe = Get-Command yara.exe -ErrorAction SilentlyContinue
    }
    
    if (-not $yaraExe) {
        Write-ColorOutput "YARA executable not found. Performing manual pattern matching..." "WARNING"
        Scan-ProcessesManual -RulePath $YaraRulePath
        return
    }
    
    $processes = Get-Process
    
    foreach ($proc in $processes) {
        try {
            # Run YARA
            $result = & $yaraExe.Source $YaraRulePath $proc.Id 2>$null
            
            if ($result) {
                $finding = @{
                    Type = "YARA Match (Process)"
                    Process = $proc.ProcessName
                    PID = $proc.Id
                    Path = $proc.Path
                    Match = $result
                    Timestamp = Get-Date
                    Severity = "CRITICAL"
                }
                
                $script:Findings.YaraMatches += $finding
                $script:Findings.SuspiciousIndicators += $finding
                
                Write-ColorOutput "  YARA MATCH: $($proc.ProcessName) (PID: $($proc.Id))" "CRITICAL"
            }
        }
        catch {
            continue
        }
    }
    
    Write-ColorOutput "  Found $($script:Findings.YaraMatches.Count) YARA matches" "WARNING"
}

# Manual YARA-like pattern matching
function Scan-ProcessesManual {
    param([string]$RulePath)
    
    Write-ColorOutput "Performing pattern-based process scanning..." "INFO"
    
    # Extract strings/patterns from YARA rules
    $patterns = @()
    $ruleContent = Get-Content $RulePath -Raw
    
    # Simple regex to extract strings from YARA rules
    if ($ruleContent -match '\$\w+\s*=\s*"([^"]+)"') {
        $patterns = [regex]::Matches($ruleContent, '\$\w+\s*=\s*"([^"]+)"') | ForEach-Object {
            $_.Groups[1].Value
        }
    }
    
    if ($patterns.Count -eq 0) {
        Write-ColorOutput "No patterns extracted from YARA rule" "WARNING"
        return
    }
    
    $processes = Get-Process
    
    foreach ($proc in $processes) {
        try {
            # Check command line
            $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
            
            foreach ($pattern in $patterns) {
                if ($cmdLine -match [regex]::Escape($pattern)) {
                    $finding = @{
                        Type = "Pattern Match (Process)"
                        Process = $proc.ProcessName
                        PID = $proc.Id
                        Path = $proc.Path
                        CommandLine = $cmdLine
                        Pattern = $pattern
                        Timestamp = Get-Date
                        Severity = "WARNING"
                    }
                    
                    $script:Findings.YaraMatches += $finding
                    $script:Findings.SuspiciousIndicators += $finding
                    
                    Write-ColorOutput "  PATTERN MATCH: $($proc.ProcessName) - Pattern: $pattern" "WARNING"
                    break
                }
            }
        }
        catch {
            continue
        }
    }
}

# Security Status Check
function Get-SecurityStatus {
    Write-ColorOutput "Checking system security status..." "INFO"
    
    $status = @{}
    
    # Windows Defender
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $status.Defender = @{
            RealTimeProtection = $defender.RealTimeProtectionEnabled
            AntivirusEnabled = $defender.AntivirusEnabled
            BehaviorMonitor = $defender.BehaviorMonitorEnabled
            IoavProtection = $defender.IoavProtectionEnabled
            LastQuickScan = $defender.QuickScanAge
            LastFullScan = $defender.FullScanAge
        }
    } catch {
        $status.Defender = "Unable to retrieve"
    }
    
    # Firewall
    try {
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $status.Firewall = @{
            DomainEnabled = ($fw | Where-Object {$_.Name -eq "Domain"}).Enabled
            PrivateEnabled = ($fw | Where-Object {$_.Name -eq "Private"}).Enabled
            PublicEnabled = ($fw | Where-Object {$_.Name -eq "Public"}).Enabled
        }
    } catch {
        $status.Firewall = "Unable to retrieve"
    }
    
    # UAC
    try {
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        $status.UAC = @{
            Enabled = $uac.EnableLUA -eq 1
            ConsentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin
        }
    } catch {
        $status.UAC = "Unable to retrieve"
    }
    
    # PowerShell Logging
    try {
        $psLogging = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        $status.PowerShellLogging = @{
            ScriptBlockLogging = $psLogging.EnableScriptBlockLogging -eq 1
            ModuleLogging = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1
            Transcription = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting -eq 1
        }
    } catch {
        $status.PowerShellLogging = "Unable to retrieve"
    }
    
    $script:Findings.SecurityStatus = $status
    return $status
}

# Query events with error handling
function Get-EventLogData {
    param(
        [string]$LogName,
        [int[]]$EventIDs,
        [datetime]$StartTime,
        [string]$EvtxFile
    )
    
    $filter = @{
        LogName = $LogName
        ID = $EventIDs
        StartTime = $StartTime
    }
    
    if ($EvtxFile) {
        $filter.Remove("LogName")
        $filter.Path = $EvtxFile
    }
    
    try {
        return Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    } catch {
        return @()
    }
}

# Authentication Analysis
function Analyze-Authentication {
    param([datetime]$StartTime, [string]$EvtxFile)
    
    Write-Host "[INFO] Analyzing authentication events..." -ForegroundColor Cyan
    
    try {
        $authEvents = @(4624,4625,4634,4647,4648,4672,4768,4769,4776)
        $events = Get-EventLogData -LogName "Security" -EventIDs $authEvents -StartTime $StartTime -EvtxFile $EvtxFile
        
        $successful = $events | Where-Object {$_.Id -eq 4624}
        $failed = $events | Where-Object {$_.Id -eq 4625}
        
        # Brute force detection
        $failedByUser = $failed | Group-Object {
            try { $_.Properties[5].Value } catch { "Unknown" }
        } | Where-Object {$_.Count -gt 5}
        
        foreach ($user in $failedByUser) {
            $finding = @{
                Type = "Brute Force Detected"
                User = $user.Name
                FailedAttempts = $user.Count
                SourceIPs = ($user.Group | ForEach-Object {
                    try { $_.Properties[19].Value } catch { "Unknown" }
                } | Select-Object -Unique)
                Severity = "CRITICAL"
                Timestamp = ($user.Group | Select-Object -First 1).TimeCreated
            }
            $script:Findings.Authentication += $finding
            $script:Findings.SuspiciousIndicators += $finding
        }
        
        Write-Host "[INFO] Found $($successful.Count) successful and $($failed.Count) failed logons" -ForegroundColor Gray
    }
    catch {
        Write-Host "[WARNING] Error analyzing authentication: $_" -ForegroundColor Yellow
    }
}

# Process Activity Analysis
function Analyze-ProcessActivity {
    param([datetime]$StartTime, [string]$EvtxFile)
    
    Write-Host "[INFO] Analyzing process execution..." -ForegroundColor Cyan
    
    try {
        $events = Get-EventLogData -LogName "Security" -EventIDs @(4688) -StartTime $StartTime -EvtxFile $EvtxFile
        
        # Limit to prevent overflow
        $eventsToAnalyze = $events | Select-Object -First 1000
        
        foreach ($event in $eventsToAnalyze) {
            try {
                $cmdLine = $event.Properties[8].Value
                $process = $event.Properties[5].Value
                $parent = $event.Properties[13].Value
                
                $isSuspicious = $false
                $reasons = @()
                
                foreach ($susCmd in $script:SuspiciousCommands) {
                    if ($cmdLine -match [regex]::Escape($susCmd)) {
                        $isSuspicious = $true
                        $reasons += "Suspicious command: $susCmd"
                        break  # Stop after first match
                    }
                }
                
                if ($cmdLine -match "encodedcommand|frombase64string|-enc |-e ") {
                    $isSuspicious = $true
                    $reasons += "Encoded/Base64 command detected"
                }
                
                $finding = @{
                    Type = "Process Execution"
                    Process = $process
                    CommandLine = $cmdLine
                    ParentProcess = $parent
                    User = $event.Properties[1].Value
                    Timestamp = $event.TimeCreated
                    Suspicious = $isSuspicious
                    Reasons = $reasons -join "; "
                    Severity = if ($isSuspicious) {"WARNING"} else {"INFO"}
                }
                
                $script:Findings.ProcessActivity += $finding
                
                if ($isSuspicious) {
                    $script:Findings.SuspiciousIndicators += $finding
                }
            }
            catch {
                continue
            }
        }
        
        Write-Host "[INFO] Analyzed $($eventsToAnalyze.Count) process executions" -ForegroundColor Gray
    }
    catch {
        Write-Host "[WARNING] Error analyzing process activity: $_" -ForegroundColor Yellow
    }
}

# PowerShell Activity Analysis
function Analyze-PowerShellActivity {
    param([datetime]$StartTime, [string]$EvtxFile)
    
    Write-ColorOutput "Analyzing PowerShell activity..." "INFO"
    
    $events = Get-EventLogData -LogName "Microsoft-Windows-PowerShell/Operational" -EventIDs @(4104) -StartTime $StartTime -EvtxFile $EvtxFile
    
    foreach ($event in $events) {
        $scriptBlock = $event.Properties[2].Value
        
        $isSuspicious = $false
        $reasons = @()
        
        foreach ($susCmd in $script:SuspiciousCommands) {
            if ($scriptBlock -match [regex]::Escape($susCmd)) {
                $isSuspicious = $true
                $reasons += "Suspicious: $susCmd"
            }
        }
        
        if ($isSuspicious) {
            $finding = @{
                Type = "PowerShell Script Execution"
                ScriptBlock = $scriptBlock.Substring(0, [Math]::Min(500, $scriptBlock.Length))
                User = $event.UserId
                Timestamp = $event.TimeCreated
                Reasons = $reasons -join "; "
                Severity = "WARNING"
            }
            
            $script:Findings.PowerShellActivity += $finding
            $script:Findings.SuspiciousIndicators += $finding
        }
    }
    
    Write-ColorOutput "  Analyzed $($events.Count) PowerShell script blocks" "DETAIL"
}

# Network/DNS Activity Analysis
function Analyze-NetworkActivity {
    param([datetime]$StartTime, [string]$EvtxFile)
    
    Write-ColorOutput "Analyzing network/DNS activity..." "INFO"
    
    $dnsEvents = Get-EventLogData -LogName "Microsoft-Windows-DNS-Client/Operational" -EventIDs @(3008) -StartTime $StartTime -EvtxFile $EvtxFile
    
    foreach ($event in $dnsEvents) {
        $domain = $event.Properties[0].Value
        
        $isSuspicious = $false
        foreach ($susDomain in $script:SuspiciousDomains) {
            if ($domain -match [regex]::Escape($susDomain)) {
                $isSuspicious = $true
                
                $finding = @{
                    Type = "Suspicious DNS Query"
                    Domain = $domain
                    Timestamp = $event.TimeCreated
                    Severity = "WARNING"
                }
                
                $script:Findings.NetworkActivity += $finding
                $script:Findings.SuspiciousIndicators += $finding
                break
            }
        }
    }
    
    $sysmonEvents = Get-EventLogData -LogName "Microsoft-Windows-Sysmon/Operational" -EventIDs @(3) -StartTime $StartTime -EvtxFile $EvtxFile
    
    foreach ($event in $sysmonEvents) {
        $destIP = $event.Properties[14].Value
        $destPort = $event.Properties[15].Value
        
        if ($destIP -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.)") {
            $script:Findings.NetworkActivity += @{
                Type = "External Connection"
                Process = $event.Properties[4].Value
                DestIP = $destIP
                DestPort = $destPort
                User = $event.Properties[1].Value
                Timestamp = $event.TimeCreated
                Severity = "INFO"
            }
        }
    }
    
    Write-ColorOutput "  Analyzed DNS and network connections" "DETAIL"
}

# System Changes Analysis
function Analyze-SystemChanges {
    param([datetime]$StartTime, [string]$EvtxFile)
    
    Write-ColorOutput "Analyzing system changes..." "INFO"
    
    $userEvents = Get-EventLogData -LogName "Security" -EventIDs @(4720,4722,4724,4726,4728,4732,4756) -StartTime $StartTime -EvtxFile $EvtxFile
    
    foreach ($event in $userEvents) {
        $script:Findings.SystemChanges += @{
            Type = "User/Group Modification"
            EventID = $event.Id
            Details = $event.Message.Split("`n")[0]
            User = $event.Properties[0].Value
            Timestamp = $event.TimeCreated
            Severity = "WARNING"
        }
    }
    
    $serviceEvents = Get-EventLogData -LogName "Security" -EventIDs @(4697) -StartTime $StartTime -EvtxFile $EvtxFile
    
    foreach ($event in $serviceEvents) {
        $serviceName = $event.Properties[0].Value
        $servicePath = $event.Properties[1].Value
        
        $finding = @{
            Type = "Service Installation"
            ServiceName = $serviceName
            ServicePath = $servicePath
            Timestamp = $event.TimeCreated
            Severity = "WARNING"
        }
        
        $script:Findings.SystemChanges += $finding
        $script:Findings.SuspiciousIndicators += $finding
    }
    
    Write-ColorOutput "  Found $($script:Findings.SystemChanges.Count) system changes" "DETAIL"
}

# Windows Defender Analysis
function Analyze-DefenderEvents {
    param([datetime]$StartTime, [string]$EvtxFile)
    
    Write-ColorOutput "Analyzing Windows Defender events..." "INFO"
    
    $defenderEvents = Get-EventLogData -LogName "Microsoft-Windows-Windows Defender/Operational" -EventIDs @(1006,1007,1008,1116,1117,5001,5007,5010,5012) -StartTime $StartTime -EvtxFile $EvtxFile
    
    foreach ($event in $defenderEvents) {
        $severity = switch ($event.Id) {
            {$_ -in @(1116,1117)} {"CRITICAL"}
            {$_ -in @(5001,5007)} {"WARNING"}
            default {"INFO"}
        }
        
        $script:Findings.DefenderEvents += @{
            Type = "Windows Defender Event"
            EventID = $event.Id
            Message = $event.Message.Split("`n")[0..2] -join " "
            Timestamp = $event.TimeCreated
            Severity = $severity
        }
    }
    
    Write-ColorOutput "  Found $($defenderEvents.Count) Defender events" "DETAIL"
}

# Main Analysis Function
function Start-Analysis {
    $startTime = (Get-Date).AddHours(-$Hours)
    
    Get-SecurityStatus
    
    if ($IOCFile) {
        Load-IOCFile -FilePath $IOCFile
    }
    elseif ($IOC) {
        $script:IOCList = @([PSCustomObject]@{
            Value = $IOC
            Type = "String"
            Regex = [regex]::Escape($IOC)
        })
    }
    
    if ($SigmaPath) {
        Load-SigmaRules -Path $SigmaPath
    }
    
    if ($YaraPath) {
        if ($ScanProcesses) {
            Scan-ProcessesWithYara -YaraRulePath $YaraPath
        }
    }
    
    Analyze-Authentication -StartTime $startTime -EvtxFile $EvtxPath
    Analyze-ProcessActivity -StartTime $startTime -EvtxFile $EvtxPath
    Analyze-PowerShellActivity -StartTime $startTime -EvtxFile $EvtxPath
    Analyze-NetworkActivity -StartTime $startTime -EvtxFile $EvtxPath
    Analyze-SystemChanges -StartTime $startTime -EvtxFile $EvtxPath
    Analyze-DefenderEvents -StartTime $startTime -EvtxFile $EvtxPath
    
    if ($script:IOCList.Count -gt 0) {
        Hunt-IOCsInEvents -StartTime $startTime -EvtxFile $EvtxPath
    }
    
    if ($script:SigmaRules.Count -gt 0) {
        Hunt-SigmaRules -StartTime $startTime -EvtxFile $EvtxPath
    }
}

# Interactive Mode
function Start-InteractiveMode {
    while ($true) {
        Write-Host "`n" -NoNewline
        Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║       INTERACTIVE INVESTIGATION       ║" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [1]  Hunt for IOC" -ForegroundColor Yellow
        Write-Host "  [2]  Load IOC File" -ForegroundColor Yellow
        Write-Host "  [3]  Load Sigma Rules" -ForegroundColor Yellow
        Write-Host "  [4]  Run Sigma Detection" -ForegroundColor Yellow
        Write-Host "  [5]  Scan Processes (YARA/Pattern)" -ForegroundColor Yellow
        Write-Host "  [6]  View IOC Matches" -ForegroundColor Green
        Write-Host "  [7]  View Sigma Matches" -ForegroundColor Green
        Write-Host "  [8]  View YARA Matches" -ForegroundColor Green
        Write-Host "  [9]  View All Suspicious Indicators" -ForegroundColor Red
        Write-Host "  [10] Timeline Reconstruction" -ForegroundColor Yellow
        Write-Host "  [11] Process Investigation" -ForegroundColor Yellow
        Write-Host "  [12] User Activity Drilldown" -ForegroundColor Yellow
        Write-Host "  [13] Kill Process" -ForegroundColor Red
        Write-Host "  [14] Block IP/Domain (Firewall)" -ForegroundColor Red
        Write-Host "  [15] Export Findings" -ForegroundColor Green
        Write-Host "  [16] Refresh Analysis" -ForegroundColor Green
        Write-Host "  [0]  Exit" -ForegroundColor Gray
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Hunt-IOC }
            "2" { 
                $file = Read-Host "Enter IOC file path"
                Load-IOCFile -FilePath $file
            }
            "3" { 
                $path = Read-Host "Enter Sigma rule path (file or directory)"
                Load-SigmaRules -Path $path
            }
            "4" { 
                if ($script:SigmaRules.Count -eq 0) {
                    Write-ColorOutput "No Sigma rules loaded. Load rules first (option 3)" "WARNING"
                }
                else {
                    Hunt-SigmaRules -StartTime (Get-Date).AddHours(-$Hours)
                }
                Read-Host "`nPress Enter to continue"
            }
            "5" { 
                $yaraPath = Read-Host "Enter YARA rule file path (or press Enter to skip)"
                if ($yaraPath) {
                    Scan-ProcessesWithYara -YaraRulePath $yaraPath
                }
                else {
                    Write-ColorOutput "Scanning processes for suspicious patterns..." "INFO"
                    $processes = Get-Process
                    $processes | Select-Object ProcessName, Id, Path | Format-Table -AutoSize | Out-String | Write-Host
                }
                Read-Host "`nPress Enter to continue"
            }
            "6" { Show-IOCMatches }
            "7" { Show-SigmaMatches }
            "8" { Show-YaraMatches }
            "9" { Show-SuspiciousIndicators }
            "10" { Show-Timeline }
            "11" { Investigate-ProcessTree }
            "12" { Investigate-UserActivity }
            "13" { Kill-TargetProcess }
            "14" { Block-NetworkTarget }
            "15" { Export-Findings }
            "16" { 
                Write-ColorOutput "Refreshing analysis..." "INFO"
                Start-Analysis
            }
            "0" { return }
            default { Write-ColorOutput "Invalid choice" "WARNING" }
        }
    }
}

# Show IOC Matches
function Show-IOCMatches {
    if ($script:Findings.IOCMatches.Count -gt 0) {
        Write-ColorOutput "Found $($script:Findings.IOCMatches.Count) IOC matches:" "CRITICAL"
        $script:Findings.IOCMatches | Format-List | Out-String | Write-Host
    }
    else {
        Write-ColorOutput "No IOC matches found" "SUCCESS"
    }
    Read-Host "`nPress Enter to continue"
}

# Show Sigma Matches
function Show-SigmaMatches {
    if ($script:Findings.SigmaMatches.Count -gt 0) {
        Write-ColorOutput "Found $($script:Findings.SigmaMatches.Count) Sigma rule matches:" "CRITICAL"
        $script:Findings.SigmaMatches | Format-List | Out-String | Write-Host
    }
    else {
        Write-ColorOutput "No Sigma matches found" "SUCCESS"
    }
    Read-Host "`nPress Enter to continue"
}

# Show YARA Matches
function Show-YaraMatches {
    if ($script:Findings.YaraMatches.Count -gt 0) {
        Write-ColorOutput "Found $($script:Findings.YaraMatches.Count) YARA/Pattern matches:" "CRITICAL"
        $script:Findings.YaraMatches | Format-List | Out-String | Write-Host
    }
    else {
        Write-ColorOutput "No YARA/Pattern matches found" "SUCCESS"
    }
    Read-Host "`nPress Enter to continue"
}

# IOC Hunting
function Hunt-IOC {
    $ioc = Read-Host "Enter IOC to hunt"
    
    Write-ColorOutput "Hunting for: $ioc" "INFO"
    
    $results = @()
    
    foreach ($category in $script:Findings.Keys) {
        if ($category -eq "SecurityStatus") { continue }
        
        foreach ($finding in $script:Findings[$category]) {
            $match = $false
            foreach ($prop in $finding.Keys) {
                if ($finding[$prop] -match [regex]::Escape($ioc)) {
                    $match = $true
                    break
                }
            }
            
            if ($match) {
                $results += $finding
            }
        }
    }
    
    if ($results.Count -gt 0) {
        Write-ColorOutput "Found $($results.Count) matches:" "SUCCESS"
        $results | Format-Table -AutoSize -Wrap | Out-String | Write-Host
    }
    else {
        Write-ColorOutput "No matches found for: $ioc" "WARNING"
    }
    
    Read-Host "`nPress Enter to continue"
}

# Timeline
function Show-Timeline {
    Write-ColorOutput "Generating timeline..." "INFO"
    
    $timeline = @()
    foreach ($category in $script:Findings.Keys) {
        if ($category -eq "SecurityStatus") { continue }
        foreach ($finding in $script:Findings[$category]) {
            if ($finding.Timestamp) {
                $timeline += $finding
            }
        }
    }
    
    $timeline | Sort-Object Timestamp -Descending | Select-Object -First 50 Timestamp, Type, Severity | Format-Table -AutoSize -Wrap | Out-String | Write-Host
    
    Read-Host "`nPress Enter to continue"
}

# Process Tree Investigation
function Investigate-ProcessTree {
    $processName = Read-Host "Enter process name to investigate"
    
    $processes = $script:Findings.ProcessActivity | Where-Object {
        $_.Process -match [regex]::Escape($processName) -or
        $_.ParentProcess -match [regex]::Escape($processName)
    }
    
    if ($processes.Count -gt 0) {
        Write-ColorOutput "Found $($processes.Count) related processes:" "SUCCESS"
        $processes | Format-List | Out-String | Write-Host
    }
    else {
        Write-ColorOutput "No processes found matching: $processName" "WARNING"
    }
    
    Read-Host "`nPress Enter to continue"
}

# User Activity Investigation
function Investigate-UserActivity {
    $username = Read-Host "Enter username to investigate"
    
    $activities = @()
    foreach ($category in $script:Findings.Keys) {
        if ($category -eq "SecurityStatus") { continue }
        foreach ($finding in $script:Findings[$category]) {
            if ($finding.User -match [regex]::Escape($username)) {
                $activities += $finding
            }
        }
    }
    
    if ($activities.Count -gt 0) {
        Write-ColorOutput "Found $($activities.Count) activities for user: $username" "SUCCESS"
        $activities | Sort-Object Timestamp -Descending | Format-Table -AutoSize -Wrap | Out-String | Write-Host
    }
    else {
        Write-ColorOutput "No activities found for user: $username" "WARNING"
    }
    
    Read-Host "`nPress Enter to continue"
}

# Suspicious Indicators
function Show-SuspiciousIndicators {
    if ($script:Findings.SuspiciousIndicators.Count -gt 0) {
        Write-ColorOutput "Found $($script:Findings.SuspiciousIndicators.Count) suspicious indicators:" "WARNING"
        $script:Findings.SuspiciousIndicators | Format-List | Out-String | Write-Host
    }
    else {
        Write-ColorOutput "No suspicious indicators detected" "SUCCESS"
    }
    
    Read-Host "`nPress Enter to continue"
}

# Kill Process
function Kill-TargetProcess {
    $processName = Read-Host "Enter process name or PID to terminate"
    
    Write-Host "WARNING: This will terminate the process!" -ForegroundColor Red
    $confirm = Read-Host "Type CONFIRM to proceed"
    
    if ($confirm -eq "CONFIRM") {
        try {
            if ($processName -match '^\d+$') {
                # PID provided
                Stop-Process -Id $processName -Force
                Write-ColorOutput "Process (PID: $processName) terminated" "SUCCESS"
            }
            else {
                # Process name provided
                Get-Process -Name $processName | Stop-Process -Force
                Write-ColorOutput "Process '$processName' terminated" "SUCCESS"
            }
        }
        catch {
            Write-ColorOutput "Failed to terminate process: $_" "WARNING"
        }
    }
    else {
        Write-ColorOutput "Operation cancelled" "INFO"
    }
    
    Read-Host "`nPress Enter to continue"
}

# Block Network Target
function Block-NetworkTarget {
    $target = Read-Host "Enter IP address or domain to block"
    
    Write-Host "WARNING: This will add a firewall rule to block the target!" -ForegroundColor Red
    $confirm = Read-Host "Type CONFIRM to proceed"
    
    if ($confirm -eq "CONFIRM") {
        try {
            $ruleName = "WinForensicX_Block_$($target -replace '[^\w]', '_')"
            
            if ($target -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                # IP address
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $target -ErrorAction Stop
                Write-ColorOutput "Firewall rule created to block IP: $target" "SUCCESS"
            }
            else {
                # Domain - block via hosts file
                $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
                Add-Content -Path $hostsPath -Value "`n127.0.0.1 $target"
                Write-ColorOutput "Added $target to hosts file (redirected to 127.0.0.1)" "SUCCESS"
            }
        }
        catch {
            Write-ColorOutput "Failed to block target: $_" "WARNING"
        }
    }
    else {
        Write-ColorOutput "Operation cancelled" "INFO"
    }
    
    Read-Host "`nPress Enter to continue"
}

# Export Findings
function Export-Findings {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    if ($ExportJSON) {
        $jsonPath = "WinForensicX_Report_$timestamp.json"
        $script:Findings | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-ColorOutput "JSON report exported to: $jsonPath" "SUCCESS"
    }
    
    if ($ExportHTML) {
        $htmlPath = "WinForensicX_Report_$timestamp.html"
        Generate-HTMLReport -OutputPath $htmlPath
        Write-ColorOutput "HTML report exported to: $htmlPath" "SUCCESS"
    }
    
    Read-Host "`nPress Enter to continue"
}

# Generate HTML Report
function Generate-HTMLReport {
    param([string]$OutputPath)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>WinForensicX Security Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
        h1 { color: #00d4ff; border-bottom: 3px solid #00d4ff; padding-bottom: 10px; }
        h2 { color: #00ff88; margin-top: 30px; border-left: 4px solid #00ff88; padding-left: 10px; }
        h3 { color: #ffd700; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #2a2a2a; padding: 15px; border-radius: 8px; border-left: 4px solid #00d4ff; }
        .critical { color: #ff4444; font-weight: bold; }
        .warning { color: #ffaa00; font-weight: bold; }
        .success { color: #00ff88; font-weight: bold; }
        .info { color: #00d4ff; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; background: #2a2a2a; }
        th { background: #3a3a3a; color: #00d4ff; padding: 12px; text-align: left; border-bottom: 2px solid #00d4ff; }
        td { padding: 10px; border-bottom: 1px solid #404040; }
        tr:hover { background: #333; }
        .finding { background: #2a2a2a; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #ff4444; }
        .timestamp { color: #888; font-size: 0.9em; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.85em; margin-right: 5px; }
        .badge-critical { background: #ff4444; color: white; }
        .badge-warning { background: #ffaa00; color: black; }
        .badge-info { background: #00d4ff; color: black; }
        .badge-success { background: #00ff88; color: black; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 WinForensicX Security Analysis Report</h1>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p><strong>Analysis Period:</strong> Last $Hours hours</p>
        <p><strong>System:</strong> $env:COMPUTERNAME</p>
    </div>
"@

    # Executive Summary
    $totalFindings = ($script:Findings.SuspiciousIndicators.Count + 
                      $script:Findings.IOCMatches.Count + 
                      $script:Findings.SigmaMatches.Count +
                      $script:Findings.YaraMatches.Count)
    
    $criticalCount = ($script:Findings.SuspiciousIndicators | Where-Object {$_.Severity -eq "CRITICAL"}).Count
    $warningCount = ($script:Findings.SuspiciousIndicators | Where-Object {$_.Severity -eq "WARNING"}).Count
    
    $html += @"
    <h2>📊 Executive Summary</h2>
    <div class="summary">
        <div class="summary-card">
            <h3>Total Findings</h3>
            <div style="font-size: 2em; color: #00d4ff;">$totalFindings</div>
        </div>
        <div class="summary-card">
            <h3>Critical Issues</h3>
            <div style="font-size: 2em;" class="critical">$criticalCount</div>
        </div>
        <div class="summary-card">
            <h3>Warnings</h3>
            <div style="font-size: 2em;" class="warning">$warningCount</div>
        </div>
        <div class="summary-card">
            <h3>IOC Matches</h3>
            <div style="font-size: 2em; color: #ff4444;">$($script:Findings.IOCMatches.Count)</div>
        </div>
        <div class="summary-card">
            <h3>Sigma Matches</h3>
            <div style="font-size: 2em; color: #ff4444;">$($script:Findings.SigmaMatches.Count)</div>
        </div>
        <div class="summary-card">
            <h3>YARA Matches</h3>
            <div style="font-size: 2em; color: #ff4444;">$($script:Findings.YaraMatches.Count)</div>
        </div>
    </div>
"@

    # IOC Matches
    if ($script:Findings.IOCMatches.Count -gt 0) {
        $html += "<h2>🎯 IOC Matches (CRITICAL)</h2>"
        foreach ($match in $script:Findings.IOCMatches) {
            $html += @"
            <div class="finding">
                <span class="badge badge-critical">CRITICAL</span>
                <strong>IOC Type:</strong> $($match.IOCType) | <strong>Value:</strong> $($match.IOC)<br>
                <strong>Event ID:</strong> $($match.EventID) | <strong>Log:</strong> $($match.LogName)<br>
                <strong>Timestamp:</strong> <span class="timestamp">$($match.Timestamp)</span><br>
                <strong>Message:</strong> $($match.Message -replace '<', '&lt;' -replace '>', '&gt;')
            </div>
"@
        }
    }

    # Sigma Matches
    if ($script:Findings.SigmaMatches.Count -gt 0) {
        $html += "<h2>⚡ Sigma Rule Matches</h2>"
        foreach ($match in $script:Findings.SigmaMatches) {
            $badgeClass = switch ($match.RuleLevel) {
                "critical" { "badge-critical" }
                "high" { "badge-warning" }
                default { "badge-info" }
            }
            $html += @"
            <div class="finding">
                <span class="badge $badgeClass">$($match.RuleLevel.ToUpper())</span>
                <strong>Rule:</strong> $($match.RuleTitle)<br>
                <strong>Description:</strong> $($match.RuleDescription)<br>
                <strong>Event ID:</strong> $($match.EventID) | <strong>Log:</strong> $($match.LogName)<br>
                <strong>Timestamp:</strong> <span class="timestamp">$($match.Timestamp)</span><br>
                <strong>Message:</strong> $($match.Message -replace '<', '&lt;' -replace '>', '&gt;')
            </div>
"@
        }
    }

    # YARA Matches
    if ($script:Findings.YaraMatches.Count -gt 0) {
        $html += "<h2>🔬 YARA/Pattern Matches</h2>"
        foreach ($match in $script:Findings.YaraMatches) {
            $html += @"
            <div class="finding">
                <span class="badge badge-critical">DETECTION</span>
                <strong>Type:</strong> $($match.Type)<br>
                <strong>Process:</strong> $($match.Process) (PID: $($match.PID))<br>
                <strong>Path:</strong> $($match.Path)<br>
                <strong>Match:</strong> $($match.Match -or $match.Pattern)<br>
                <strong>Timestamp:</strong> <span class="timestamp">$($match.Timestamp)</span>
            </div>
"@
        }
    }

    # Authentication Events
    if ($script:Findings.Authentication.Count -gt 0) {
        $html += "<h2>🔐 Authentication Events</h2><table><tr><th>Type</th><th>User</th><th>Details</th><th>Severity</th><th>Timestamp</th></tr>"
        foreach ($auth in $script:Findings.Authentication) {
            $severityClass = $auth.Severity.ToLower()
            $html += "<tr><td>$($auth.Type)</td><td>$($auth.User)</td><td>Failed: $($auth.FailedAttempts)</td><td><span class='$severityClass'>$($auth.Severity)</span></td><td class='timestamp'>$($auth.Timestamp)</td></tr>"
        }
        $html += "</table>"
    }

    # Suspicious Indicators
    if ($script:Findings.SuspiciousIndicators.Count -gt 0) {
        $html += "<h2>⚠️ Suspicious Indicators</h2>"
        foreach ($indicator in $script:Findings.SuspiciousIndicators | Select-Object -First 20) {
            $badgeClass = switch ($indicator.Severity) {
                "CRITICAL" { "badge-critical" }
                "WARNING" { "badge-warning" }
                default { "badge-info" }
            }
            $html += @"
            <div class="finding">
                <span class="badge $badgeClass">$($indicator.Severity)</span>
                <strong>Type:</strong> $($indicator.Type)<br>
"@
            foreach ($key in $indicator.Keys) {
                if ($key -notin @("Type", "Severity", "Timestamp")) {
                    $value = $indicator[$key]
                    if ($value) {
                        $html += "<strong>$($key):</strong> $($value -replace '<', '&lt;' -replace '>', '&gt;')<br>"
                    }
                }
            }
            $html += "<strong>Timestamp:</strong> <span class='timestamp'>$($indicator.Timestamp)</span></div>"
        }
    }

    # Security Status
    $html += "<h2>🛡️ Security Status</h2><table>"
    $html += "<tr><th>Component</th><th>Status</th></tr>"
    
    if ($script:Findings.SecurityStatus.Defender) {
        $defStatus = $script:Findings.SecurityStatus.Defender
        if ($defStatus -is [hashtable]) {
            $rtpStatus = if ($defStatus.RealTimeProtection) { "✅ Enabled" } else { "❌ Disabled" }
            $html += "<tr><td>Windows Defender Real-Time Protection</td><td>$rtpStatus</td></tr>"
        }
    }
    
    if ($script:Findings.SecurityStatus.Firewall) {
        $fwStatus = $script:Findings.SecurityStatus.Firewall
        if ($fwStatus -is [hashtable]) {
            $html += "<tr><td>Firewall (Public)</td><td>$(if ($fwStatus.PublicEnabled) { '✅ Enabled' } else { '❌ Disabled' })</td></tr>"
        }
    }
    
    if ($script:Findings.SecurityStatus.UAC) {
        $uacStatus = $script:Findings.SecurityStatus.UAC
        if ($uacStatus -is [hashtable]) {
            $html += "<tr><td>UAC</td><td>$(if ($uacStatus.Enabled) { '✅ Enabled' } else { '❌ Disabled' })</td></tr>"
        }
    }
    
    $html += "</table>"

    # Footer
    $html += @"
    <div style="margin-top: 50px; padding-top: 20px; border-top: 2px solid #404040; color: #888; text-align: center;">
        <p>Report generated by WinForensicX v$script:Version</p>
        <p>Duration: $((Get-Date) - $script:StartTime | Select-Object -ExpandProperty TotalSeconds) seconds</p>
    </div>
</body>
</html>
"@

    $html | Out-File $OutputPath -Encoding UTF8
}

# Main Execution
Show-Banner

switch ($Mode) {
    "QuickScan" {
        Write-ColorOutput "Running Quick Scan..." "INFO"
        Start-Analysis
        Export-Findings
        Write-ColorOutput "`nQuick Scan completed!" "SUCCESS"
    }
    "DeepAnalysis" {
        Write-ColorOutput "Running Deep Analysis..." "INFO"
        Start-Analysis
        Export-Findings
        Write-ColorOutput "`nDeep Analysis completed!" "SUCCESS"
    }
    "ThreatHunt" {
        Write-ColorOutput "Starting Threat Hunt Mode..." "INFO"
        Start-Analysis
        Export-Findings
        Write-ColorOutput "`nThreat Hunt completed!" "SUCCESS"
    }
    "SigmaHunt" {
        if (-not $SigmaPath) {
            Write-ColorOutput "SigmaHunt mode requires -SigmaPath parameter" "CRITICAL"
            exit 1
        }
        Write-ColorOutput "Running Sigma-based Threat Hunt..." "INFO"
        Load-SigmaRules -Path $SigmaPath
        Start-Analysis
        Export-Findings
        Write-ColorOutput "`nSigma Hunt completed!" "SUCCESS"
    }
    "LiveMonitor" {
        Write-ColorOutput "Live monitoring not implemented in this version" "WARNING"
    }
    "Interactive" {
        Start-Analysis
        Start-InteractiveMode
    }
}

$duration = (Get-Date) - $script:StartTime
Write-ColorOutput "`nTotal execution time: $([math]::Round($duration.TotalSeconds, 2)) seconds" "INFO"
