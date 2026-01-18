# WinForensicX

<div align="center">

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

**Advanced Windows Event Log Analyzer & Threat Hunting Toolkit**

A comprehensive DFIR/SIEM tool for Security Operations Centers, Incident Responders, and Threat Hunters

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Safety](#-safety--requirements)

</div>

---

## 🎯 Overview

**WinForensicX** (formerly Windows Event Log Security Analyzer) is a powerful PowerShell-based mini-SIEM and digital forensics toolkit designed for:

- 🔍 **SOC Analysts** - Quick triage and security monitoring
- 🛡️ **Incident Responders** - Rapid host assessment and investigation
- 🎯 **Threat Hunters** - IOC hunting with Sigma/YARA integration
- 🧪 **Malware Analysts** - Live malware behavior analysis
- 🏆 **CTF/Competitions** - Fast forensic analysis and flag hunting

### Why WinForensicX?

- ✅ **No SIEM Required** - Standalone analysis without Splunk/ELK/Sentinel
- ✅ **Sigma & YARA Integration** - Industry-standard detection rules
- ✅ **IOC Hunting** - Single or bulk IOC searching
- ✅ **Interactive Mode** - Real-time investigation and response
- ✅ **HTML Reports** - Professional, shareable analysis reports
- ✅ **Offline Analysis** - Works with .evtx files from any system
- ✅ **Live Monitoring** - Watch malware behavior in real-time
- ✅ **Response Actions** - Kill processes, block IPs, disable services

---

## 🚀 Features

### Core Analysis Capabilities

| Category | Detection Capabilities |
|----------|----------------------|
| **Authentication** | Brute force detection, failed logons, source IP tracking, privilege escalation |
| **Process Activity** | Command-line analysis, parent-child relationships, suspicious process detection |
| **PowerShell** | Script block logging, encoded commands, malicious cmdlets (Invoke-Mimikatz, etc.) |
| **Network/DNS** | Suspicious domains (C2, DGA), external connections, DNS tunneling indicators |
| **System Changes** | User/group modifications, service installations, scheduled tasks |
| **Windows Defender** | Malware detections, tamper attempts, exclusion modifications |
| **Sysmon Integration** | Network connections, file creations, process creation (Event ID 1, 3, 11) |
| **Threat Hunting** | IOC matching, Sigma rule detection, YARA process scanning |

### Advanced Features

#### 🎯 IOC Hunting
- Single IOC search or bulk IOC file import
- Auto-detection of IOC types (IP, domain, hash, file, string)
- Cross-log correlation
- Real-time matching with severity scoring

#### 📋 Sigma Rule Integration
- Load single rules or entire rule directories
- Supports `.yml` and `.yaml` formats
- MITRE ATT&CK technique detection
- Custom rule creation support

#### 🔍 YARA Process Scanning
- Scan running processes for malware signatures
- Memory pattern matching
- Command-line argument inspection
- Fallback to manual pattern matching if YARA not available

#### 🕵️ Interactive Investigation
- Timeline reconstruction
- User activity drilldown
- Process tree investigation
- Real-time IOC/Sigma/YARA hunting
- Live response actions

#### 📊 Reporting
- HTML reports with color-coded findings
- JSON export for SIEM integration
- Executive summary dashboards
- Detailed finding breakdown

---

## 📋 Requirements

### Minimum Requirements

| Requirement | Details |
|------------|---------|
| **OS** | Windows 10/11, Windows Server 2016+ |
| **PowerShell** | Version 5.1 or higher (7.x recommended) |
| **Privileges** | Administrator/Elevated privileges required |
| **RAM** | 4GB minimum (8GB+ recommended for large log analysis) |
| **Disk Space** | 500MB for script + logs |

### Optional Dependencies

| Component | Purpose | Required? |
|-----------|---------|-----------|
| **Sysmon** | Enhanced process/network monitoring | Optional but recommended |
| **YARA** | Process memory scanning | Optional (has fallback) |
| **Sigma Rules** | Detection rule library | Optional (user-provided) |

### PowerShell Modules (Built-in)
- `Microsoft.PowerShell.Management`
- `Microsoft.PowerShell.Security`
- `Microsoft.PowerShell.Utility`
- `NetSecurity` (for firewall actions)

**No external PowerShell modules required!** Everything uses native Windows capabilities.

---

## 💾 Installation

### Option 1: Quick Start (Recommended)

```powershell
# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourusername/WinForensicX/main/WinForensicX.ps1" -OutFile "WinForensicX.ps1"

# Run with admin privileges
powershell.exe -ExecutionPolicy Bypass -File .\WinForensicX.ps1 -Mode Interactive
```

### Option 2: Git Clone

```bash
git clone https://github.com/yourusername/WinForensicX.git
cd WinForensicX
```

```powershell
# Run as Administrator
.\WinForensicX.ps1 -Mode Interactive
```

### Option 3: Manual Download
1. Download `WinForensicX.ps1` from the [Releases](https://github.com/yourusername/WinForensicX/releases) page
2. Right-click → "Run with PowerShell" (as Administrator)

### Setting Up Optional Components

#### Install Sysmon (Highly Recommended)
```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip

# Install with SwiftOnSecurity config (popular baseline)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

#### Install YARA (Optional)
```powershell
# Download YARA for Windows
Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.3.2/yara-4.3.2-2150-win64.zip" -OutFile "yara.zip"
Expand-Archive yara.zip -DestinationPath "C:\Tools\YARA"

# Add to PATH or place yara64.exe in script directory
```

#### Get Sigma Rules
```powershell
# Clone Sigma rule repository
git clone https://github.com/SigmaHQ/sigma.git C:\Sigma-Rules

# Or download specific rules
Invoke-WebRequest -Uri "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" -OutFile "sigma-rules.zip"
```

---

## 🎮 Usage

### Basic Syntax

```powershell
.\WinForensicX.ps1 [Parameters]
```

### Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-Mode` | String | Operation mode | `Interactive` |
| `-Hours` | Integer | Hours to look back | `24` |
| `-EvtxPath` | String | Path to offline .evtx files | Current system |
| `-IOC` | String | Single IOC to hunt | None |
| `-IOCFile` | String | Path to IOC list file | None |
| `-SigmaPath` | String | Path to Sigma rule(s) | None |
| `-YaraPath` | String | Path to YARA rule file | None |
| `-ScanProcesses` | Switch | Enable process scanning | `$false` |
| `-ExportJSON` | Switch | Export to JSON | `$false` |
| `-ExportHTML` | Switch | Export to HTML | `$true` |

### Operation Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `QuickScan` | Fast triage (critical events only) | Initial assessment, CTF |
| `DeepAnalysis` | Comprehensive analysis (all events) | Full investigation |
| `ThreatHunt` | IOC/Sigma hunting focus | APT hunting, malware analysis |
| `SigmaHunt` | Sigma rule detection only | MITRE ATT&CK detection |
| `LiveMonitor` | Real-time monitoring | Malware sandbox analysis |
| `Interactive` | Full interactive menu (default) | General investigation |

---

## 📚 Examples

### Example 1: Quick System Triage
```powershell
.\WinForensicX.ps1 -Mode QuickScan
```
Fast scan of last 24 hours, automatically exports HTML report.

### Example 2: Deep Investigation
```powershell
.\WinForensicX.ps1 -Mode DeepAnalysis -Hours 48 -ExportHTML
```
Comprehensive 48-hour analysis with detailed HTML report.

### Example 3: IOC Hunting with File
```powershell
.\WinForensicX.ps1 -Mode ThreatHunt -IOCFile "apt-iocs.txt" -Hours 72
```

**IOC File Format** (`apt-iocs.txt`):
```text
# IP Addresses
192.168.1.100
10.0.0.50

# Domains
malware.evil.com
c2server.duckdns.org

# File Hashes (MD5/SHA1/SHA256)
d41d8cd98f00b204e9800998ecf8427e
5d41402abc4b2a76b9719d911017c592

# Process Names
mimikatz.exe
procdump.exe

# Strings
invoke-mimikatz
password dump
```

### Example 4: Sigma Rule Detection
```powershell
.\WinForensicX.ps1 -Mode SigmaHunt -SigmaPath "C:\Sigma-Rules\rules\windows\"
```

**Sigma Rule Example**:
```yaml
title: Mimikatz Credential Dumping
description: Detects mimikatz command line execution
level: critical
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'lsadump::sam'
            - 'kerberos::golden'
    condition: selection
```

### Example 5: Combined Threat Hunting
```powershell
.\WinForensicX.ps1 -Mode Interactive `
    -IOCFile "threat-intel.txt" `
    -SigmaPath "C:\Sigma-Rules\rules\" `
    -YaraPath "malware-rules.yar" `
    -ScanProcesses `
    -Hours 168
```
Full-spectrum threat hunt with IOCs, Sigma, and YARA over 7 days.

### Example 6: Offline Forensic Analysis
```powershell
# Export logs from compromised system first:
wevtutil epl Security C:\Forensics\Security.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Forensics\Sysmon.evtx

# Analyze on forensic workstation:
.\WinForensicX.ps1 -EvtxPath "C:\Forensics\*.evtx" `
    -Mode DeepAnalysis `
    -IOCFile "known-bad.txt" `
    -SigmaPath "sigma-rules\"
```

### Example 7: Live Malware Analysis
```powershell
# Terminal 1: Start monitoring
.\WinForensicX.ps1 -Mode LiveMonitor -YaraPath "malware-patterns.yar" -ScanProcesses

# Terminal 2: Execute malware sample in sandbox
# WinForensicX captures all activity in real-time
```

### Example 8: Interactive Investigation
```powershell
.\WinForensicX.ps1 -Mode Interactive
```

**Interactive Menu Options:**
```
[1]  Hunt for IOC
[2]  Load IOC File
[3]  Load Sigma Rules
[4]  Run Sigma Detection
[5]  Scan Processes (YARA/Pattern)
[6]  View IOC Matches
[7]  View Sigma Matches
[8]  View YARA Matches
[9]  View All Suspicious Indicators
[10] Timeline Reconstruction
[11] Process Investigation
[12] User Activity Drilldown
[13] Kill Process
[14] Block IP/Domain (Firewall)
[15] Export Findings
[16] Refresh Analysis
[0]  Exit
```

### Example 9: Quick IOC Search
```powershell
.\WinForensicX.ps1 -IOC "evil.com" -Mode ThreatHunt
```

### Example 10: CTF/Competition Mode
```powershell
.\WinForensicX.ps1 -Mode QuickScan -Hours 1 -ExportHTML
# Fast analysis, recent events only, immediate HTML report
```

---

## 🔒 Safety & Requirements

### Is It Safe to Run?

**YES** - WinForensicX is safe when used properly. Here's why:

#### ✅ What It Does (READ-ONLY by default)
- **Reads** Windows Event Logs (no modifications)
- **Analyzes** existing log data
- **Searches** for patterns and IOCs
- **Generates** reports (HTML/JSON)
- **Displays** findings to analyst

#### ⚠️ Optional Actions (Require Confirmation)
These features require explicit confirmation (`Type 'CONFIRM' to proceed`):
- **Kill Process** - Terminate running processes
- **Block IP/Domain** - Create Windows Firewall rules
- **Disable Service** - Stop and disable services

**All destructive actions:**
1. Show clear warnings in RED
2. Require typing "CONFIRM"
3. Can be disabled (don't select those menu options)

### Permission Requirements

| Requirement | Why Needed | Can Bypass? |
|-------------|------------|-------------|
| **Administrator** | Access Security event log | ❌ No |
| **Execution Policy** | Run PowerShell scripts | ✅ Yes (-ExecutionPolicy Bypass) |

### What Data Does It Access?

| Data Source | Purpose | Sensitivity |
|-------------|---------|-------------|
| Windows Event Logs | Security analysis | High (contains logon info, IPs) |
| Running Processes | Malware detection | Medium (process names, PIDs) |
| Network Firewall | Response actions | Medium (firewall rules) |
| Defender Status | Security posture | Low (configuration only) |

**No data is sent externally** - Everything runs locally!

### Audit Trail

WinForensicX creates its own audit trail:
- All actions logged to console
- HTML reports include timestamp and parameters
- JSON exports contain full analysis metadata
- No silent operations - everything is visible

### Best Practices

1. **Test in Lab First** - Try on test systems before production
2. **Review IOC Files** - Verify IOC lists before hunting
3. **Backup Firewall Rules** - Before using blocking features
4. **Use Read-Only Mode** - Avoid response actions if unsure
5. **Run Latest Version** - Check for updates regularly

### Known Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Large log files (1GB+) | Slow analysis | Filter by time range (-Hours) |
| YARA not installed | No memory scanning | Uses pattern fallback |
| Sigma parsing | Basic YAML support only | Use standard Sigma format |
| No GUI | Command-line only | HTML reports for sharing |

---

## 📊 Output Examples

### Console Output
```
[INFO] Starting Windows Security Analyzer...
[INFO] Mode: ThreatHunt | Analysis Period: Last 24 hours
[INFO] Loading IOCs from: threat-iocs.txt
[SUCCESS]   Loaded 47 IOCs
[DETAIL]     IP: 12
[DETAIL]     Domain: 18
[DETAIL]     Hash: 15
[DETAIL]     String: 2
[INFO] Hunting for 47 IOCs in event logs...
[DETAIL]   Scanning 15847 events...
[CRITICAL]   IOC MATCH: Domain - evil.duckdns.org in Event 3008
[CRITICAL]   IOC MATCH: IP - 192.168.1.100 in Event 4688
[WARNING]   Found 2 IOC matches
[SUCCESS] ✅ Analysis complete!
```

### HTML Report Preview
- **Executive Summary** - Color-coded statistics
- **IOC Matches** - Red-highlighted critical findings
- **Sigma Detections** - Orange-highlighted rule matches
- **YARA Matches** - Purple-highlighted malware signatures
- **Timeline** - Chronological event reconstruction
- **Suspicious Indicators** - Automated threat detection

---

## 🛠️ Troubleshooting

### Common Issues

#### Issue: "Access Denied" Error
**Solution:**
```powershell
# Run as Administrator
Start-Process powershell -Verb runAs -ArgumentList "-File .\WinForensicX.ps1"
```

#### Issue: "Execution Policy" Error
**Solution:**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\WinForensicX.ps1
```

#### Issue: No Events Found
**Solution:**
- Check Event Log service is running: `Get-Service EventLog`
- Verify audit policies: `auditpol /get /category:*`
- Enable command-line logging: Group Policy → Audit Process Creation

#### Issue: Slow Performance
**Solution:**
```powershell
# Reduce time window
.\WinForensicX.ps1 -Hours 6

# Use QuickScan mode
.\WinForensicX.ps1 -Mode QuickScan
```

#### Issue: YARA Not Working
**Solution:**
Script automatically falls back to pattern matching. No action needed unless you want full YARA:
```powershell
# Download YARA from: https://github.com/VirusTotal/yara/releases
# Place yara64.exe in script directory or PATH
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit:
- 🐛 Bug reports
- 💡 Feature requests
- 📝 Documentation improvements
- 🔧 Code contributions

### Development Setup
```bash
git clone https://github.com/yourusername/WinForensicX.git
cd WinForensicX
# Make changes
# Test thoroughly
# Submit PR
```

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🙏 Acknowledgments

- **Sigma Project** - Detection rule format
- **YARA Project** - Pattern matching engine
- **Sysmon** - Enhanced Windows logging
- **SwiftOnSecurity** - Sysmon configuration baseline
- **DFIR Community** - Threat hunting techniques

---

## 📞 Support

- 📧 Email: support@winforensicx.com
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/WinForensicX/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/WinForensicX/discussions)
- 📖 Wiki: [Documentation](https://github.com/yourusername/WinForensicX/wiki)

---

## ⚠️ Disclaimer

This tool is provided for **legitimate security analysis, incident response, and threat hunting purposes only**. Users are responsible for:
- Obtaining proper authorization before use
- Complying with applicable laws and regulations
- Understanding their organization's security policies
- Using responsibly in production environments

The authors assume no liability for misuse or damage caused by this tool.

---

<div align="center">

**Made with ❤️ by Security Researchers, for Security Professionals**

⭐ Star this repo if you find it useful!

[Report Bug](https://github.com/yourusername/WinForensicX/issues) • [Request Feature](https://github.com/yourusername/WinForensicX/issues)

</div>
