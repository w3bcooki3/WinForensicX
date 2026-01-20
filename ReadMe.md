# WinForensicX - Interactive DFIR/EDR Tool

![Version](https://img.shields.io/badge/version-4.0-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## What is WinForensicX?

**WinForensicX** is an interactive PowerShell-based Digital Forensics & Incident Response (DFIR) and Endpoint Detection & Response (EDR) tool. It's a Swiss Army knife for Threat Hunters, SOC Analysts, and Security Professionals to investigate, detect, and respond to security incidents on Windows systems.

## What Can It Do?

### 🔍 **Process Management**
- List and analyze running processes
- Detect suspicious processes (malware, unusual locations)
- Kill malicious processes
- Monitor process creation in real-time
- Scan with YARA rules

### 👥 **User Management**
- Track user accounts and administrators
- Monitor login history and failed attempts
- Detect recently created/modified users
- Create/disable/delete user accounts

### 🌐 **Network Analysis**
- View all network connections
- Detect suspicious connections (C2 servers, malicious ports)
- Monitor network activity live
- Block IP addresses
- Scan ports

### 📊 **Event Log Analysis**
- Analyze Security, System, and Application logs
- Track PowerShell script execution
- Monitor process creation events
- Review failed login attempts
- Export logs to CSV

### ⚙️ **System Analysis**
- Check installed software and services
- Analyze scheduled tasks and startup programs
- Review registry persistence mechanisms
- Verify Windows Defender status
- Track USB device history

### 🎯 **IOC Hunting**
- Load and hunt for Indicators of Compromise (IPs, domains, hashes, filenames)
- Search across processes, network, DNS cache, and files
- Generate detailed reports

## Purpose

WinForensicX was built to provide security professionals with:

- **Rapid Incident Response** - Quickly identify and neutralize threats
- **Threat Hunting** - Proactively search for IOCs and suspicious activity
- **Forensic Analysis** - Gather evidence and understand attack timelines
- **Security Auditing** - Assess system security posture
- **Real-time Monitoring** - Watch for malicious activity as it happens

All in a single, interactive, menu-driven PowerShell tool that requires no installation.

## How to Use

### Prerequisites
- **Windows 10/11** or **Windows Server 2016+**
- **PowerShell 5.1+**
- **Administrator privileges**

### Basic Usage

#### 1. Interactive Mode (Default)
```powershell
# Open PowerShell as Administrator
.\WinForensicX.ps1
```
Navigate through interactive menus to investigate and respond to threats.

#### 2. Quick Scan
```powershell
.\WinForensicX.ps1 -Mode QuickScan
```
Performs rapid security checks (processes, network, logins, Defender status).

#### 3. Deep Analysis
```powershell
.\WinForensicX.ps1 -Mode DeepAnalysis
```
Comprehensive forensic analysis across all modules.

#### 4. IOC Hunting
```powershell
.\WinForensicX.ps1 -IOCFile "C:\IOCs\threats.txt"
```
Hunt for specific indicators across the system.

### Example Workflow

**Investigating Suspicious Process:**
```powershell
# 1. Launch tool
.\WinForensicX.ps1

# 2. Navigate to Process Management
Main Menu → [1] Process Management

# 3. List suspicious processes
→ [2] List Suspicious Processes

# 4. Get details on flagged process
→ [4] Get Process Details (PID)

# 5. Kill if confirmed malicious
→ [8] Kill Process
```

**Responding to Network Threat:**
```powershell
# 1. Launch tool
.\WinForensicX.ps1

# 2. Navigate to Network Analysis
Main Menu → [3] Network Analysis

# 3. Scan for suspicious connections
→ [8] Scan for Suspicious Connections

# 4. Block malicious IP
→ [11] Block IP Address
```

### IOC File Format

Create a text file with IOCs (one per line):

```
# IPs
192.168.1.100
10.0.0.50

# Domains
malicious.com
evil-server.net

# Filenames
mimikatz.exe
ransomware.dll

# Hashes
5d41402abc4b2a76b9719d911017c592
```

### Command Reference

| Command | Description |
|---------|-------------|
| `.\WinForensicX.ps1` | Interactive mode |
| `.\WinForensicX.ps1 -Mode QuickScan` | Quick security scan |
| `.\WinForensicX.ps1 -Mode DeepAnalysis` | Comprehensive analysis |
| `.\WinForensicX.ps1 -Hours 48` | Analyze last 48 hours |
| `.\WinForensicX.ps1 -IOCFile <path>` | Hunt for IOCs |
| `.\WinForensicX.ps1 -YaraPath <path>` | Scan with YARA rules |

### Menu Quick Reference

**Main Menu:**
- `[1]` Process Management
- `[2]` User Management
- `[3]` Network Analysis
- `[4]` Event Log Analysis
- `[5]` System Analysis
- `[6]` IOC Hunting
- `[7]` Quick Scan
- `[8]` Deep Analysis
- `[9]` Generate Report

## Key Features

✅ **No Installation Required** - Pure PowerShell script  
✅ **Interactive Menus** - User-friendly navigation  
✅ **Real-time Monitoring** - Live process and network tracking  
✅ **IOC Hunting** - Search for known threats  
✅ **Automated Scanning** - Quick and deep scan modes  
✅ **Report Generation** - Export findings to HTML  
✅ **YARA Support** - Scan processes with custom rules  
✅ **Color-coded Output** - Easy identification of threats  

## Troubleshooting

**Script won't run:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Access Denied errors:**
```
Run PowerShell as Administrator
```

**No event log data:**
```powershell
# Enable auditing
auditpol /set /category:"Detailed Tracking" /success:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for legitimate security research, incident response, and system administration only. Users are responsible for compliance with applicable laws.


<p align="center">Made for the InfoSec Community by Rahul <a href="https://github.com/w3bcooki3">@w3bcooki3</a></p>
