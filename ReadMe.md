WinForensicX - Professional DFIR/EDR Tool

WinForensicX is a lightweight, high-performance PowerShell-based Digital Forensics and Incident Response (DFIR) tool designed for rapid triage, live system analysis, and APT hunting. It provides responders with a centralized interface to perform deep process forensics, network auditing, and real-time behavior monitoring.

🚀 Core Features

🔍 Deep Process & Memory Forensics

Advanced Inventory: WMI-integrated process listing with full command-line arguments.

Injection Detection: Identify ghosted processes and suspicious threads.

LotL Discovery: Automatic detection of Living-off-the-Land binary abuse (e.g., certutil, mshta).

Tree Analysis: Visualize parent-child relationships to find malicious spawns.

🌐 Network & C2 Hunting

Connection Audit: Real-time view of established TCP/UDP connections.

Hidden Listeners: Identify non-standard ports acting as listeners.

DNS Beaconing: Search the DNS cache for high-entropy domains or suspicious TLDs (.top, .xyz, etc.).

🏹 APT & IOC Hunting

Web Shell Scanner: Rapidly scan common web directories for .aspx, .php, and .jsp shells.

Sigma-Lite: Search for common attacker patterns like Base64-encoded PowerShell commands.

IOC Search: Global log search for specific IPs, Domains, or File Hashes.

🛡️ Live Malware Monitor

Real-time Baselines: Establish a system snapshot and monitor for new process creation.

Command-line Capture: Automatically log the arguments used by new processes as they spawn.

📊 SIEM & Log Analysis

Live/Offline Modes: Analyze the current system or ingest .evtx files from a forensic image.

Event Audit: Dedicated modules for Process Creation (4688), PowerShell Activity (4104), and Logon Events (4624).

🛠️ Requirements & Setup

Requirements

OS: Windows 10/11 or Windows Server 2016+

Shell: PowerShell 5.1 or PowerShell Core 7.x

Privileges: Administrator (Required for Security Log access and deep process memory analysis).

Installation

Clone the repository or download WinForensicX.ps1.

Open a PowerShell terminal as Administrator.

Set execution policy if necessary:

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process


Run the script:

.\WinForensicX.ps1


📖 Usage Notes

Upon launching, press N at any menu to view the internal documentation, system requirements, and the latest legal disclaimer.

Key Navigation

[1-9]: Select modules.

[0/Back]: Return to the previous menu.

[N]: View System Notes.

[Q]: Safely exit the application.

⚖️ Legal Disclaimer

WARNING: FOR AUTHORIZED USE ONLY.

This tool is provided for professional forensic investigation, security auditing, and educational purposes. Unauthorized use against systems without explicit, documented consent is illegal and may violate local and international laws. The author assumes no liability for any misuse, data loss, or damage caused by this software. Use at your own risk.

📝 License

This project is licensed under the MIT License.

Developed by w3bcooki3 | Part of the WinForensicX Stability & Rule-Based Hunting Edition.
