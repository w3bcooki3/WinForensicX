import json, pathlib
base = pathlib.Path(__file__).resolve().parent.parent / "WinForensicX" / "Rules"

# ─────────────────────────── events.json ───────────────────────────
# Sigma-lite rules over normalized Windows events. `select` fields are matched against
# the normalized event object produced by the event collector/analyzer.
E = []
def ev(id, title, logs, eids, pattern, fields, technique, severity, confidence, description, recommendation, match=None, nomatch=None):
    E.append(dict(id=id, title=title, logs=logs, eventIds=eids, pattern=pattern, fields=fields,
                  technique=technique, severity=severity, confidence=confidence,
                  description=description, recommendation=recommendation,
                  tests=dict(match=match or [], nomatch=nomatch or [])))

ev("EVT-4625-SPRAY", "Password spraying / brute force (many failed logons)", ["Security"], [4625],
   None, ["TargetUserName","IpAddress"], ["T1110","T1110.003"], "High", "Medium",
   "A burst of failed logons. Many accounts from one source suggests spraying; one account many times suggests brute force.",
   "Identify the source IP/host, block it, and confirm no success (4624) followed. Enforce lockout and MFA.",
   )
ev("EVT-4625-THEN-4624", "Successful logon after repeated failures (likely cracked)", ["Security"], [4624,4625],
   None, ["TargetUserName","IpAddress"], ["T1110"], "High", "High",
   "An account that failed to log on many times then succeeded from the same source — the hallmark of a guessed or sprayed password.",
   "Reset the account password, review what the session did, and check the source host.",
   )
ev("EVT-4672-SENSITIVE", "Sensitive privileges assigned at logon (admin-equivalent)", ["Security"], [4672],
   None, ["SubjectUserName"], ["T1078"], "Low", "Low",
   "A logon was granted sensitive privileges (effectively admin). Normal for admins and services; useful as timeline context.",
   "Correlate with the matching 4624 and confirm the account is meant to have these rights.",
   )
ev("EVT-1102-CLEARED", "Security event log cleared", ["Security"], [1102],
   None, ["SubjectUserName"], ["T1070.001"], "High", "High",
   "The Security log was cleared. Attackers do this to destroy evidence; it is almost never part of normal operations.",
   "Find who cleared it and when, and recover logs from your SIEM or forwarded copies.",
   )
ev("EVT-104-CLEARED", "System/application event log cleared", ["System"], [104],
   None, ["SubjectUserName"], ["T1070.001"], "Medium", "High",
   "An event log was cleared.",
   "Confirm whether this was a sanctioned maintenance action.",
   )
ev("EVT-7045-SERVICE", "New service installed", ["System","Security"], [7045,4697],
   r"(?i)powershell|cmd(?:\.exe)?\s*/c|mshta|rundll32|regsvr32|\\users\\|\\temp\\|\\programdata\\|\\appdata\\|%systemroot%\\[^\\]+\.exe$|\.ps1|-enc\b|frombase64",
   ["ServiceName","ImagePath"], ["T1543.003"], "Medium", "Medium",
   "A new Windows service was installed whose program looks like a script interpreter or sits in a user-writable path — common for persistence and lateral movement (PsExec-style).",
   "Inspect the service's binary path and signature; remove it if not legitimate.",
   )
ev("EVT-4698-TASK", "Scheduled task created", ["Security","Microsoft-Windows-TaskScheduler/Operational"], [4698,106],
   r"(?i)powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|\\users\\|\\temp\\|\\appdata\\|\\programdata\\|-enc\b|frombase64|downloadstring",
   ["TaskName","Command"], ["T1053.005"], "Medium", "Medium",
   "A scheduled task was created that runs a script host or a user-folder program.",
   "Review the task action and trigger; remove it if unexpected.",
   )
ev("EVT-4688-LOLBIN", "Suspicious process creation (command-line rules)", ["Security"], [4688],
   "__lotl__", ["NewProcessName","CommandLine","ParentProcessName"], [], "Medium", "Medium",
   "Process-creation events are run through the full living-off-the-land rule set, so historical 4688 logs are analyzed the same way as live processes.",
   "See the matched command-line rule for specifics.",
   )
ev("EVT-4104-SCRIPTBLOCK", "Suspicious PowerShell script block", ["Microsoft-Windows-PowerShell/Operational"], [4104],
   "__lotl__", ["ScriptBlockText"], [], "Medium", "Medium",
   "Recorded PowerShell script blocks are scanned with the command-line rules, catching encoded commands, download cradles, AMSI bypasses and reflective loading.",
   "See the matched rule; recover the full script block for analysis.",
   )
ev("EVT-4104-SUSPICIOUS-CEARED", "PowerShell logging was reduced or disabled", ["Microsoft-Windows-PowerShell/Operational"], [4104],
   r"(?i)set-psreadlineoption\s+-historysaving\s+disable|clear-history|remove-item[^\n]*consolehost_history|group\s*policy[^\n]*scriptblocklogging[^\n]*0|\bEtwEventWriteFull\b|wevtutil\s+sl\s+microsoft-windows-powershell",
   ["ScriptBlockText"], ["T1562.002"], "High", "Medium",
   "A script tried to turn off PowerShell history or script-block logging — covering tracks.",
   "Treat subsequent PowerShell activity as under-logged; pull any history that remains.",
   )
ev("EVT-4720-USER-CREATED", "New user account created", ["Security"], [4720],
   None, ["TargetUserName"], ["T1136.001"], "Medium", "Medium",
   "A new account was created. Normal in managed environments; suspicious on a workstation or outside a change window.",
   "Confirm the account is expected and who created it.",
   )
ev("EVT-4732-ADMIN-ADD", "Member added to a privileged local group", ["Security"], [4732],
   r"(?i)S-1-5-32-544|S-1-5-32-555|administrators|remote desktop users",
   ["TargetUserName","MemberName","GroupName"], ["T1098"], "High", "Medium",
   "An account was added to local Administrators or Remote Desktop Users.",
   "Verify authorization; remove and investigate if not.",
   )
ev("EVT-4728-DOMAIN-ADMIN", "Member added to a privileged domain group", ["Security"], [4728,4756],
   r"(?i)domain admins|enterprise admins|schema admins|administrators|account operators",
   ["TargetUserName","MemberName","GroupName"], ["T1098"], "Critical", "Medium",
   "An account was added to a highly privileged domain group — a major escalation if unexpected.",
   "Confirm with your change process immediately; this is a common post-compromise action.",
   )
ev("EVT-4698-DISABLE-DEFENDER", "Defender protection events", ["Microsoft-Windows-Windows Defender/Operational"], [5001,5007,1116,1117],
   r"(?i)disabled|turned off|exclusion|tamper",
   ["Message"], ["T1562.001"], "High", "Medium",
   "Microsoft Defender reported being disabled, modified or that it detected malware. Protection changes near other suspicious activity are a red flag.",
   "Check what changed, re-enable protection, and review detections.",
   )
ev("EVT-RDP-EXTERNAL", "Interactive/RDP logon from an external address", ["Security"], [4624],
   None, ["LogonType","IpAddress","TargetUserName"], ["T1021.001","T1133"], "Medium", "Medium",
   "An interactive or remote-desktop logon came from a public IP address. Direct RDP from the internet is a common intrusion vector.",
   "Confirm the source is expected; restrict RDP exposure and require MFA/VPN.",
   )
(base / "events.json").write_text(json.dumps(
    {"name":"Windows event-log detections (Sigma-lite)","version":"2026.10","rules":E}, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
print(len(E), "event rules")

# ─────────────────────────── ai.json ───────────────────────────
# AI-era context: local LLM runtimes, AI CLIs/agents, and signs of AI-enabled abuse.
ai = {
  "name": "AI-era software and activity",
  "version": "2026.10",
  "runtimeProcesses": ["ollama.exe","ollama app.exe","lm studio.exe","lmstudio.exe","jan.exe","gpt4all.exe",
      "koboldcpp.exe","llama-server.exe","llamafile.exe","localai.exe","text-generation-webui.exe","oobabooga.exe",
      "comfyui.exe","stable-diffusion.exe","openwebui.exe","anythingllm.exe"],
  "runtimePorts": [11434, 1234, 8080, 5000, 7860, 8000, 3000],
  "assistantProcesses": ["claude.exe","chatgpt.exe","copilot.exe","cursor.exe","codeium.exe","windsurf.exe",
      "warp.exe","continue.exe","cody.exe","tabnine.exe","aider.exe","goose.exe","perplexity.exe"],
  "cliHints": ["claude","openai","ollama","llm ","aider","goose","sgpt","shell-gpt","chatgpt","gh copilot","gemini ","llamafile","aichat"],
  "agentHints": ["autogpt","agentgpt","babyagi","crewai","langchain","autogen","open interpreter","interpreter --","gpt-engineer","smol developer","devika","openhands"],
  "apiDomains": ["api.openai.com","api.anthropic.com","generativelanguage.googleapis.com","api.cohere.ai",
      "api.mistral.ai","api.groq.com","openrouter.ai","api.together.xyz","api.replicate.com","api.perplexity.ai",
      "api-inference.huggingface.co","api.deepseek.com","api.x.ai","oai.azure.com","bedrock-runtime"],
  "notes": "Local AI runtimes often expose an unauthenticated API on localhost (e.g. Ollama on 11434). "
           "On a shared or server system that is an exposure worth flagging. AI coding assistants and autonomous "
           "agents can run shell commands on the user's behalf, which matters when reconstructing who or what ran something.",
  "rules": [
    {"id":"AI-OLLAMA-EXPOSED","title":"Local LLM API listening on all interfaces","technique":["T1133"],
     "severity":"Medium","confidence":"Medium",
     "description":"A local AI runtime (such as Ollama) is listening on 0.0.0.0 rather than localhost. Its API usually has no authentication, so anyone who can reach the port can use the model, read loaded context and run it at the host's expense.",
     "recommendation":"Bind the runtime to 127.0.0.1 (e.g. OLLAMA_HOST=127.0.0.1) or put it behind an authenticated proxy, and restrict the port with the firewall."},
    {"id":"AI-KEY-EXPOSED","title":"AI provider API key stored in clear text","technique":["T1552.001"],
     "severity":"High","confidence":"High",
     "description":"An API key for an AI provider was found in a file, environment variable or history. These keys are billable and often grant broad access, so a leaked key can be abused immediately.",
     "recommendation":"Revoke and rotate the key with the provider, remove it from the file/variable, and store it in a secret manager instead."},
    {"id":"AI-AGENT-SHELL","title":"Autonomous AI agent able to run shell commands","technique":["T1059.001","T1204.004"],
     "severity":"Low","confidence":"Low",
     "description":"An AI agent framework or a coding assistant with command execution was present. This is legitimate, but it means some commands on the host may have been generated and run by an AI tool rather than typed by a person — relevant when attributing activity.",
     "recommendation":"When reconstructing a timeline, consider the AI tool as a possible actor. Review its logs/history if available."},
    {"id":"AI-PHISHING-ARTIFACT","title":"AI-generated lure or deepfake artifact present","technique":["T1204.002"],
     "severity":"Low","confidence":"Low",
     "description":"Filenames or tooling associated with AI-generated phishing content, voice cloning or face-swap deepfakes were found. Attackers increasingly use these to make lures and impersonation more convincing.",
     "recommendation":"If this host is not expected to create such content, review how the files arrived and whether they were used against your users."}
  ]
}
(base / "ai.json").write_text(json.dumps(ai, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
print(len(ai["rules"]), "ai rules +", len(ai["runtimeProcesses"]), "runtimes")

# ─────────────────────────── threats.json ───────────────────────────
threats = {
  "name": "Threat tooling, RMM and infrastructure indicators",
  "version": "2026.10",
  "rmmProcesses": ["anydesk.exe","teamviewer.exe","teamviewer_service.exe","screenconnect.clientservice.exe",
      "screenconnect.windowsclient.exe","connectwisecontrol.client.exe","atera_agent.exe","ateraagent.exe","syncro.exe",
      "splashtop.exe","sraserver.exe"," scinstaller","supremo.exe","ultraviewer_service.exe","rustdesk.exe",
      "gotohttp.exe","dwservice.exe","mremoteng.exe","remotepc.exe","pcmonitor.exe","mmc.exe/vnc","ngrok.exe",
      "cloudflared.exe","tailscale.exe","vnc.exe","winvnc.exe","tvnserver.exe","dwagent.exe","meshagent.exe","zoho assist.exe"],
  "offensiveProcesses": ["mimikatz.exe","rubeus.exe","seatbelt.exe","sharphound.exe","bloodhound.exe","certify.exe",
      "lazagne.exe","winpeas.exe","wce.exe","pwdump.exe","gsecdump.exe","procdump.exe","procdump64.exe","nanodump.exe",
      "cobaltstrike","beacon.exe","sliver","covenant","meterpreter","nc.exe","ncat.exe","socat.exe","chisel.exe",
      "advanced_port_scanner.exe","advanced_ip_scanner.exe","softperfect","netscan.exe","angryip.exe","nmap.exe",
      "psexec.exe","paexec.exe","winrs.exe","adfind.exe","impacket","secretsdump","wmiexec","smbexec","defendercontrol.exe",
      "gmer.exe","processhacker.exe","kdmapper.exe","kprocesshacker"],
  "offensiveNote": "Presence of a tool is not proof of compromise (some are legitimate admin or pentest tools), "
      "but offensive tooling on a normal endpoint, outside an authorized engagement, warrants investigation.",
  "suspiciousPipes": ["\\msagent_","\\status_","\\postex_","\\MSSE-","\\mojo_","\\posh_","\\gruntsvc","\\djkawejf",
      "\\ntsvcs_","\\windows.update.manager","\\interprocess_","\\demoagent","\\f4c3","\\srvsvc_"],
  "suspiciousPipeNote": "Named pipes used by default by Cobalt Strike, Meterpreter and similar C2 frameworks.",
  "unsignedDriverPaths": ["\\users\\","\\temp\\","\\programdata\\","\\appdata\\","\\downloads\\","\\perflogs\\"],
  "vulnerableDrivers": ["rtcore64.sys","gdrv.sys","dbutil_2_3.sys","iqvw64e.sys","procexp152.sys","winio.sys",
      "winring0x64.sys","atillk64.sys","aswarpot.sys","mhyprot2.sys","truesight.sys","viragt64.sys","ene.sys","physmem.sys"],
  "vulnerableDriverNote": "Known-vulnerable signed drivers abused in BYOVD (bring-your-own-vulnerable-driver) attacks to disable security tools."
}
(base / "threats.json").write_text(json.dumps(threats, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
print(len(threats["rmmProcesses"]), "rmm +", len(threats["offensiveProcesses"]), "offensive +", len(threats["vulnerableDrivers"]), "drivers")

# ─────────────────────────── dns.json ───────────────────────────
dns = {
  "name": "Network and DNS indicators",
  "version": "2026.10",
  "suspiciousTlds": [".top",".xyz",".club",".work",".click",".link",".gq",".cf",".ml",".ga",".tk",".rest",".country",
      ".download",".stream",".loan",".racing",".win",".review",".date",".kim",".party",".science",".men",".cam",
      ".monster",".cyou",".sbs",".lol",".quest",".mom",".zip",".mov"],
  "dgaNote": "High-entropy, long, consonant-heavy or dictionary-mashup hostnames can indicate domain-generation-algorithm C2.",
  "dohProviders": ["dns.google","cloudflare-dns.com","mozilla.cloudflare-dns.com","dns.quad9.net","doh.opendns.com",
      "dns.nextdns.io","doh.cleanbrowsing.org","dns.adguard.com","chrome.cloudflare-dns.com","commondatastorage.googleapis.com/doh"],
  "dohNote": "DNS-over-HTTPS can be used by malware to hide lookups from local DNS monitoring.",
  "pasteSites": ["pastebin.com","paste.ee","hastebin.com","ghostbin","rentry.co","transfer.sh","0x0.st","termbin.com",
      "controlc.com","dpaste","ix.io","privatebin","anonfiles","gofile.io","tmpfiles.org","file.io","catbox.moe","litterbox.catbox.moe"],
  "pasteNote": "Text-paste and anonymous file-sharing sites are commonly used to stage payloads and exfiltrate data.",
  "tunnelDomains": ["ngrok.io","ngrok-free.app","trycloudflare.com","loca.lt","localtunnel.me","serveo.net","pagekite.me",
      "telebit.io","portmap.io","localhost.run","bore.pub","tunnelto.dev"],
  "tunnelNote": "Ad-hoc tunneling services expose internal services to the internet and are abused for C2 and data theft.",
  "beaconNote": "Regular, evenly spaced connections to one destination (low timing jitter) are characteristic of C2 beaconing."
}
(base / "dns.json").write_text(json.dumps(dns, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
print(len(dns["suspiciousTlds"]), "tlds +", len(dns["tunnelDomains"]), "tunnels")
