# WinForensicX

**A read-only DFIR / incident-triage and investigation toolkit for Windows, written in PowerShell.**
One command collects the state of a host, analyzes it against data-driven detection rules mapped to
**MITRE ATT&CK**, scores it, and writes a self-contained HTML report plus a hashed case folder. Around that
core it gives investigators and CTF players a set of everyday tools: file triage, payload decoding, IOC
hunting, super-timelines and case diffing.

> **Defensive by design.** WinForensicX changes no system settings and executes nothing it finds. Secrets are
> audited, never extracted: values are redacted to *type + length*. It never dumps LSASS, parses SAM/NTDS
> hashes, decrypts browser/DPAPI secrets, or sends data anywhere. See [SECURITY.md](SECURITY.md).

---

## What's in the box

| Command | What it does |
|---|---|
| `Invoke-WfxTriage` | Collect → analyze → score → report. Modes: **local**, **remote** (`-ComputerName`, WinRM), **offline** (`-EvtxPath`, exported logs only), **re-analyze** (`-InputPath`). |
| `Save-WfxEvidence` | Collect a hashed evidence bundle now, analyze later (anywhere). |
| `Invoke-WfxAnalyze` | Run all analyzers over a bundle. OS-neutral (Windows, Linux, macOS). |
| `Invoke-WfxHunt` | Sweep a host or saved case for IOCs: MD5/SHA-1/SHA-256, exact IPs, domains + subdomains, strings — across processes, network, DNS, autostarts, **event logs**, files. Accepts defanged IOCs and IOC files. |
| `Get-WfxFileTriage` | "What is this file?" — hashes, true type from magic bytes vs. extension, entropy, Mark-of-the-Web download URL, alternate data streams, Authenticode signer, PE header (machine, compile time, sections, packer hints), strings and extracted IOCs. Never executes the file. |
| `ConvertFrom-WfxEncodedCommand` | Decode `-EncodedCommand`, Base64 (UTF-16LE / UTF-8), gzip-wrapped and nested `FromBase64String(...)` payloads, and run the detection rules over the result. Decode only. |
| `Export-WfxTimeline` / `Get-WfxTimeline` | UTC super-timeline of a case: boot/install, process starts, connections, event-log records, file writes, findings → CSV / JSON. |
| `Compare-WfxCase` | Diff two cases: new/removed processes, autostarts, services & drivers, listeners, DNS names, exposures, findings. Baselines, before/after malware runs, CTF "what changed?". |
| `Start-WfxMonitor` | Live baseline + delta monitoring of processes and connections, with beacon detection. |
| `Show-WfxMenu` / `Show-WfxHelp` | Interactive menu over everything above; help in the terminal and as an HTML guide. |

## What it detects

| Area | Examples |
|---|---|
| **Command-line tradecraft** (49 rules) | Encoded PowerShell (auto-decoded and re-scanned), download cradles, AMSI tampering, reflective loading, obfuscation, Defender tampering, certutil/bitsadmin/mshta/regsvr32/rundll32/msiexec/MSBuild/InstallUtil/CMSTP/WMIC proxy execution, comsvcs/procdump LSASS dumps, Mimikatz syntax, hive export, NTDS extraction, Kerberoasting, shadow-copy deletion, log clearing, firewall disable, UAC-bypass keys, Run-key/IFEO/service/task persistence, port proxies, SSH reverse tunnels, AD recon, **ClickFix / fake-CAPTCHA lures** |
| **Processes** | System-name masquerading, parent spoofing (with PID-reuse guard), Office/browser spawning interpreters, unsigned binaries in user folders, offensive & RMM tooling, AI agents |
| **Persistence** | Run keys, Startup, services, drivers (incl. known-vulnerable BYOVD drivers), scheduled tasks (incl. COM handlers), WMI subscriptions, Winlogon, AppInit, IFEO, LSA packages, BootExecute, **Run-dialog history (RunMRU)** |
| **Events** | 4625 spraying/brute force, failure→success chains, 1102/104 log clearing, 7045/4697 services, 4698 tasks, **4688** and **Sysmon 1** command lines, **4104** script blocks (split blocks re-assembled), 4720/4732/4728 account and group changes, 4740 lockouts, external RDP, **Defender detections (1116/1117)** and tampering (5001/5007), **Sysmon 8/10** LSASS access, Sysmon 13 Run keys, Sysmon 22 DNS |
| **Network & DNS** | Non-default listeners on all interfaces, tunnels (ngrok/Cloudflare/…), C2 ports, DGA-like names, risky TLDs, paste sites, AI-API use, low-jitter beaconing (monitor) |
| **Files** (`-FileScan`) | Web shells, double extensions, internet-downloaded executables (with download URL), packed binaries, ransom notes (same name dropped in many folders), mass encryption |
| **Exposure (redacted)** | GPP cPassword, unattend passwords, **live SAM/SYSTEM/SECURITY/NTDS readable by users (HiveNightmare)**, stray hive copies, world-readable cloud credentials, auto-logon password, unencrypted SSH keys, AI/API keys and secrets in env vars, history and config files |
| **Posture & visibility** | AV off / no AV, tamper protection, stale signatures, Defender exclusions, process/command-line/script-block auditing, Sysmon, firewall, RDP without NLA, LSASS protection |

**Two scores.** *Compromise risk* is computed only from evidence of attacker activity. *Posture* is
computed from hardening and visibility gaps. Both use `score = 1 − Π(1 − wᵢ/40)`, so many weak leads can't add
up to a critical. A clean but un-hardened host shows low risk and high posture, not "compromised".

---

## Install

**Requirements:** Windows PowerShell **5.1** or PowerShell **7+**. No external modules. Run elevated for
full visibility. Without admin rights the tool still runs and records what it couldn't see as **gaps**.

**Verify before you run.** Check the release's published SHA-256 for `dist/WinForensicX.ps1` (or the module
files) with `Get-FileHash`. A DFIR tool contains detection strings for attacker techniques, so some antivirus
products may flag it. Do not disable your antivirus. Verify the hash, then add a narrowly scoped, approved
exception or report the false positive to your AV vendor.

### Option A — single file
```powershell
.\WinForensicX.ps1                 # interactive menu
.\WinForensicX.ps1 -RunTriage      # triage straight away
. .\WinForensicX.ps1 -NoAuto       # just load the functions into your session
```

### Option B — module
```powershell
Import-Module .\WinForensicX\WinForensicX.psd1
```

---

## Quick start

```powershell
# Triage this host; write the case to external media
Invoke-WfxTriage -OutputPath E:\cases

# Thorough: web roots / drop folders / ransomware checks + config-file secrets
Invoke-WfxTriage -FileScan -ExposureScan -OutputPath E:\cases

# Remote hosts over WinRM (only the collection code is sent; its SHA-256 is recorded)
Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)

# Offline: exported .evtx only — nothing is collected from the analysis machine
Invoke-WfxTriage -EvtxPath D:\evidence\logs

# Re-analyze a saved case (any OS), with an allowlist of known-good findings
Invoke-WfxTriage -InputPath .\WFX_host_20261103-101500Z -AllowlistPath .\allowlist.json

# Hunt for IOCs (defanged OK) in a saved case, including event logs
Invoke-WfxHunt -Ioc 'evil[.]example','203.0.113.7','44d88612fea8a8f36de82e1278abb02f' -InputPath .\case
Invoke-WfxHunt -IocFile .\advisory.txt -FileScan -HashProcesses     # live, hashing running binaries

# Investigator / CTF utilities
Get-WfxFileTriage .\challenge.bin -Strings | Format-List
Get-ChildItem $env:USERPROFILE\Downloads -File | Get-WfxFileTriage | Where-Object ExtensionMismatch
ConvertFrom-WfxEncodedCommand 'powershell -nop -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAaQAnAA=='
Export-WfxTimeline -InputPath .\case                    # writes <case>-timeline.csv next to the case
Compare-WfxCase -Baseline .\golden -Current .\today | Where-Object Change -eq 'Added'
```

---

## Outputs & chain of custody

```
WFX_<host>_<utc-timestamp>Z/
├─ report.html      # self-contained, filterable report (offline; no external assets)
├─ result.json      # findings, Risk + Posture scores, ATT&CK coverage, gaps, suppressed, case metadata
├─ findings.json / findings.csv
├─ raw/bundle.json  # normalized collected data (all timestamps UTC); re-analyzable with -InputPath
├─ audit.log        # JSON lines: every step, timing, gaps
└─ manifest.json    # written LAST: SHA-256 of every file + tool/rule-pack hashes + parameters + sources
```

After the manifest is written the case is **closed**: no later command can append to it. Hunts write their
own case. Timelines are written *next to* the case folder. Re-analysis cases record the SHA-256 of the source
bundle and manifest.

**What the manifest does and does not prove.** It proves the files are unchanged *relative to the manifest*.
The manifest itself is not signed. The tool prints the manifest's SHA-256 at the end of each run: record it
in your ticket or evidence log, or sign it, to make the case tamper-evident.

---

## Tuning

* **Allowlist** (`-AllowlistPath` or `$env:WFX_ALLOWLIST`): a JSON array of `{ "Id", "Entity", "Host", "Reason" }`
  with `-like` wildcards. Suppressed findings are listed in the report with their reason; they are never
  silently dropped. Example: [`examples/allowlist.example.json`](examples/allowlist.example.json).
* **Custom rule packs** (`$env:WFX_RULES`): files named `<pack>.<label>.json`. Every rule is validated when
  loaded (id, severity, ATT&CK id format). Every regex runs with a 250 ms timeout. See [docs/RULES.md](docs/RULES.md).

## Testing & quality

```powershell
Invoke-Pester ./tests          # 73 tests: analyzers, rule self-tests, regressions, features (any OS)
Invoke-ScriptAnalyzer -Path ./WinForensicX -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
pwsh -File tools/build.ps1     # deterministic single-file build → dist/WinForensicX.ps1
```

## Honest limitations

- Findings are **leads, not verdicts**. Read them alongside the collection gaps: with no process auditing
  and no Sysmon, "nothing found" mostly means "nothing could be seen".
- **Triage, not imaging.** No disk/memory acquisition, no carving of deleted files.
- Live collection requires Windows. Its collectors were designed for Windows 10/11 and Server 2016+ with
  PowerShell 5.1/7; the analysis, hunt, timeline, diff and decoder code is tested on PowerShell 7.
- Only **loaded** user hives (logged-on users) are inspected; unloaded `NTUSER.DAT` files are not parsed.
- Event collection is capped per query, and hitting a cap is reported as a gap. Short-lived processes between
  monitor polls are not seen.
- Reading files can update NTFS last-access times where that is enabled. Write cases to external media for
  evidence work (the tool warns when writing to the system drive of the host under investigation).
- It will not extract, decrypt or dump secrets. That is a deliberate boundary.

## License
MIT. See [LICENSE](LICENSE).
