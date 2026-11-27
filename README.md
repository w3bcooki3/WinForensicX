# WinForensicX

**Incident triage, investigation and containment for Windows, in plain PowerShell. Read-only unless you choose to respond.**

One command collects the state of a Windows host, checks it against detection rules mapped to MITRE ATT&CK,
and writes a case report you can hand to a colleague. Around that core is a toolkit for the rest of the job:
61 live views of the machine, execution artifacts (Amcache, ShimCache, Jump Lists, ShellBags, SRUM, `$MFT` …)
from the live host or a KAPE folder, process trees, event-log tampering checks, Sigma and YARA, incident grouping, IOC hunting, file triage, payload decoding,
timelines, case diffing, and exports to Timesketch, Elastic (ECS) and STIX 2.1.

No install, no external modules, no network traffic of its own. Windows PowerShell 5.1 or PowerShell 7+.

![Case report: summary](docs/img/report-summary.png)

<sub>Sample report from a synthetic APT scenario (no real host): [`examples/sample-report.html`](examples/sample-report.html).</sub>

---

## Contents

- [Quick start](#quick-start)
- [The case report](#the-case-report)
- [Explore: live views with flags](#explore-live-views-with-flags)
- [Evidence of execution](#evidence-of-execution)
- [Commands](#commands)
- [What it detects](#what-it-detects)
- [Respond: contain what you found](#respond-contain-what-you-found)
- [Sigma, YARA and exports](#sigma-yara-and-exports)
- [Case folder and chain of custody](#case-folder-and-chain-of-custody)
- [Safety boundaries](#safety-boundaries)
- [Tuning](#tuning)
- [Testing](#testing)
- [Limitations](#limitations)

---

## Quick start

1. **Download and extract the whole archive.** Optionally [verify the hashes](#verifying-the-download).
2. **Open PowerShell** (Start → type *PowerShell*). Administrator rights give access to the Security log,
   every process, Prefetch, the NTFS change journal and BitLocker state. If the window is not elevated, the tool
   asks once: **A** restart as administrator (Windows asks you to confirm), **C** continue without (each report
   lists what it could not see) or **Q** quit. `-Elevate` skips the question, `-NoElevate` never asks.
3. **Start it from that window:**

   ```powershell
   cd "$HOME\Downloads\WinForensicX-3.3.0"
   .\Start-WinForensicX.ps1
   ```

   | If PowerShell says | Do this |
   |---|---|
   | *running scripts is disabled on this system* | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then run it again. It applies to this window only. |
   | *…is not digitally signed* | The files still carry the downloaded-from-the-Internet mark. After checking the hashes: `Get-ChildItem -Recurse \| Unblock-File`. |

   > Right-click → **Run with PowerShell** is not supported: it closes the window as soon as PowerShell
   > refuses the script, so all you see is a window flashing open and shut.

   At start it also checks its own files against `SHA256SUMS.txt` and says if any code file was changed,
   removed or added.

4. **Pick from the menu:**

   ```
     1  Investigate this computer    triage: find signs of compromise and get a report
     2  Explore this computer        61 live views: what changed recently, users, software, network, USB...
     3  Hunt & analyze               IOC hunting, file triage, decode payloads
     4  Cases & evidence             open reports, verify, timeline, compare
     5  Live monitor                 watch new processes / connections as they happen
     6  Settings                     output folder, look-back, allowlist, custom rules
     7  Respond                      stop, quarantine, disable, block, isolate: confirmed and undoable
     H  Help & guide                 the field guide, in your browser
   ```

   **B** goes back and **Q** quits from anywhere. Output goes to `Desktop\WinForensicX` unless you change it
   in Settings; for real evidence, use an external drive.

Prefer commands? `Import-Module .\WinForensicX\WinForensicX.psd1`, then `Invoke-WfxTriage`.
For a USB stick or a remote host, copy the single file `dist\WinForensicX.ps1`.

The full field guide (investigations step by step, how to read each flag, every view and command) is
[`docs/guide.html`](docs/guide.html), also opened with **H** in the menu.

---

## The case report

`report.html` is a single offline file: no external assets, a strict Content-Security-Policy, and every
evidence value escaped. It opens in any browser, including inside Windows Sandbox or on an isolated
analysis machine.

| Section | What you get |
|---|---|
| **Summary** | A verdict in words, what happened from the earliest to the latest finding, a numbered *Do first* list with the action for each item, the suspicious-activity window, accounts involved, external addresses, compromise risk and hardening scores. |
| **Act now** | Live triage only. The first steps for *this* computer and what to avoid, and whether its memory could be kept if it had to go off: virtual-machine snapshot, crash-dump type, page file and free space for a full dump, Ctrl+Scroll Lock, hibernation and Fast Startup, BitLocker recovery key, Memory Integrity, LSA protection, Credential Guard, uptime. Each check is *Ready*, *Not ready*, *Note* or *Unknown*, with the fix to make before an incident. Nothing is changed. |
| **When it happened** | Every time-stamped finding on a time axis, one row per ATT&CK stage, with incidents shaded behind them. Zoom to any incident; select a point to open the finding. |
| **Incidents** | Findings that share a file, account or address within hours (or a burst of high-severity findings) grouped into one story, with the ATT&CK stages it covers, why each finding was joined and the **likely starting point**. |
| **Attack path** | Findings placed on the ATT&CK lifecycle, earliest stage first, with the time each stage was first seen. |
| **Findings** | A list (by severity, by time or by incident) beside a case file for the selected finding: **What happened**, **When** (the time and what it means, the finding's place in its incident), **How we know** (the source, process chain, command line with the suspicious parts marked, the evidence, and every **independent source that also recorded it**), and **What to do**. Printing gives every case file. |
| **Evidence of execution** | Amcache, ShimCache, Prefetch, BAM, Jump Lists, shortcuts, ShellBags, browser downloads and Defender logs, filterable by artifact and evidence kind, with flagged rows linked to their finding. CSV export. |
| **Indicators** | IPs, domains, URLs, hashes, files, registry keys and accounts pulled from attacker-related findings. Defang for sharing, copy, or download as CSV. |
| **Timeline / Changes** | Findings and recent changes grouped by day; CSV export. |
| **ATT&CK** | Technique matrix, with a layer you can load into MITRE ATT&CK Navigator. |
| **Not visible** | Collection gaps and allowlisted findings, so "nothing found" is never mistaken for "nothing there". |
| **Custody** | Case ID, operator, parameters and hashes, with the `Test-WfxCase` command to verify the folder. |

All times are UTC. Dark mode, phone width and print (with running page headers and page numbers) are
supported. CSV exports neutralise spreadsheet formulas.

![A finding's case file: what happened, when, how we know, what to do](docs/img/report-finding.png)

![When it happened: findings by ATT&CK stage over time, incidents shaded](docs/img/report-timeline.png)

---

## Explore: live views with flags

Instant, read-only answers without a full triage. Every view can be filtered, opened in the browser, exported
to CSV, or saved all together as a hashed inventory report. The browser page summarises what was flagged,
filters by flag and by the main columns, sorts, and opens any row in a side panel with every field in full.

Views that can show attacker activity run the same analyzers as triage over each row and add **Flag**
(CRITICAL / HIGH / MEDIUM / LOW), **Why**, **Technique** and **Rule**. **S** shows flagged rows only.

![Flagged rows in an Explore view](docs/img/flagged-view.png)

| Group | Views |
|---|---|
| **Evidence of execution** | What ran (Amcache, ShimCache, Prefetch, BAM, UserAssist, PCA, with SHA-1 where recorded); user activity (Jump Lists, shortcuts, ShellBags, RunMRU, typed paths, Explorer searches); browser downloads with source URL; Defender support logs |
| **Recent changes** | Combined timeline; registry writes in persistence and security keys; NTFS change journal (created, deleted, modified, renamed, alternate streams, timestamps); deleted files (Recycle Bin, Sysmon); software and driver installs; programs that ran (Prefetch, BAM, UserAssist); connection history; security configuration changes |
| System | Overview, updates, software, users, privileged groups, sessions, profiles, shares, USB history, drives and BitLocker |
| Processes | All processes (signer, owner, parent, command line, SHA-256), process tree, unsigned or user-folder programs, DLLs loaded from user-writable folders, open named pipes |
| Network | Listening ports, connections (named from the DNS cache), DNS cache, adapters, routes, ARP, hosts file, proxy, Wi-Fi profiles, firewall rules, SMB sessions |
| Persistence | Autostarts, non-standard services and drivers, scheduled tasks, WMI subscriptions |
| Events | Logons, failed logons, RDP, account and group changes, new services, cleared logs, reboots and crashes, suspicious PowerShell, Defender detections |
| Files | Downloads with source URL, new programs in user folders, Prefetch, recent files, PowerShell history (redacted), Run-dialog history |
| Security | Posture checklist (AV, tamper protection, firewall, UAC, LSA, Credential Guard, WDigest, SMBv1, LLMNR, logging, Sysmon, RDP NLA, auto-logon, patch age) with fixes; memory-capture readiness and the incident card |

**How "recent changes" works with no prior monitoring:** Windows already keeps the evidence. Registry keys
have last-write times, the NTFS change journal records file operations, the Recycle Bin keeps original
paths and deletion times, Prefetch/BAM/UserAssist record program runs, and the event logs record installs,
services, tasks, accounts and policy changes. Sources that are not enabled (Sysmon, WFP auditing, the
firewall log) are reported as gaps.

---

## Evidence of execution

`Get-WfxArtifact` parses the artifacts investigators reach for first and returns one normalised record per
entry: **Artifact, Time, TimeKind** (what the time actually means), **Evidence** (Execution, Presence,
Access, Download, Detection, Install), **Path, Name, Sha1, User, Detail, Source**.

| Artifact | Source | Proves |
|---|---|---|
| Amcache | `Amcache.hve`: files (SHA-1), programs, drivers | Presence, often execution; the hash identifies the binary even after it is deleted |
| ShimCache | `SYSTEM` AppCompatCache (Win7 – 11) | Presence on disk; order and last-modified time |
| Prefetch, BAM, UserAssist, PCA | Prefetch folder, `SYSTEM`, `NTUSER.DAT`, `C:\Windows\appcompat\pca` | Execution, with last-run times and counts |
| Jump Lists, shortcuts | `AutomaticDestinations`, `CustomDestinations`, `Recent\*.lnk` | Files and folders opened, with target times, volume serial, machine and **arguments** |
| ShellBags | `UsrClass.dat`, `NTUSER.DAT` | Folders browsed, including removable drives, network and admin shares |
| RunMRU, typed paths, searches | `NTUSER.DAT` | Commands typed in Run (checked by the command-line rules), Explorer paths and searches |
| Browser downloads | Chrome, Edge, Brave, Opera, Vivaldi `History`; Firefox `places.sqlite` | What was downloaded, from where (URL chain and referrer), and where it went |
| Defender logs | `MPLog-*.log`, `MPDetection-*.log` | Detections and the files Defender saw, even after the event log was cleared |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Bytes sent and received, and bytes written and read, per program and user, hour by hour for about 30 days, even for programs since deleted |
| `$MFT` | The NTFS master file table from a collection (`C\$MFT`) | Programs, scripts, archives and shortcuts on the volume, including deleted records; the download origin from `Zone.Identifier`; both sets of timestamps, for timestomping |

```powershell
Get-WfxArtifact -Flag | Where-Object Flag                          # this computer (administrator)
Get-WfxArtifact -Path D:\kape\C -Flag | Export-Csv art.csv         # a KAPE / Velociraptor collection or mounted image
Invoke-WfxTriage -ArtifactPath D:\kape\C -CaseName ctf-01          # full case report from a collection
Invoke-WfxHunt -ArtifactPath D:\kape\C -Ioc 'e3b0c442…'            # hashes, URLs and paths across the artifacts
```

The parsers are written from the file-format specifications in plain PowerShell: registry hives (with
`.LOG1/.LOG2` transaction-log replay in memory), compound files, shell links, shell items, SQLite, ESE
(the database format of SRUM, with its compressed and long values) and NTFS file records (with update
sequence fixups, extension records and alternate data streams). Files
are recognised by content, so renamed hives work. Nothing is loaded into the registry, executed or modified.
Every record is checked by the triage rules: offensive, exfiltration and remote-management tools, system-name
masquerading, execution from staging folders, known-vulnerable drivers, risky downloads, admin-share and
removable-drive access, encoded or LOLBin arguments in shortcuts and Run history, sensitive searches.

---

## Commands

| Command | Purpose |
|---|---|
| `Invoke-WfxTriage` | Collect → analyze → score → report. **Local**, **remote** (`-ComputerName`, WinRM), **offline** (`-EvtxPath`) or **re-analyze** (`-InputPath`). |
| `Save-WfxEvidence` | Collect a hashed evidence bundle now; analyze later, anywhere. |
| `Invoke-WfxAnalyze` | Run every analyzer over a bundle. Runs on Windows, Linux and macOS. |
| `Get-WfxArtifact` | Execution and user-activity artifacts from this computer or a folder of collected files. |
| `Get-WfxInsight` / `Save-WfxInsight` | The 61 live views / export them all as a hashed inventory report. |
| `Get-WfxActivity` | What changed recently; `-Journal` adds the NTFS change journal. |
| `Invoke-WfxHunt` | Sweep a host or saved case for IOCs (hashes, IPs, domains and subdomains, strings), including event logs. Accepts defanged values and IOC files. |
| `Find-WfxFile` | Fast search across all drives by name (wildcards or regex), extension or none, size, date, hidden; as administrator, NTFS drives are read from the master file table in seconds. Optional SHA-256, real type, signature. |
| `Get-WfxFileTriage` | "What is this file?" Hashes, true type vs. extension, entropy, download URL (Mark of the Web), alternate streams, signer, PE facts, strings and IOCs. Never executes it. |
| `ConvertFrom-WfxEncodedCommand` | Decode `-EncodedCommand`, Base64, gzip and nested `FromBase64String` payloads, then run the rules over the result. |
| `Export-WfxTimeline` | UTC super-timeline of a case (findings, events, changes and artifacts) to CSV or JSON. |
| `Export-WfxCase` | A case as Timesketch CSV, Elastic Common Schema NDJSON, STIX 2.1 bundle or an indicator CSV. |
| `New-WfxFleetReport` | One HTML report across many cases: hosts by risk, movement between hosts, programs on one host only, findings and indicators seen on several hosts, ATT&CK stages. |
| `Compare-WfxCase` | Diff two cases: new processes, autostarts, services, listeners, DNS names, findings. |
| `New-WfxFileBaseline` / `Compare-WfxFileBaseline` | File-integrity baseline for chosen folders. |
| `Test-WfxCase` | Re-hash a case against its manifest: changed, missing or added files. |
| `Invoke-WfxRespond` | Containment, each action confirmed and recorded: stop a process, quarantine a file, disable an autostart, block an address or program, disable a local account. `-PlanPath` runs what a triage suggested. |
| `Get-WfxAction` / `Undo-WfxAction` | What Respond did, and putting it back. |
| `Start-WfxIsolation` / `Stop-WfxIsolation` | Network isolation except your session and allowed addresses; ends by itself after 30 minutes. |
| `Invoke-WfxDefenderScan` | A Microsoft Defender second opinion on files or folders. |
| `Test-WfxIntegrity` | Check this copy of WinForensicX against `SHA256SUMS.txt`: changed, missing, or extra code files the module would load. |
| `Start-WfxMonitor` | Live baseline, then alerts on new suspicious processes, connections and beaconing. |
| `Show-WfxMenu` / `Show-WfxHelp` | The menu; help in the terminal or (`-Html`) in the browser. |

```powershell
Invoke-WfxTriage -FileScan -Plan                                   # what it would read, with these options; reads nothing
Invoke-WfxTriage -OutputPath E:\cases                              # triage this host to external media
Invoke-WfxTriage -FileScan -ExposureScan -OutputPath E:\cases      # plus web roots, drop folders, exposed secrets
Invoke-WfxTriage -DeepScan -OutputPath E:\cases                    # plus injected code in memory (opt-in, slower)
Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)
Invoke-WfxTriage -EvtxPath D:\evidence\logs                        # exported .evtx only
Invoke-WfxTriage -ArtifactPath D:\kape\C                           # collected hives, Amcache, Jump Lists, browsers, .evtx
Invoke-WfxTriage -SigmaPath D:\sigma\rules\windows -YaraRules D:\yara\rules
Invoke-WfxTriage -InputPath .\WFX_PC01_20261103-101500Z -AllowlistPath .\allowlist.json

Invoke-WfxHunt -Ioc 'evil[.]example','203.0.113.7' -InputPath .\case
Get-ChildItem $env:USERPROFILE\Downloads -File | Get-WfxFileTriage | Where-Object ExtensionMismatch
Find-WfxFile -Extension ps1,hta,js,vbs -ModifiedAfter (Get-Date).AddDays(-7)   # scripts changed this week, every drive
Find-WfxFile -NoExtension -Path C:\Users -CheckType | Where-Object TypeMismatch
ConvertFrom-WfxEncodedCommand 'powershell -nop -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAaQAnAA=='
Compare-WfxCase -Baseline .\golden -Current .\today | Where-Object Change -eq 'Added'
Export-WfxCase -InputPath .\case -Format All                       # Timesketch, ECS, STIX 2.1, indicators
New-WfxFleetReport -Path E:\cases                                  # every host's latest case on one page
```

---

## What it detects

| Area | Examples |
|---|---|
| **Command lines** (49 rules) | Encoded PowerShell (decoded and re-scanned), download cradles, AMSI tampering, LOLBin proxy execution (certutil, mshta, regsvr32, rundll32, MSBuild …), LSASS dumping, hive and NTDS export, Kerberoasting, shadow-copy deletion, log clearing, port proxies, SSH tunnels, ClickFix lures. Matched on the original **and** a normalised form, so carets, en-dashes, split quotes and `/switch` spellings do not evade them. |
| **Processes** | C2 and privilege-escalation named pipes open now, unsigned DLLs side-loaded from user-writable folders, system-name masquerading, renamed interpreters, parent spoofing, Office or browsers spawning shells, unsigned programs in user folders, offensive and remote-management tools, AI agents |
| **Persistence** | Run keys, Startup, services, drivers (including known-vulnerable BYOVD drivers), tasks, WMI, Winlogon, AppInit, IFEO, LSA packages, COM hijacks |
| **Event logs** (20 rules) | Spraying and brute force (including spray-then-success by source), log clearing, new services and tasks, 4688 / Sysmon 1 command lines, 4104 script blocks, account and group changes, external RDP, Defender detections and tampering, LSASS access |
| **Network and DNS** | Listeners on all interfaces, tunnels (ngrok, Cloudflare …), C2 ports, DGA-like names, risky TLDs, paste sites, beaconing |
| **Files** (`-FileScan`) | Web shells, double extensions, downloaded executables, packed binaries, ransom notes, mass encryption |
| **Exposed secrets** (`-ExposureScan`) | GPP passwords, unattend files, readable SAM/SYSTEM (HiveNightmare), cloud and API keys, unencrypted SSH keys. Reported redacted to *type + length*. |
| **Recent activity** | Defender exclusions, hijack keys, weakened LSA/WDigest, timestomping, time changes, mass deletion or modification bursts |
| **Execution artifacts** | Offensive, exfiltration and remote-management tools by name or Amcache hash, masquerading, staging-folder execution, vulnerable drivers, risky downloads, admin-share and USB access, encoded arguments in shortcuts, Jump Lists and Run history, Defender detections from support logs, large uploads by one program (SRUM), timestomped programs (`$MFT`) |
| **Log integrity** | The clock set back while a log was recording, a busy Security or Sysmon log falling silent for hours while other logs kept recording, Sysmon stopped or its configuration changed |
| **Posture** | AV state, tamper protection, auditing, Sysmon, firewall, RDP without NLA, LSASS protection |

**Two scores.** *Compromise risk* comes only from evidence of attacker activity; *posture* comes from
hardening and visibility gaps. A clean but unhardened host shows low risk, not "compromised". Both use
`1 − Π(1 − wᵢ/40)`, so a pile of weak leads cannot add up to a critical.

**Incidents.** Findings that share a file, account or public address within six hours, or High/Critical
findings within twenty minutes of each other, are grouped into incidents. Every link records why it was made.
The likely starting point is the earliest initial-access finding, else the earliest execution finding, else
the earliest finding: a lead for where to look first, not a proven root cause.

**Corroboration.** For each finding, the tool looks for independent sources that record the same program:
Amcache, Prefetch, ShimCache, BAM, Sysmon process and driver events, 4688, service installs, Defender,
running processes, autostarts and the change journal. Matching is by full path, or by file name only when
the name is distinctive; common Windows programs (cmd.exe, rundll32.exe …) count only when recorded within
minutes of the finding. Two or more independent sources raise confidence one level, and the report shows
each source and the **earliest trace**, which dates findings that otherwise only describe state at collection.

**Process trees.** Who started whom is rebuilt from Sysmon process events (by process GUID), 4688 events
(by process ID and start time, so a reused ID is not mistaken for the parent) and the live process list.
Each finding about a process shows its ancestry, up to twelve levels, with the command line, user and the
source of every step. When a parent's own start was not recorded, the name the child's record gives is
shown and labelled as such.

**Timestomping.** In an `$MFT`, the standard-information times (which any program can set) are compared
with the file-name times (which only the file system sets). A program in a user-writable folder whose
creation time is earlier than its file-name creation time, or whose times are whole seconds while the
file-name times are not, is reported. Installers and Windows Setup set times for whole folders at once,
so five or more such files in one folder within the same minute are treated as an installation.

---

## Respond: contain what you found

Triage and Explore never change anything. **Respond** (menu 7, or the commands below) is the one part that
does, and only what you confirm, one action at a time. It needs administrator rights.

| Action | What it does | Undo |
|---|---|---|
| Stop a process | Checks the PID is still the same program (name, path, start time, hash) so a reused number is never hit, records its command line, parent, owner, hash and connections, then stops it | No: capture memory first if you need it |
| Quarantine a file | Encrypts it into `Downloads\WinForensicX-Quarantine` (it cannot run there and scanners do not re-detect it), checks the copy, then removes the original. Hash, times, signature and download mark are recorded | Restored byte for byte, with its times and download mark |
| Disable an autostart | Removes a Run / RunOnce value, disables a scheduled task, sets a service to Disabled and stops it, or removes a WMI event binding. The value, task XML or start type is recorded first | Yes |
| Block | Windows Firewall rules (group *WinForensicX*) for an address, in and out, or for a program, outbound | Yes |
| Disable a local account | Never the account in use or the last enabled local administrator | Yes |
| Isolate the computer | Blocks every address except your session (RDP / WinRM / SSH), the DHCP server and addresses you allow. **Ends by itself after 30 minutes** unless you say otherwise | Yes (`Stop-WfxIsolation`) |
| Defender scan | A second opinion from Microsoft Defender on a file or folder | Defender's own |

```powershell
Invoke-WfxTriage -OutputPath E:\cases                         # the case gets respond-plan.json: suggestions only
Invoke-WfxRespond -PlanPath E:\cases\WFX_PC01_... -WhatIf        # what would happen
Invoke-WfxRespond -PlanPath E:\cases\WFX_PC01_...               # each action asks first
Invoke-WfxRespond -KillProcess 4242 -QuarantineFile C:\Users\ana\AppData\Roaming\upd\upd.exe
Start-WfxIsolation -Minutes 30 -Allow 10.0.0.15
Get-WfxAction | Format-Table Time, Type, Target, Status, Undone
Undo-WfxAction -Id 20261127101500-3fa2c1
```

**Never touched, whatever you type:** processes Windows cannot run without (`lsass`, `csrss`, `wininit`,
`smss`, `services`, `winlogon` …), `svchost.exe` as a whole (disable the one service instead), security
products, WinForensicX itself; Microsoft-signed files in the Windows folder; services Windows needs to start,
log on, network or protect itself; registry values outside the Run keys; firewall blocks for loopback,
"everything" or this computer's own addresses. Riskier actions (a Microsoft program, a task in the Microsoft
folder, a private address) ask a second time. The suggested plan is checked against the case manifest, so a
plan edited after the triage is refused. The quarantine refuses to sit in a OneDrive, Dropbox or Google Drive
folder, because syncing would copy malware off the computer (`-QuarantinePath` for another local folder).

---

## Sigma, YARA and exports

- **Sigma.** Point `-SigmaPath` (or `WFX_SIGMA`, or Settings in the menu) at a folder of Sigma rules, for
  example `rules/windows` from SigmaHQ. Rules are read as data and compiled to the tool's own matcher: field
  modifiers (`contains`, `startswith`, `endswith`, `re`, `all`, `cidr`, `base64`, `base64offset`, `windash`,
  `exists`), full conditions (`1 of selection_*`, `all of them`, `not`, parentheses). Rules add the
  Security and System event IDs they need to collection. 4688 events are mapped to Sysmon field names. Of the
  2,427 SigmaHQ Windows rules, 2,229 load; the rest (aggregations, correlations, unsupported log sources)
  are listed as a gap with the reason. Matches become `SIGMA-…` findings with the rule's level and ATT&CK tags.
- **YARA** (optional). `-YaraRules` (or `WFX_YARA`) runs a `yara` executable *you* installed (`-YaraExe`,
  `WFX_YARA_EXE` or PATH) over running programs, autostarts, flagged files and artifact paths — or over the
  whole `-ArtifactPath` folder. Matches become `YARA-<rule>` findings. Without yara, a gap says so.
- **Exports.** `Export-WfxCase -Format Timesketch|Ecs|Stix|Indicators|All` writes next to the case:
  `*-timesketch.csv` (import into Timesketch), `*-ecs.ndjson` (Elastic / OpenSearch bulk-ready, ECS fields),
  `*-stix.json` (STIX 2.1 bundle: indicators with patterns, ATT&CK attack-patterns, a report; ids are
  deterministic so re-exports match) and `*-indicators.csv`. The case manifest is not touched, so
  `Test-WfxCase` still verifies.
- **Fleet.** `New-WfxFleetReport -Path <folder of cases>` reads each host's latest case (`-AllCases` for all)
  and writes one offline HTML page: hosts ranked by risk, findings and indicators seen on more than one host,
  which ATT&CK stages appeared where, **movement between hosts** (remote logons in, explicit-credential
  logons and SMB, RDP, WinRM, RPC or SSH connections out, matched to hosts by name or by addresses that
  belong to one host only), machines in those records that were not triaged, and **programs recorded on
  only one host** (with three or more hosts; paths compared without drive, user name or version folders).
  Cases triaged before 3.2 carry no program or logon summary; triage them again to include them.

---

## Case folder and chain of custody

```
WFX_<host>_<utc>Z/
├─ report.html       the case report (offline, self-contained)
├─ result.json       findings, scores, ATT&CK coverage, gaps, case metadata
├─ findings.csv      flat view for a spreadsheet or SIEM
├─ raw/bundle.json   normalised evidence, UTC; re-analyse with -InputPath
├─ audit.log         every step the tool took, with timings
└─ manifest.json     written last: SHA-256 of every file, tool and rule hashes, parameters
```

Once the manifest is written the case is closed. `Test-WfxCase` detects any changed, missing or added
file. The manifest is not signed, so record its SHA-256 (printed at the end of each run) in your ticket or
evidence log.

---

## Safety boundaries

- **Read-only unless you respond.** Triage, Explore, hunting and analysis change no settings and execute nothing
  they find; their only writes are the case folder. Respond mode changes only what you confirm, records it
  first and can undo it (see [Respond](#respond-contain-what-you-found)).
  `Invoke-WfxTriage -Plan` shows what a triage will read before it reads anything.
- **Never elevates without asking.** The restart as administrator goes through the Windows prompt, runs without
  your PowerShell profile and with the execution policy you already have.
- **Secrets are audited, never extracted.** No LSASS dumping, no SAM/NTDS hash parsing, no DPAPI or browser
  decryption. Command lines and file contents are scrubbed of secrets at collection time.
- **No network traffic of its own.** Remote mode uses the WinRM session you start; `-ExposureScan` reads
  the domain SYSVOL share.
- PowerShell 7 itself sends anonymous start-up telemetry unless `POWERSHELL_TELEMETRY_OPTOUT=1` is set.
  Windows PowerShell 5.1 does not.
- Reading files can update NTFS last-access times. Write cases to external media for evidence work.

See [SECURITY.md](SECURITY.md).

### Antivirus warnings

The rule packs contain the names and command-line patterns of attacker tools so they can be detected, and the
tool reads security-sensitive locations. Heuristic scanners sometimes flag that. The code is plain, readable
PowerShell with no obfuscation, downloads or encoded payloads. **Do not turn off your antivirus.** Verify the
hashes, read the flagged file, and report the false positive to the vendor.

### Verifying the download

```powershell
Get-Content .\SHA256SUMS.txt | ForEach-Object {
  $h, $f = $_ -split '  ', 2
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash -ne $h) { "CHANGED: $f" }
}
```

No output means every file matches the release.

### Two packages

| Package | For | Contains |
|---|---|---|
| `WinForensicX-<version>.zip` | Investigators and CTF players | The toolkit, single-file build, rules, guide and examples |
| `WinForensicX-<version>-source.zip` | Developers and reviewers | All of the above plus `tests\` and the scenario suite |

The test data contains realistic attacker command lines as plain text, which antivirus engines often flag.
Nothing in it runs. If you only want to use the tool, take the main package.

---

## Tuning

- **Allowlist** (`-AllowlistPath`, `$env:WFX_ALLOWLIST`, or Settings in the menu): a JSON array of
  `{ "Id", "Entity", "Host", "Reason" }` with `-like` wildcards. Allowlisted findings stay visible in the
  report with their reason. Example: [`examples/allowlist.example.json`](examples/allowlist.example.json).
- **Custom rule packs** (`$env:WFX_RULES`): every rule is validated on load and every regex runs with a
  250 ms timeout. See [docs/RULES.md](docs/RULES.md).

---

## Testing

```powershell
Invoke-Pester ./tests                                                # unit and regression tests (in this repository)
pwsh -File tools/Invoke-WfxScenarioSuite.ps1 -OutputPath .\results   # source package only; add -SingleFile for dist\WinForensicX.ps1
Invoke-ScriptAnalyzer -Path ./WinForensicX -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
pwsh -File tools/build.ps1                                           # builds dist\WinForensicX.ps1
pwsh -File tools/build-guide.ps1                                     # builds docs\guide.html
```

The **scenario suite** ships in the source package, not in this repository, because its test data trips antivirus engines. It feeds synthetic evidence for ten scenarios through every workflow: a clean and a busy
admin workstation (false-positive controls), phishing malware, a LOLBin chain, a hands-on-keyboard intrusion,
credential theft, a multi-day APT ending in ransomware, malware-free lateral movement, ClickFix and AI-tool
abuse, and malformed or hostile evidence, now with execution artifacts in each. It also runs 42 evasion
variants against 15 benign look-alikes: 339 checks in all. It checks the report, manifest, tamper detection, timeline, hunt and Explore flags.
Nothing is executed; the evidence is data.

The artifact parsers are tested against hives, Jump Lists, shortcuts, compound files and SQLite databases
built byte by byte in the tests, and were cross-checked during development against independent parsers on
public test data (ShimCache and Amcache against regipy, shortcuts against LnkParse3, `$MFT` files against the
`mft` crate, ESE databases including SRUM against dissect.esedb). The `$MFT` and ESE readers were also
fuzzed with corrupted input. The STIX export is checked with the OASIS validator.

Collectors need real Windows. `Invoke-WfxSandboxEmulation.ps1` (shipped separately) plants harmless
look-alike artefacts **inside Windows Sandbox only**, checks each is flagged, and reverts them.

---

## Limitations

- Findings are **leads, not verdicts**. Read them with the *Not visible* section: without process auditing or
  Sysmon, "nothing found" often means "nothing could be seen".
- **Triage, not imaging.** No disk or memory acquisition, no carving of deleted files.
- Live: Amcache is locked by Windows and is reported as a gap (collect it with KAPE or a VSS copy and use
  `-ArtifactPath`). Prefetch, including Windows 10/11 compressed files, is fully parsed (run count, last
  eight run times, volumes, loaded files).
- Event logs are read by a built-in parser when the Windows event API is unavailable or cannot open a file
  (damaged or partly overwritten logs); that path has no rendered message text, only the event fields.
- The built-in event detections were measured on 278 public attack-sample logs (EVTX-ATTACK-SAMPLES):
  201 produce at least one finding. Live collection on Windows was not part of that measurement.
  SRUM is usually locked too and is then reported as a gap; a large SRUM database takes minutes to read.
  `$MFT` is read only from collected files; the tool never opens a raw volume.
- Deleted ESE records are skipped. Timestomping is checked only for programs in user-writable folders, and
  a tool that also rewrites the file-name times (by moving the file twice) is not detected.
- Event-log checks see only what was collected: a cleared log shows as a clear event or a gap, a log that
  rolled over by size shows as a shorter history, and neither proves tampering on its own.
- Explore views inspect only loaded user hives (logged-on users); `-ArtifactPath` reads every `NTUSER.DAT`
  and `UsrClass.dat` it is given. Event collection is capped per query, and a cap
  that is hit is reported as a gap.
- Detection is heuristic. Expect some false positives and false negatives; tune with the allowlist and
  custom rules.
- Live collection targets Windows 10/11 and Server 2016+. The 3.0 artifact collectors are verified with the
  Windows Sandbox script; parsing collected files is tested on every platform. Analysis, hunting, timelines, diffs and decoding
  also run on Linux and macOS with PowerShell 7.

## License

MIT. See [LICENSE](LICENSE).
