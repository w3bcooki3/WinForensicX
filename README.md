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

## ▶ Start here (30 seconds)

1. **Download and extract** the whole archive (not just one file). Optionally check the files against
   `SHA256SUMS.txt` (see [Verifying the download](#verifying-the-download)).
2. Open **Windows PowerShell** with **Run as administrator** (Start → type *PowerShell* → *Run as
   administrator*). Administrator rights let it read the Security log, every process, Prefetch, the NTFS
   change journal and BitLocker state; a normal window works with less visibility.
3. Go to the extracted folder and start it:
   ```powershell
   cd "$HOME\Downloads\WinForensicX-2.6.0"
   .\Start-WinForensicX.ps1
   ```
   If PowerShell refuses, the message says why:

   | Message | What to do |
   |---|---|
   | *running scripts is disabled on this system* | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then run it again. Applies to **this window only**; nothing on the system changes. |
   | *…is not digitally signed* | The files still carry the "downloaded from the Internet" mark. After checking the hashes, remove it with `Get-ChildItem -Recurse \| Unblock-File`, or use the same process-only command above. |

   > **Why not right-click → "Run with PowerShell"?** That shortcut first asks *"Do you want to change the
   > execution policy?"* with **No** as the default, never runs as administrator, and closes the window the
   > moment PowerShell refuses — so you see a window flash and disappear. Start it from a PowerShell window
   > as above.
4. Use the menu:

```
  ── Main menu ───────────────────────────────────────────────────
   1  Investigate this computer    triage: find signs of compromise and get a report
   2  Explore this computer        53 live views: what changed recently, users, software, network, USB...
   3  Hunt & analyze               IOC hunting, file triage, decode payloads
   4  Cases & evidence             open reports, verify, timeline, compare
   5  Live monitor                 watch new processes / connections as they happen
   6  Settings                     output folder, look-back, allowlist, custom rules
   H  Help & guide                 what everything does, in a browser page
   Q  Quit
```

Every submenu explains each option on the same line. **B** goes back and **Q** quits from anywhere.
Paths are checked before anything runs. Results (cases, CSV exports) go to `Desktop\WinForensicX` unless you
change the output folder in **Settings**; use an external drive for real evidence work.

**Using the commands directly:** `Import-Module .\WinForensicX\WinForensicX.psd1` to use the commands directly. The portable single file is
`dist\WinForensicX.ps1`.

### Two packages

| Package | For | Contains |
|---|---|---|
| `WinForensicX-<version>.zip` | Investigators, CTF players: **use this** | The toolkit, single-file build, rule packs, guide, examples. |
| `WinForensicX-<version>-source.zip` | Developers and reviewers | Everything above **plus** `tests\`: unit tests and the attack-scenario suite. |

The test data in the source package contains realistic attacker command lines (download cradles, ClickFix
lures, encoded PowerShell, credential-dumping commands) as plain text, so the detections can be tested. Heuristic
antivirus engines often flag such files. Nothing in them runs; they are inputs to the analyzers. If you only want
to use the tool, take the main package.

### Verifying the download

```powershell
Get-Content .\SHA256SUMS.txt | ForEach-Object {
  $h, $f = $_ -split '  ', 2
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash -ne $h) { "CHANGED: $f" }
}
```
No output means every file matches the release.

### Antivirus warnings

WinForensicX is a forensics tool: its rule packs *contain* the names and command-line patterns of attacker
tools (mimikatz, wscript, encoded PowerShell …) so it can detect them, and it reads security-sensitive places
(event logs, Run keys, the NTFS journal). Heuristic scanners sometimes flag that. The code is plain, readable
PowerShell with no obfuscation, no downloads, no encoded payloads and nothing that runs on its own. If your
antivirus blocks it: **do not turn the antivirus off.** Check the hashes above, read the flagged file, and
report the false positive to the vendor (e.g. Avast: <https://www.avast.com/false-positive-file-form.php>).

### Which files are which

| File / folder | What it is |
|---|---|
| `Start-WinForensicX.ps1` | **Run this.** Loads the module and opens the menu. It never elevates or relaunches itself and never changes the execution policy. |
| `SHA256SUMS.txt` | SHA-256 of every file in the release, to check nothing was altered. |
| `WinForensicX\` | The module (all source code and rule packs). |
| `dist\WinForensicX.ps1` | Everything in one file, for copying to a USB stick or a remote host. |
| `docs\guide.html` | **The field guide**: investigations step by step, how to read the flags, every view and command. Opens with **H** in the menu. |
| `tools\`, `docs\`, `examples\` | Build scripts, rule-writing guide, sample report and allowlist. |
| `tests\` | **Source package only** (see [Two packages](#two-packages)): unit tests and the attack-scenario suite. |

### Explore: live views of the computer

Instant, read-only answers without a full triage. Each view can be filtered, opened in a sortable browser table (offline, works in Windows Sandbox and Server Core)
and exported to CSV, or exported all together as a hashed **inventory report** (HTML + CSVs).

**Suspicious rows are flagged.** Views that can show attacker activity run the same analyzers as triage over
every row and add **Flag** (CRITICAL / HIGH / MEDIUM / LOW), **Why** (each reason in plain words),
**Technique** (MITRE ATT&CK) and **Rule** (the rule ID, for the allowlist). Flagged rows are coloured in the
console, **S** shows them alone, and the inventory report opens with every flagged item across all views.
Examples: encoded or hidden PowerShell, Office spawning a shell, a known credential-theft tool in Prefetch, an
executable dropped in a Startup folder, `invoice.pdf.exe`, a deleted event log, a Defender exclusion, a new
local admin, a hosts-file override of a security vendor, remote-access software, a connection to port 4444.
A flag is a lead, not a verdict; a view without flags is not proof the host is clean.

| Group | Views |
|---|---|
| **Recent changes** | everything that changed (combined timeline), registry writes in persistence & security keys, file system changes from the NTFS change journal (created / deleted / content changed / renamed / alternate streams / timestamps), deleted files (Recycle Bin + Sysmon), software & driver installs/removals, programs that ran (Prefetch, BAM, UserAssist), connection history (Sysmon 3, WFP 5156, firewall log, live, saved RDP targets), security-relevant config changes (accounts, tasks, audit policy, firewall rules, Defender, time changes, log clearing, BITS, WMI) |
| System | overview, installed updates, installed software, local users, privileged groups, logged-on sessions, profiles, shares, USB storage history, drives & BitLocker |
| Processes | all processes (signer, owner, parent, command line), process tree, unsigned / user-folder programs |
| Network | listening ports, active connections (named from DNS cache), DNS cache, adapters, routes, ARP, hosts file, proxy, saved Wi-Fi names, custom firewall rules, SMB sessions |
| Persistence | autostarts, non-standard services, non-standard drivers, non-Microsoft scheduled tasks, WMI subscriptions |
| Events | logon summary, failed logons, RDP activity, account & group changes, installed services, cleared logs, reboots/crashes, suspicious PowerShell, Defender detections |
| Files | recent downloads with source URL, new programs/scripts in user folders, Prefetch execution history, recently opened files, PowerShell history (redacted), Run-dialog history |
| Security | posture checklist (AV, tamper, firewall, UAC, LSA, Credential Guard, WDigest, SMBv1, LLMNR, logging, Sysmon, RDP NLA, auto-logon, patch age) with fixes |

From PowerShell: `Get-WfxInsight -List`, `Get-WfxInsight logons -Days 3`, `Save-WfxInsight`, `Get-WfxActivity -Days 2 -Journal`.

**How "recent changes" works without prior monitoring.** Windows already keeps the evidence; WinForensicX reads it.
Registry keys carry a last-write time, and the NTFS change journal records file creates, deletes and writes.
The Recycle Bin keeps original paths and deletion times. Prefetch, BAM and UserAssist record program runs. The
event logs record installs, services, tasks, accounts, firewall and Defender changes. Sysmon, the Windows
Filtering Platform audit (5156) and the firewall log, *when enabled*, record connections. What isn't enabled is
reported as a gap. For continuous file-integrity checking of specific folders, use **Hunt & analyze → Take a
file-integrity baseline** (`New-WfxFileBaseline` / `Compare-WfxFileBaseline`).

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
| `Get-WfxInsight` / `Save-WfxInsight` | 45 live read-only views of the host (see above) / export them all as a hashed inventory report. |
| `Test-WfxCase` | Verify a case: re-hash every file against its manifest and flag changed, missing or added files. |
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
| **Recent activity** | Defender exclusion / policy keys changed, IFEO / SilentProcessExit / UAC-bypass handler keys changed, autostart keys changed, WDigest/LSA weakened, remote-access tool installed, PsExec-style or user-path services installed, firewall changed by a non-system program, audit policy changed, logs cleared, Defender disabled, timestomping, system time changed, BITS downloads from unusual hosts, permanent WMI subscriptions, programs run from user folders, executables dropped in staging folders, alternate data streams, **mass deletion / mass modification bursts** (ransomware, wipers) |
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

### Option A — single file (`dist\WinForensicX.ps1`)
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
Invoke-Pester ./tests          # 120 tests incl. the attack-scenario suite below (any OS)
Invoke-ScriptAnalyzer -Path ./WinForensicX -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
pwsh -File tools/build.ps1     # deterministic single-file build → dist/WinForensicX.ps1
pwsh -File tools/build-guide.ps1   # docs/guide.html from the template + the tool's own help and view table
```

### Attack-scenario suite

`tools/Invoke-WfxScenarioSuite.ps1` runs synthetic evidence for ten scenarios through every workflow:
a clean and a busy-admin workstation (false-positive controls), commodity phishing malware, a LOLBin download
chain, a hands-on-keyboard intrusion, credential theft, a multi-day APT chain (ISO lure → persistence → C2 →
anti-forensics → ransomware), malware-free lateral movement, ClickFix and AI-tool abuse, and malformed/hostile
evidence. For each it checks the expected and forbidden detections, report, manifest and tamper detection,
timeline, IOC hunt and the Explore-view flags. It also runs 42 command-line evasion variants (carets, en-dash
parameters, renamed PowerShell, alternate cradles, slash switches…) against 15 benign look-alikes, and the
case diff, file baseline, file triage, decoder, live monitor and inventory workflows. Nothing is executed;
the evidence is data. `-SingleFile` tests the built `dist\WinForensicX.ps1`; the run writes
`scenario-results.json` and a readable `scenario-report.html`.

```powershell
pwsh -File tools/Invoke-WfxScenarioSuite.ps1 -OutputPath .\scenario-results
```

Testing the Windows collectors needs real Windows: a separate script, `Invoke-WfxSandboxEmulation.ps1`
(distributed separately from the toolkit), creates harmless look-alike artefacts **inside Windows Sandbox only**,
checks that each is flagged, and reverts them.

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
