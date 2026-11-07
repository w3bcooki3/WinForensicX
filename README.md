# WinForensicX

**Read-only incident triage and investigation for Windows, in plain PowerShell.**

One command collects the state of a Windows host, checks it against detection rules mapped to MITRE ATT&CK,
and writes a case report you can hand to a colleague. Around that core is a toolkit for the rest of the job:
53 live views of the machine, IOC hunting, file triage, payload decoding, timelines and case diffing.

No install, no external modules, no network traffic of its own. Windows PowerShell 5.1 or PowerShell 7+.

![Case report: summary](docs/img/report-summary.png)

<sub>Sample report from a synthetic APT scenario (no real host): [`examples/sample-report.html`](examples/sample-report.html).</sub>

---

## Contents

- [Quick start](#quick-start)
- [The case report](#the-case-report)
- [Explore: live views with flags](#explore-live-views-with-flags)
- [Commands](#commands)
- [What it detects](#what-it-detects)
- [Case folder and chain of custody](#case-folder-and-chain-of-custody)
- [Safety boundaries](#safety-boundaries)
- [Tuning](#tuning)
- [Testing](#testing)
- [Limitations](#limitations)

---

## Quick start

1. **Download and extract the whole archive.** Optionally [verify the hashes](#verifying-the-download).
2. **Open PowerShell as administrator** (Start → type *PowerShell* → *Run as administrator*). Admin rights
   give access to the Security log, every process, Prefetch, the NTFS change journal and BitLocker state.
   Without them the tool still runs and lists what it could not see.
3. **Start it from that window:**

   ```powershell
   cd "$HOME\Downloads\WinForensicX-2.6.0"
   .\Start-WinForensicX.ps1
   ```

   | If PowerShell says | Do this |
   |---|---|
   | *running scripts is disabled on this system* | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then run it again. It applies to this window only. |
   | *…is not digitally signed* | The files still carry the downloaded-from-the-Internet mark. After checking the hashes: `Get-ChildItem -Recurse \| Unblock-File`. |

   > Right-click → **Run with PowerShell** is not supported: it never runs as administrator and closes the
   > window as soon as PowerShell refuses, so all you see is a window flashing open and shut.

4. **Pick from the menu:**

   ```
     1  Investigate this computer    triage: find signs of compromise and get a report
     2  Explore this computer        53 live views: what changed recently, users, software, network, USB...
     3  Hunt & analyze               IOC hunting, file triage, decode payloads
     4  Cases & evidence             open reports, verify, timeline, compare
     5  Live monitor                 watch new processes / connections as they happen
     6  Settings                     output folder, look-back, allowlist, custom rules
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
| **Summary** | A verdict in words, a numbered *Do first* list with the action for each item, the suspicious-activity window, accounts involved, external addresses, compromise risk and hardening scores. |
| **Attack path** | Findings placed on the ATT&CK lifecycle, earliest stage first, with the time each stage was first seen. |
| **Findings** | Sortable and filterable by severity, stage and area. Each row opens to show why it matters, what to do, the evidence, the rule and source, and **everything else that happened within 30 minutes**. |
| **Indicators** | IPs, domains, URLs, hashes, files, registry keys and accounts pulled from attacker-related findings. Defang for sharing, copy, or download as CSV. |
| **Timeline / Changes** | Findings and recent changes grouped by day; CSV export. |
| **ATT&CK** | Technique matrix, with a layer you can load into MITRE ATT&CK Navigator. |
| **Not visible** | Collection gaps and allowlisted findings, so "nothing found" is never mistaken for "nothing there". |
| **Custody** | Case ID, operator, parameters and hashes, with the `Test-WfxCase` command to verify the folder. |

Dark mode, phone width and print are supported. CSV exports neutralise spreadsheet formulas.

![A finding opened: evidence and related events](docs/img/report-finding.png)

---

## Explore: live views with flags

Instant, read-only answers without a full triage. Every view can be filtered, opened as a sortable table in
the browser, exported to CSV, or saved all together as a hashed inventory report.

Views that can show attacker activity run the same analyzers as triage over each row and add **Flag**
(CRITICAL / HIGH / MEDIUM / LOW), **Why**, **Technique** and **Rule**. **S** shows flagged rows only.

![Flagged rows in an Explore view](docs/img/flagged-view.png)

| Group | Views |
|---|---|
| **Recent changes** | Combined timeline; registry writes in persistence and security keys; NTFS change journal (created, deleted, modified, renamed, alternate streams, timestamps); deleted files (Recycle Bin, Sysmon); software and driver installs; programs that ran (Prefetch, BAM, UserAssist); connection history; security configuration changes |
| System | Overview, updates, software, users, privileged groups, sessions, profiles, shares, USB history, drives and BitLocker |
| Processes | All processes (signer, owner, parent, command line), process tree, unsigned or user-folder programs |
| Network | Listening ports, connections (named from the DNS cache), DNS cache, adapters, routes, ARP, hosts file, proxy, Wi-Fi profiles, firewall rules, SMB sessions |
| Persistence | Autostarts, non-standard services and drivers, scheduled tasks, WMI subscriptions |
| Events | Logons, failed logons, RDP, account and group changes, new services, cleared logs, reboots and crashes, suspicious PowerShell, Defender detections |
| Files | Downloads with source URL, new programs in user folders, Prefetch, recent files, PowerShell history (redacted), Run-dialog history |
| Security | Posture checklist (AV, tamper protection, firewall, UAC, LSA, Credential Guard, WDigest, SMBv1, LLMNR, logging, Sysmon, RDP NLA, auto-logon, patch age) with fixes |

**How "recent changes" works with no prior monitoring:** Windows already keeps the evidence. Registry keys
have last-write times, the NTFS change journal records file operations, the Recycle Bin keeps original
paths and deletion times, Prefetch/BAM/UserAssist record program runs, and the event logs record installs,
services, tasks, accounts and policy changes. Sources that are not enabled (Sysmon, WFP auditing, the
firewall log) are reported as gaps.

---

## Commands

| Command | Purpose |
|---|---|
| `Invoke-WfxTriage` | Collect → analyze → score → report. **Local**, **remote** (`-ComputerName`, WinRM), **offline** (`-EvtxPath`) or **re-analyze** (`-InputPath`). |
| `Save-WfxEvidence` | Collect a hashed evidence bundle now; analyze later, anywhere. |
| `Invoke-WfxAnalyze` | Run every analyzer over a bundle. Runs on Windows, Linux and macOS. |
| `Get-WfxInsight` / `Save-WfxInsight` | The 53 live views / export them all as a hashed inventory report. |
| `Get-WfxActivity` | What changed recently; `-Journal` adds the NTFS change journal. |
| `Invoke-WfxHunt` | Sweep a host or saved case for IOCs (hashes, IPs, domains and subdomains, strings), including event logs. Accepts defanged values and IOC files. |
| `Get-WfxFileTriage` | "What is this file?" Hashes, true type vs. extension, entropy, download URL (Mark of the Web), alternate streams, signer, PE facts, strings and IOCs. Never executes it. |
| `ConvertFrom-WfxEncodedCommand` | Decode `-EncodedCommand`, Base64, gzip and nested `FromBase64String` payloads, then run the rules over the result. |
| `Export-WfxTimeline` | UTC super-timeline of a case to CSV or JSON. |
| `Compare-WfxCase` | Diff two cases: new processes, autostarts, services, listeners, DNS names, findings. |
| `New-WfxFileBaseline` / `Compare-WfxFileBaseline` | File-integrity baseline for chosen folders. |
| `Test-WfxCase` | Re-hash a case against its manifest: changed, missing or added files. |
| `Start-WfxMonitor` | Live baseline, then alerts on new suspicious processes, connections and beaconing. |
| `Show-WfxMenu` / `Show-WfxHelp` | The menu; help in the terminal or (`-Html`) in the browser. |

```powershell
Invoke-WfxTriage -OutputPath E:\cases                              # triage this host to external media
Invoke-WfxTriage -FileScan -ExposureScan -OutputPath E:\cases      # plus web roots, drop folders, exposed secrets
Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)
Invoke-WfxTriage -EvtxPath D:\evidence\logs                        # exported .evtx only
Invoke-WfxTriage -InputPath .\WFX_PC01_20261103-101500Z -AllowlistPath .\allowlist.json

Invoke-WfxHunt -Ioc 'evil[.]example','203.0.113.7' -InputPath .\case
Get-ChildItem $env:USERPROFILE\Downloads -File | Get-WfxFileTriage | Where-Object ExtensionMismatch
ConvertFrom-WfxEncodedCommand 'powershell -nop -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAaQAnAA=='
Compare-WfxCase -Baseline .\golden -Current .\today | Where-Object Change -eq 'Added'
```

---

## What it detects

| Area | Examples |
|---|---|
| **Command lines** (49 rules) | Encoded PowerShell (decoded and re-scanned), download cradles, AMSI tampering, LOLBin proxy execution (certutil, mshta, regsvr32, rundll32, MSBuild …), LSASS dumping, hive and NTDS export, Kerberoasting, shadow-copy deletion, log clearing, port proxies, SSH tunnels, ClickFix lures. Matched on the original **and** a normalised form, so carets, en-dashes, split quotes and `/switch` spellings do not evade them. |
| **Processes** | System-name masquerading, renamed interpreters, parent spoofing, Office or browsers spawning shells, unsigned programs in user folders, offensive and remote-management tools, AI agents |
| **Persistence** | Run keys, Startup, services, drivers (including known-vulnerable BYOVD drivers), tasks, WMI, Winlogon, AppInit, IFEO, LSA packages, COM hijacks |
| **Event logs** (20 rules) | Spraying and brute force (including spray-then-success by source), log clearing, new services and tasks, 4688 / Sysmon 1 command lines, 4104 script blocks, account and group changes, external RDP, Defender detections and tampering, LSASS access |
| **Network and DNS** | Listeners on all interfaces, tunnels (ngrok, Cloudflare …), C2 ports, DGA-like names, risky TLDs, paste sites, beaconing |
| **Files** (`-FileScan`) | Web shells, double extensions, downloaded executables, packed binaries, ransom notes, mass encryption |
| **Exposed secrets** (`-ExposureScan`) | GPP passwords, unattend files, readable SAM/SYSTEM (HiveNightmare), cloud and API keys, unencrypted SSH keys. Reported redacted to *type + length*. |
| **Recent activity** | Defender exclusions, hijack keys, weakened LSA/WDigest, timestomping, time changes, mass deletion or modification bursts |
| **Posture** | AV state, tamper protection, auditing, Sysmon, firewall, RDP without NLA, LSASS protection |

**Two scores.** *Compromise risk* comes only from evidence of attacker activity; *posture* comes from
hardening and visibility gaps. A clean but unhardened host shows low risk, not "compromised". Both use
`1 − Π(1 − wᵢ/40)`, so a pile of weak leads cannot add up to a critical.

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

- **Read-only.** It changes no settings and executes nothing it finds. Its only writes are its own case folder.
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
Invoke-Pester ./tests                                                # 120 tests, including the scenario suite
pwsh -File tools/Invoke-WfxScenarioSuite.ps1 -OutputPath .\results   # add -SingleFile to test dist\WinForensicX.ps1
Invoke-ScriptAnalyzer -Path ./WinForensicX -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
pwsh -File tools/build.ps1                                           # builds dist\WinForensicX.ps1
pwsh -File tools/build-guide.ps1                                     # builds docs\guide.html
```

The **scenario suite** feeds synthetic evidence for ten scenarios through every workflow: a clean and a busy
admin workstation (false-positive controls), phishing malware, a LOLBin chain, a hands-on-keyboard intrusion,
credential theft, a multi-day APT ending in ransomware, malware-free lateral movement, ClickFix and AI-tool
abuse, and malformed or hostile evidence. It also runs 42 evasion variants against 15 benign look-alikes:
328 checks in all. It checks the report, manifest, tamper detection, timeline, hunt and Explore flags.
Nothing is executed; the evidence is data.

Collectors need real Windows. `Invoke-WfxSandboxEmulation.ps1` (shipped separately) plants harmless
look-alike artefacts **inside Windows Sandbox only**, checks each is flagged, and reverts them.

---

## Limitations

- Findings are **leads, not verdicts**. Read them with the *Not visible* section: without process auditing or
  Sysmon, "nothing found" often means "nothing could be seen".
- **Triage, not imaging.** No disk or memory acquisition, no carving of deleted files.
- Only loaded user hives (logged-on users) are inspected. Event collection is capped per query, and a cap
  that is hit is reported as a gap.
- Detection is heuristic. Expect some false positives and false negatives; tune with the allowlist and
  custom rules.
- Live collection targets Windows 10/11 and Server 2016+. Analysis, hunting, timelines, diffs and decoding
  also run on Linux and macOS with PowerShell 7.

## License

MIT. See [LICENSE](LICENSE).
