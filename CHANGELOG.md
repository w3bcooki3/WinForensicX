# Changelog

## 3.3.0 — parser accuracy and event detections

### Parsers
- **Event logs (.evtx)** are read by a built-in parser on every platform, and on Windows whenever the event
  API cannot open a file. It handles damaged chunks (checked by CRC), files without a header, inline and
  shared templates, arrays, embedded Sysmon data and classic unnamed parameters, and recovers older
  records from unused space (marked `Recovered`, reported as a gap). Checked record by record against
  libevtx on 37,364 records from 278 public attack-sample logs.
- **Prefetch** versions 17, 23, 26, 30 and 31, including Windows 10/11 compressed files (XPRESS Huffman):
  run count, the last eight run times, volumes and loaded files. The program's full path is taken from
  the loaded-file list. The timeline has one entry per run. Matches libscca on 62 of 62 test files.
- **SQLite** applies the `-wal` file (committed frames only), handles quoted names, table-level primary
  keys, defaults and REAL affinity. 1,128 tables match the SQLite library.
- **Shell items:** users property views, property stores, ZIP folders and many more known folders. 16,031
  items match libfwsi.
- **Registry:** ShimCache and BAM/DAM are read from every control set (entries only in an older control set
  are marked), UserAssist handles Windows XP entries and skips counter entries, string values stop at the
  first NUL. 1,170,935 keys match libregf.
- **Sigma YAML:** comments, escapes, multi-line scalars and block scalars follow the YAML spec;
  3,779 of 3,779 SigmaHQ rules parse identically to PyYAML.
- Damaged input never stops a triage: fuzzing every parser with corrupted files found three numeric
  overflows in the browser-history reader, now fixed.

### Detections
- Event rules can now test individual fields (`match`, `matchNot`, `differ`) with alternatives such as
  `Image|NewProcessName`, so one rule covers Sysmon and Security events. Titles name the actual program,
  key or account.
- 47 new rules, among them: DCSync (4662), DSRM password change, SID history, boot debugging/test signing,
  GetSystem pipe services, bare-command services, PsExec/Impacket pipes and executables copied to admin
  shares (5145), tunnelled RDP, KrbRelayUp, pass-the-hash logons, LSASS handle requests (4656/4663),
  silent-process-exit LSASS dumps, NTDS copies, xp_cmdshell, process tampering, WMI subscriptions,
  unsigned drivers, remote threads, shellcode handle access, credential-dump files, Startup drops,
  sideloaded and planted DLLs, Office and server processes starting shells, WMI execution, UAC bypasses
  (auto-elevating parents and hijacked registry keys), masquerading and renamed binaries, weakened
  security settings, persistence keys, SAM/LSA secret edits, port proxies, MRU wiping, potato/PsExec
  pipes, suspicious BITS downloads, accessibility shims, Winsock LSPs, BlueKeep probes and stopped
  logging services.
- More events are collected (Security 4656, 4662, 4663, 4703, 4765, 4766, 4794, 4826, 5136, 5145;
  System 7036; Application ESENT, SQL Server and WER events; Sysmon 2, 6, 12, 17–21, 25; BITS, shim,
  Winsock and RDP core events), each with its own cap.
- On the 278 public attack-sample logs, files with at least one finding rose from 84 to 201.

## 3.2.0 — process trees, log integrity, $MFT, SRUM, fleet movement

### Added
- **Process trees.** Parent-child chains rebuilt from Sysmon process events (by process GUID), 4688 events
  (by process ID and start time, so a reused ID is not taken for the parent) and the live process list.
  Findings about a process carry their ancestry (up to twelve levels, with command line, user and the source
  of each step) and the case file shows it as a tree.
- **Event-log integrity:** the clock set back while a log was recording (`LOG-TIME-BACKWARDS`), a busy
  Security or Sysmon log falling silent for six hours or more while other logs kept recording
  (`LOG-SILENT-GAP`), Sysmon stopped (`LOG-SYSMON-STOPPED`) or reconfigured (`LOG-SYSMON-CONFIG`). Sysmon
  events 4 and 16 are now collected.
- **`$MFT` parsing** from collected files (`Get-WfxArtifact -Path`, `-ArtifactPath`): programs, scripts,
  archives and shortcuts with full paths, deleted records, alternate data streams and the download origin
  from `Zone.Identifier`. Handles update-sequence fixups (including torn records), extension records and
  orphaned files. **Timestomp detection** (`ART-TIMESTOMP`) compares standard-information and file-name
  times for programs in user-writable folders.
- **SRUM** (`SRUDB.dat`) through a new read-only ESE database reader: bytes sent and received, and written
  and read, per program and user. **Large uploads** by exfiltration tools or by programs that do not usually
  upload are reported (`ART-SRUM-UPLOAD`).
- **Fleet report:** movement between hosts from each host's remote logons in and remote access out,
  matched by host name or by addresses that belong to one host only; machines in those records that were
  not triaged; programs recorded on only one host when three or more hosts are compared. `result.json` now
  carries compact `Programs`, `Logons` and `Addresses` summaries for this, and host information records the
  host's own addresses.

### Tests
- Engine tests (`tests/Engine.Tests.ps1`) build event logs, `$MFT` files and ESE databases byte by byte.
  The `$MFT` reader was cross-checked during development against an independent parser on four public test
  images, and the ESE reader against another on three public databases.

## 3.1.0 — redesigned report, corroboration

### Tests
- **Case report redesigned.** A masthead with the host, verdict and case details; a summary that says what
  happened first and last; a chart of when it happened (one row per ATT&CK stage, incidents shaded, zoom to
  an incident). Each finding opens as a case file: what happened, when, how we know (source, process chain,
  marked command line, evidence, independent sources), what to do. Print gives a cover page, every case
  file, running headers and page numbers. All times are now UTC.
- **Explore views in the browser** use the same design: a summary of flagged rows, filters by flag and by
  the main columns, a column picker, a side panel with every field of a row, CSV of exactly what is shown.
- Fleet report, in-tool help and the field guide share the same look and mark.

### Added
- **Corroboration.** Findings record which independent sources (Amcache, Prefetch, Sysmon, 4688, service
  installs, Defender, autostarts, running processes, the change journal) also saw the same program, with
  the earliest trace. Two or more raise confidence one level, and the report says why.
- **Likely starting point** for each incident.
- ATT&CK names for phishing (T1566, .001, .002) and drive-by compromise (T1189).

### Fixed
- Paths stored as `%SystemRoot%\...` (UserAssist, shortcuts) were flagged as system programs in the wrong
  folder.

## 3.0.0 — evidence of execution, Sigma, YARA, incidents and exports

### Added
- **Execution and user-activity artifacts** (`Get-WfxArtifact`, `Invoke-WfxTriage -ArtifactPath`,
  `Invoke-WfxHunt -ArtifactPath`): Amcache (files with SHA-1, programs, drivers), ShimCache (Windows 7 – 11),
  Prefetch, BAM, UserAssist, PCA (Windows 11), ShellBags, Jump Lists (automatic and custom), shortcut files,
  RunMRU, typed paths, Explorer searches, Chromium and Firefox download history, and Defender support logs.
  Read from the live host, or from a folder of collected files (KAPE, Velociraptor, a mounted image).
  Files are recognised by content. Dirty hives are repaired in memory from their `.LOG1/.LOG2`.
- Parsers written from the specifications in plain PowerShell: registry hive (regf), compound file (CFB),
  shell link, shell items and SQLite. Nothing is loaded into the registry or executed.
- **Artifact detections:** offensive, exfiltration and remote-management tools, system-name masquerading,
  execution from staging folders, known-vulnerable drivers, Defender detections from support logs, risky and
  offensive downloads, admin-share and removable-drive access, sensitive searches. Shortcut and Jump List
  arguments and Run-dialog commands go through the command-line rules.
- **Sigma** (`-SigmaPath`, `WFX_SIGMA`, menu Settings): a rule compiler for Sigma YAML, with field modifiers,
  full conditions, 4688-to-Sysmon field mapping and literal pre-filters. Rules extend event collection with
  the IDs they need. Rules that cannot run are listed as a gap with the reason.
- **YARA** (`-YaraRules`, `WFX_YARA`): runs your own `yara` executable over process, autostart, file and
  artifact paths, or over an `-ArtifactPath` folder.
- **Incidents:** findings grouped by shared files, accounts and addresses in time, with the reason for each
  link. New report section.
- **Report:** *Incidents* and *Evidence of execution* sections (filters, CSV, links to findings).
- **Explore:** new *Evidence of execution* group (what ran, user activity, browser downloads, Defender logs):
  57 views.
- **`Export-WfxCase`:** Timesketch CSV, Elastic Common Schema NDJSON, STIX 2.1 bundle (deterministic ids,
  validated with the OASIS validator) and indicator CSV.
- **`New-WfxFleetReport`:** one offline page across many cases.
- Menu: evidence-folder triage, artifact parsing and hunting, export, fleet report, Sigma and YARA settings.
- Field guide: three new walk-throughs (what ran, a KAPE collection, many hosts).

### Fixed
- Collection gaps could be nested arrays in `result.json`.
- Secret scrubbing is about ten times faster on large collections (a pre-filter before the full patterns).

## 2.6.0 — case report redesign

### Tests
- **Case report (`report.html`) rewritten** as a plain, document-style report that reads top to bottom and
  prints cleanly:
  - **Summary:** a verdict in words (compromise indicated / likely, suspicious activity, no strong
    indicators), a numbered *Do first* list (deduplicated), the suspicious-activity window, accounts
    involved, external addresses and the hardening score.
  - **Attack path:** findings placed on the ATT&CK lifecycle, earliest stage first, with the time each stage
    was first seen.
  - **Findings:** a sortable table filterable by severity, stage and area. Each row opens to show why it
    matters, what to do, the evidence fields, the rule and source, and every other event within 30 minutes.
  - **Indicators:** IPs, domains, URLs, hashes, files, registry keys and accounts extracted from the
    attacker-related findings, with defang-for-sharing, copy and CSV. Private addresses and stock Windows
    binaries are hidden by default.
  - **Timeline** grouped by day (CSV export), the **Changes** table, and an **ATT&CK** matrix with a
    MITRE ATT&CK Navigator layer download.
  - **Not visible** (collection gaps and suppressed findings), **custody** (case ID, operator, parameters,
    hash) with the `Test-WfxCase` command to verify it.
  - Dark mode, print and narrow (phone) layouts. The printed copy leaves out the full change list (it is
    in the CSV and `raw/bundle.json`).
- The report now has a strict Content-Security-Policy (no network access, no external resources). Every
  evidence value is escaped, and CSV exports neutralise spreadsheet formulas.

### Fixed
- Font ligatures and contextual alternates could render evidence text incorrectly (for example `3x9`
  shown as `3×9`) in all HTML outputs. They are now disabled everywhere.
- Report header showed no OS when the bundle used the `OS` property; timestamps carried milliseconds.
- *Accounts involved* could list process paths; only account-shaped values are kept.

## 2.5.0 — automated attack-scenario testing

### Added
- **Attack-scenario suite** (`tools/Invoke-WfxScenarioSuite.ps1`, part of `Invoke-Pester ./tests`): ten
  scenarios from a clean host to a multi-day APT chain, 42 evasion variants, 15 benign look-alikes and every
  workflow; 324 checks; writes `scenario-results.json` and `scenario-report.html`. Synthetic evidence only.
- **Windows Sandbox emulation** (`Invoke-WfxSandboxEmulation.ps1`, shipped separately): harmless look-alike
  artefacts on real Windows, checked and reverted; refuses to run outside Windows Sandbox.
- `PROC-RENAMED-INTERPRETER`: an encoded PowerShell payload run by a program not named PowerShell (T1036.003).
- AI coding assistants installed as npm/pip packages (Claude Code, Codex CLI, Gemini CLI, Aider, OpenHands …)
  are recognised from the node/python command line.

### Fixed (found by the suite)
- Command-line rules missed common obfuscation: en/em-dash parameters (`–enc`), cmd caret escapes
  (`p^o^w^e^r^s^h^e^l^l`), empty-quote splitting (`p""owershell`) and `/switch` spellings (`certutil /urlcache`).
  Rules now also match the canonical form of each command line; evidence keeps the original text.
- `EVT-RDP-EXTERNAL` fired on local logons whose address is `-` (every unlock), even on clean hosts.
- A password spray followed by a successful logon for a *different* sprayed account from the same source was not
  correlated; `EVT-4625-THEN-4624` now also correlates by source address.
- One malformed field (e.g. a non-numeric event ID) in saved evidence aborted the whole analysis; such records
  are now skipped.
- Explore views did not flag activity whose target is empty (e.g. Defender real-time protection disabled).
- PowerShell-history wiping was matched on a parameter that does not exist; now matched as it is really done
  (`-HistorySaveStyle SaveNothing`, `Remove-Item (Get-PSReadlineOption).HistorySavePath`).
- cloudflared tunnels (`*.argotunnel.com`) were not recognised as a tunnelling service.
- All HTML outputs disable font ligatures and contextual alternates, so text such as `kq3x9` can never render
  as `kq3×9` in an indicator.

### Packaging
- Released as two packages: the toolkit (no test data) and a `-source` package that adds `tests\`. Test
  fixtures contain attacker command lines as text, which heuristic antivirus engines flag (Avast reported
  `LNK:Downloader-AD` for the 2.5.0 download, although no shortcut file exists in it).

### Documented gaps (by design, listed in the scenario report)
- DLL side-loading by a validly signed program in a user folder (loaded DLLs are not collected).
- Exfiltration volume (no data-transfer telemetry); internal RDP by a valid account without correlation;
  admin-share access is logged on the target, not the source.

## 2.4.0 — suspicious-activity flags, field guide

### Added
- **Flags in Explore views.** 35 views mark suspicious rows with Flag / Why / Technique / Rule. Analyzer-backed
  views (processes, connections, listeners, DNS, autostarts, services, drivers, every *Recent changes* view) run
  the same analyzers as triage, so a view and a report never disagree; the others get focused checks
  (scheduled tasks, WMI consumers, PowerShell history and 4104 script blocks, new services, cleared logs, failed
  logons, account changes, RDP from public addresses, Defender detections, hosts file, firewall, Prefetch,
  downloads, new programs, installed software, users, shares). Command text is checked in full, before it is
  shortened for display. Flagged rows are coloured in the console, **S** shows only them, bursts (mass delete /
  rename) are shown as patterns. The triage allowlist (menu setting or `$env:WFX_ALLOWLIST`) applies to views.
- **Inventory report** opens with every flagged item across all views, ranked by severity.
- New activity detections: file in a Startup folder, double extension (`.pdf.exe`), ransom-note names, short-lived
  executables, deleted event logs and PowerShell history, offensive / remote-access tools executed (Prefetch,
  BAM, UserAssist), Defender exclusions, malware detections, new accounts, privileged-group additions, scheduled
  tasks with attack-technique commands, outbound connections to C2-typical ports.
- **Field guide** `docs/guide.html` (offline, one file): start-up, menu map with exact keys, how to read flags,
  seven investigation walkthroughs, all 53 views and all commands. Reference sections are generated from the
  tool's own help model and view table (`tools/build-guide.ps1`), so they match the code. **H** opens it.

### Fixed
- Activity rules that had stopped matching after 2.3.2 renamed journal actions: alternate-data-stream writes,
  mass rename (ransomware), Sysmon executable creation.
- Deleted `.evtx` files were hidden by the journal's noise filter.
- The allowlist read by views was nested one level too deep, so multi-entry allowlists would not have matched.
- `New-WfxCase` now stops with one clear message when the output folder cannot be created (it used to continue
  and cascade errors).
- Browser view: short values no longer break mid-word; wide tables scroll instead of crushing columns.
- Removed two malformed entries from the remote-access tool list (`" scinstaller"`, `"mmc.exe/vnc"`) that could
  never match; a test now keeps the lists well-formed.
- A help example contained a literal tab instead of `\t` (`.\today` displayed as `.<TAB>oday`).
- Launch instructions: right-click *Run with PowerShell* is no longer suggested (it defaults to refusing the
  execution-policy change and closes the window); README and guide give the exact fix for each refusal message.

## 2.3.2 — correctness fixes for live views and change reconstruction

### Fixed
- **Explore views showed one blank row instead of the data** (e.g. *Deleted files* → "1 row(s)" with empty
  columns). Collectors returned their records wrapped as a single array object; views piped that object into
  `Select-Object`. Affected every collector-backed view (processes, network, DNS, autostarts, services,
  drivers and all *Recent changes* views) and `Get-WfxActivity` in a pipeline. Collectors now stream records.
- **Live monitor** baseline counted the whole process / connection list as one item.
- **Triage bundle**: autostarts and services were stored as two nested arrays; offline `.evtx` events were
  wrapped in one item. Both are now flat lists.
- **Ransomware scan roots / "new programs" view** built wrong paths on machines with more than one profile.
- **NTFS change journal** (*File system changes*):
  - a file or folder sent to the Recycle Bin is a *rename* into `$Recycle.Bin`, not a delete — it was
    invisible. Renames are now paired with their old name: reported as **Deleted to Recycle Bin** (with the
    original path), **Renamed** or **Moved**; deleting `$R…` items is reported as the bin being emptied;
  - reason flags were mislabelled (an ordered dictionary was indexed by position, not by flag);
  - accepts hex or text reason codes, quoted names containing commas, and non-English column headers;
  - file IDs are passed to `fsutil file queryFileNameById` in its documented `0x…` form (128- and 64-bit);
  - files vs. folders are distinguished; unresolved folders are shown as a placeholder, never guessed;
  - when nothing can be read, the view says exactly why (rights, journal disabled, unsupported output) and
    how far back the readable journal window goes.
- **Recycle Bin**: reads every fixed drive, validates `$I` records, and states whether the item is a file or
  folder and whether its content is still recoverable (with its `$R` path).

### Tests
- **G** in a view now opens a self-contained, offline browser table (sort, filter, copy as TSV). Values are
  inserted as text only and the page has a no-network Content-Security-Policy, so hostile file names in the
  evidence cannot run script. Out-GridView is offered (as **W**) only where it actually works — it needs the
  ISE graphical host, which Windows Sandbox, Server Core and PowerShell 7 usually lack.
- Empty or partial views show **Notes (coverage and limits)** instead of "Nothing found".

## 2.3.1 — simpler, more transparent launcher

### Tests
- **Removed `Start-WinForensicX.cmd`.** Start the tool with `.\Start-WinForensicX.ps1` from a PowerShell
  window (administrator recommended), or right-click it → Run with PowerShell.
- **The launcher no longer elevates or relaunches itself** and never passes `-ExecutionPolicy`. When not
  elevated it says what will be missing and how to reopen as administrator. A batch file that starts
  PowerShell with a policy bypass, plus a self-elevating relaunch, is the pattern heuristic antivirus engines
  associate with script droppers (Avast reported the 2.3.0 archive as `VBS:Runner-NI`). The tool did nothing
  harmful; the launch pattern simply looked like one.
- **Recent files** view parses `.lnk` shortcuts directly from their bytes (`[MS-SHLLINK]`) instead of
  using the `WScript.Shell` COM object, and also shows the target's recorded modification time.

### Added
- `SHA256SUMS.txt` in the release, and README sections on verifying the download and handling antivirus
  warnings (report false positives; never disable protection).

## 2.3.0 — what changed recently, and a new report

### Added
- **Recent-activity reconstruction** (`Get-WfxActivity`, collected in every triage):
  - registry last-write times for persistence, hijack, credential, defence, firewall-rule, service, task and
    uninstall keys
  - NTFS change journal (with `-FileScan` / `-Journal`, admin): created, deleted, content overwritten /
    extended / truncated, renamed, alternate data stream and timestamp changes, with parent folders resolved
  - Recycle Bin deletions with original path and recoverability
  - MSI install/remove and driver install/load events
  - Prefetch, BAM and UserAssist execution
  - connection history from Sysmon 3, WFP 5156, the firewall log, live connection creation times and saved
    RDP targets
  - config-change events: services, tasks, accounts/groups, audit policy, time change, log clearing, firewall
    rules, Defender, BITS, WMI, RDP client, Sysmon 2/11/12/13/14/23/26
- **Activity detections** (ACT-*): Defender exclusion/policy changes, hijack keys, autostart keys,
  WDigest/LSA weakening, RMM installs, PsExec-style and user-path services, firewall changes by non-system
  programs, audit-policy change, log tampering, Defender disabled, timestomping, time change, BITS from
  unusual hosts, WMI subscriptions, user-folder executions, staging-folder drops, alternate data streams,
  mass deletion and mass modification bursts.
- **Recent changes** group in Explore (8 views, listed first), and activity in the timeline, hunt and report.
- **File-integrity baselines**: `New-WfxFileBaseline` / `Compare-WfxFileBaseline` (added, deleted,
  content-changed, timestamp-only), also in Hunt & analyze.
- 5 new tests (83 total).

### Tests
- **Redesigned HTML report** in a case-file style:
  - a sticky sidebar with the host, both scores and the sections
  - an evidence-tag verdict in plain words with a numbered "start here" list
  - findings as a worklist grouped by area with severity and area filters, search and expandable evidence
  - a searchable Recent activity table
  - a day-grouped timeline merging findings and notable changes
  - ATT&CK techniques in lifecycle order, a "what this report could not see" section, and case & custody details
  - light/dark themes, a phone layout and print styles; still a single offline file
- Fixed: findings without a time no longer appear at 1 Jan 1970 in the timeline. IP IOCs now match `ip:port`.

## 2.2.0 — usability: launcher, menu, live views, speed

### Added
- **`Start-WinForensicX.cmd`** (double-click) and **`Start-WinForensicX.ps1`** in the repository root. They use
  PowerShell 7 when installed, offer to restart as administrator, load the module and open the menu, and show
  a clear error instead of a closing window if something is missing.
- **Rebuilt menu** with sections and submenus: Investigate, Explore, Hunt & analyze, Cases & evidence, Live
  monitor, Settings, Help. It has a status header (host, elevation, output folder, last case), a description
  on every option, validated input (paths checked, numbers range-checked, invalid keys re-asked), B/Q
  everywhere, errors that never close the menu, and an offer to open the report after a triage.
- **`Get-WfxInsight`**: 45 live, read-only views across System, Processes, Network, Persistence, Events,
  Files and Security. In the menu each view can be filtered, listed, opened in Out-GridView and exported
  to CSV. **`Save-WfxInsight`** exports all views as a hashed inventory case (inventory.html + one CSV per view).
- **`Test-WfxCase`**: verifies a case against its manifest (changed / missing / added-after-close files,
  optional check of the recorded manifest hash). Available from the menu.
- Per-stage collection progress with timings (`[3/9] Processes … 12.4s 312 items`) and a progress bar.

### Changed / fixed
- **Much faster event collection.** Rendered message text (the slowest part, milliseconds per event) is only
  read for low-volume events that need it. Secret redaction runs only on free-text fields. Default caps are
  lower (15,000 logon/process events), and caps are still reported as gaps.
- Process owners come from one bulk `Get-Process -IncludeUserName` call when elevated, instead of one CIM call
  per process.
- Ransomware file collection now runs as part of the file-scan stage. File triage accepts paths containing `[ ]`.
- Version 2.2.0. 5 new tests (78 total). PSScriptAnalyzer is clean, including Windows PowerShell 5.1
  command/syntax compatibility checks.

## 2.1.0 — correctness, evidence integrity and investigator tooling

### Fixed
- **Analysis no longer aborts** when a rule pack is missing or broken (e.g. quarantined): each analyzer is
  isolated and failures become analysis gaps. Built-in packs are checked at startup with a clear message.
- **Chain of custody:** a completed case is closed, so later commands can no longer append to its
  `audit.log` and invalidate its manifest. Re-analysis creates its case before analyzing and records the
  source bundle/manifest hashes.
- **Offline (`-EvtxPath`) mode** no longer mixes the analyst workstation's live processes, persistence and
  network into the case. The host name comes from the events. Event-ID queries are chunked to stay within
  `Get-WinEvent` limits, and rules now match on log name as well as event id.
- **No outbound network activity:** reverse-DNS lookups (which also polluted the DNS cache before it was
  collected) were removed. Endpoints are named from the DNS cache instead. The domain SYSVOL is only read
  with `-ExposureScan`.
- **False positives on clean hosts:** default Windows listeners (RPC dynamic range on core processes, 5040,
  7680, …) and Defender's ProgramData platform folder are baselined. Validly signed per-user apps
  (OneDrive, Teams…) become Info. A simulated clean Windows 11 host went from 79/100 Critical to <20.
- "Unknown" is no longer reported as "off" (process auditing when `auditpol` needs admin or prints
  localized text; Defender exclusions for non-admins).
- "No events matched" is no longer reported as a collection gap. Event caps are reported as gaps.
  High-volume IDs are queried separately so they can't crowd out rare events.
- `EXPO-HIVE-ACCESS` fired regardless of the ACL check. ACL checks now test the actual read bits. The NTDS
  default path is fixed. **Live SAM/SYSTEM/SECURITY readability (HiveNightmare)** is now checked.
- Failure→success logon correlation now requires failures *before* the success (24 h window) and is O(n).
- Monitor: beaconing is computed from new-connection times (not poll times), alerts are de-duplicated, and
  multi-finding polls no longer print `System.Object[]`. Only new processes are enriched each poll.
- Hunt: IPs and domains match exactly (no `1.2.3.4` ↦ `11.2.3.45`). Event logs are searched. MD5/SHA-1 work.
  Defanged IOCs and IOC files are accepted. Results are saved to a hunt case.
- `POSTURE-NO-AV` could never fire. Several secret env vars in one scope collapsed into one finding.
  `-Depth` implied recursion where one level was intended. The parent-spoof check now has a PID-reuse guard.
  4104 script blocks split across events are re-assembled.
- Built-in regexes over collected text now use timeouts. Redaction fails closed. The ransom-note pattern
  is bounded (a crafted note took ~7 s per file before).
- Report: ATT&CK links are only built from well-formed ids. A malicious custom rule pack could previously
  inject an HTML attribute (script execution). Technique ids are validated at load and at finding creation.
- Ransom-note candidates are no longer "any recent .txt/.html under C:\Users" stored raw. They are notes by
  name or the same file name dropped in ≥5 folders, read once, redacted and truncated. Web-script content
  has a total budget.
- All timestamps in bundles are UTC ISO-8601 strings (identical across PowerShell 5.1/7).
- User profiles come from the registry ProfileList (not a hard-coded `C:\Users`). HKCU and HKU\<SID> are no
  longer double-counted.

### Added
- `Get-WfxFileTriage`, `ConvertFrom-WfxEncodedCommand`, `Get-WfxTimeline` / `Export-WfxTimeline`,
  `Compare-WfxCase`. Allowlist support (`-AllowlistPath`, `$env:WFX_ALLOWLIST`).
- Separate **Compromise risk** and **Posture** scores. Case & chain-of-custody panel and suppressed
  findings in the report.
- Manifest v2: tool & rule-pack hashes, parameters, sources, and a note on what it proves.
- New rule pack `lotl.json` (49 rules, self-tested; samples are non-functional fragments on reserved
  `example.invalid` hosts). Encoded PowerShell is decoded and re-scanned automatically.
- Event coverage: 4688, 4740, Sysmon 1/8/10/13/22, Defender 1116/1117, TerminalServices 1149 (timeline).
  RunMRU (ClickFix) collection. COM-handler scheduled tasks. UDP endpoints. MOTW HostUrl/ReferrerUrl.
- 36 regression tests (73 total).

### Changed (breaking)
- Result schema `winforensicx.result/2` (adds `Posture`, `Suppressed`, `Case`, `Collected`); bundle schema
  `winforensicx.bundle/2` (UTC strings, `Started`). `-FileScan`/`-ExposureScan` are not valid with
  `-EvtxPath`. Event rule ids renamed: `EVT-4698-DISABLE-DEFENDER` → `EVT-DEFENDER-CONFIG-CHANGE`
  (5001/5007), `EVT-4104-SUSPICIOUS-CEARED` → `EVT-4104-HISTORY-TAMPER`. `EVT-4672-SENSITIVE` was removed
  (it never fired). New `EVT-DEFENDER-DETECTION`. `NET-LISTENER-EXPOSED` is now Low and one per port+process.
- Rule packs (`Rules/*.json`) are the source of truth. The old Python generators are retired.

## 2.0.0
Ground-up rebuild: collector/analyzer split, JSON rule packs mapped to ATT&CK, risk scoring, HTML report,
case folders with audit log and manifest, single-file build, Pester tests.
