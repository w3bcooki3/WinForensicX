# Changelog

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
