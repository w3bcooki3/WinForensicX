# WinForensicX

**A read-only DFIR / incident-triage toolkit for Windows.** One command collects the state of a host,
analyzes it against data-driven detection rules mapped to **MITRE ATT&CK**, scores the host's risk, and
produces a self-contained HTML report with full chain of custody — for SOC analysts, DFIR responders,
threat hunters, and anyone who needs a fast, trustworthy picture of what a Windows machine is doing.

It is built for the AI era: alongside the classic tradecraft (living-off-the-land abuse, persistence,
credential exposure, lateral movement, ransomware) it detects locally-hosted LLM runtimes exposed to the
network, leaked AI provider API keys, AI agents wired to a shell, and modern social-engineering artifacts
such as ClickFix / fake-CAPTCHA lures.

> **Defensive by design.** WinForensicX is strictly read-only. For credentials and secrets it performs an
> **exposure audit only** — it reports *that* sensitive material is exposed or misconfigured, with the
> actual values **redacted to type + length**. It never dumps LSASS, parses SAM/NTDS hashes, decrypts
> browser or DPAPI secrets, or exfiltrates anything. See [SECURITY.md](SECURITY.md).

---

## Why

Most "all-in-one" DFIR scripts grow into thousands of lines of tangled collection and detection logic that
is impossible to test, tune, or trust. WinForensicX is rebuilt around a clean separation:

- **Collectors** gather normalized, OS-neutral data from a Windows host (or an exported artifact).
- **Analyzers** are pure functions over that normalized data — so every detection is unit-tested on any OS.
- **Rule packs** are data (JSON), not code: add or tune detections without touching the engine.
- **Risk scoring** combines findings as *independent evidence* (`risk = 1 − Π(1 − wᵢ/40)`), so a pile of
  low-confidence leads can never masquerade as a critical, and two real criticals clearly dominate.

The result is a tool you can read, test, extend, and defend in an investigation.

---

## What it detects

| Area | Examples |
|---|---|
| **Process tradecraft** | System-name masquerade (e.g. `lsass.exe` from a temp folder), parent-process spoofing, Office/browser spawning script interpreters, unsigned binaries in user-writable paths, offensive & RMM tooling |
| **Living-off-the-land** | Encoded PowerShell, download cradles, AMSI bypass, reflective loading, `mshta`/`certutil`/`bitsadmin`/`regsvr32`/`rundll32` proxy execution, `comsvcs` LSASS minidump, shadow-copy deletion, log clearing |
| **Persistence** | Run keys, Startup, services, scheduled tasks, WMI event subscriptions, AppInit, IFEO debuggers, LSA providers, Winlogon, BootExecute, from untrusted locations |
| **Network & C2** | Exposed listeners, tunnels (ngrok/Cloudflare/SSH), suspicious ports, DGA-like domains, high-risk TLDs, paste/exfil services, and low-jitter **beaconing** detection |
| **Events** | 4625 password spray, cracked-logon chains, 1102/104 log clearing, 7045 service install, 4698 task creation, 4688/4104 command-line & script-block abuse, account-change and external-RDP events |
| **Files** | Web shells (PHP/ASP/JSP), double-extension lures, internet-downloaded executables (Mark-of-the-Web), packed/high-entropy binaries, ransom notes and mass-encryption bursts |
| **Exposure (redacted)** | GPP cPassword, unattend passwords, accessible SAM/SYSTEM/NTDS, world-readable cloud credentials, auto-logon password, unencrypted SSH keys, secrets in env vars / history / config files |
| **Security posture** | AV/real-time protection off, suspicious Defender exclusions, stale signatures, missing process/script-block auditing (a *visibility* gap), firewall off, RDP without NLA, LSASS not protected |
| **AI-era threats** | Ollama/LM-Studio exposed on `0.0.0.0`, leaked AI provider API keys, AI agents with shell access, ClickFix/fake-CAPTCHA artifacts |

**~62 command-line/event/AI rules + ~47 analyzer detections, mapped to ~74 ATT&CK techniques.**

---

## Install

**Requirements:** Windows PowerShell **5.1** or PowerShell **7+**. No external modules. Administrator
rights are recommended (more data), but the tool degrades gracefully without them and records what it
could not see as **collection gaps**.

### Option A — single file (simplest)
Copy `dist/WinForensicX.ps1` to the host and run it. It is fully self-contained (rules embedded, no assets).

```powershell
# Interactive menu
.\WinForensicX.ps1

# Or run a triage straight away
.\WinForensicX.ps1 -RunTriage

# Or load the functions into your session and call them directly
. .\WinForensicX.ps1
Invoke-WfxTriage -FileScan
```

### Option B — module
Copy the `WinForensicX` folder onto the host (or into a `$env:PSModulePath` location) and import it.

```powershell
Import-Module .\WinForensicX\WinForensicX.psd1
Invoke-WfxTriage
```

---

## Quick start

```powershell
# Triage this host (fast)
Invoke-WfxTriage

# Thorough: also scan web roots / drop folders and audit config-file secrets
Invoke-WfxTriage -FileScan -ExposureScan

# Triage remote hosts over WinRM, analyze locally
Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)

# Offline: analyze exported event logs (dead-box / image triage)
Invoke-WfxTriage -EvtxPath D:\evidence\Security.evtx

# Re-analyze a previously collected case (no collection; works on any OS)
Invoke-WfxTriage -InputPath C:\cases\WFX_host_20260101-000000Z

# Live monitor: baseline, then alert on new suspicious processes/connections/beacons
Start-WfxMonitor -Interval 5 -Duration 300

# Hunt for specific IOCs across the host
Invoke-WfxHunt -Ioc 'evil.com','1.2.3.4','5d41402abc4b2a76b9719d911017c592'

# Preserve evidence quickly without analysis (analyze later with -InputPath)
Save-WfxEvidence -FileScan -ExposureScan

# Not sure where to start? The menu drives everything.
Show-WfxMenu

# How to use, every command, and the limitations — printed in the terminal,
# with a clickable link to the full illustrated HTML guide.
Show-WfxHelp          # add -Html to open the guide in a browser
```

Every run also prints a clickable `file://` link to its `report.html`, and the report itself carries a
**Limitations & how to read this** panel so the caveats travel with the output.

---

## Commands

| Command | Purpose |
|---|---|
| `Invoke-WfxTriage` | Collect → analyze → score → report. Modes: local, `-ComputerName` (remote WinRM), `-EvtxPath` (offline), `-InputPath` (re-analyze). |
| `Invoke-WfxAnalyze` | Run all analyzers over a collection bundle (object, `bundle.json`, or case folder). The OS-neutral core. |
| `Start-WfxMonitor` | Live baseline + delta monitoring with alerting and beacon detection. |
| `Invoke-WfxHunt` | Sweep a host (or a saved bundle) for IOCs — hashes, IPs, domains, names, strings. |
| `Save-WfxEvidence` | Collect a hashed, read-only evidence bundle for later analysis. |
| `Show-WfxMenu` | Interactive menu over all of the above. |
| `Show-WfxHelp` | How-to, commands, and limitations in the terminal, plus a clickable link to the HTML guide (`-Html` opens it). |

---

## Outputs & chain of custody

Each run creates a timestamped **case folder** (default `Desktop\WinForensicX\…`) containing:

```
WFX_<host>_<utc-timestamp>Z/
├─ report.html        # self-contained, filterable triage report (open in any browser, offline)
├─ result.json        # findings + risk + ATT&CK coverage + gaps (machine-readable)
├─ findings.json      # just the findings
├─ findings.csv       # flat triage view for a spreadsheet / SIEM import
├─ raw/bundle.json    # the normalized collected data (re-analyzable with -InputPath)
├─ audit.log          # JSON-lines record of every step the tool took, with timings
└─ manifest.json      # SHA-256 of every output file, written last
```

The audit log and the SHA-256 manifest give you a defensible record of exactly what was collected, when,
by whom, and on what — and let you prove the outputs were not altered after collection.

---

## Customising detections

Rule packs live in `WinForensicX/Rules/*.json` (and are embedded in the single-file build). You can add
your own without editing the engine — point WinForensicX at a folder of custom packs:

```powershell
$env:WFX_RULES = 'C:\my-rules'   # files named <pack>.<label>.json, e.g. lotl.acme.json
```

Each rule carries an `id`, a regex `pattern`, the `images` it applies to, an ATT&CK `technique`, a
`severity`/`confidence`, a human `description` + `recommendation`, and `tests` (match / nomatch samples)
that the test suite enforces. Every regex is compiled once with a **250 ms match timeout**, so a badly
written rule can never hang a triage. See [docs/RULES.md](docs/RULES.md).

---

## Testing & quality

```powershell
# Pure analyzer/rule tests run on any OS (Windows, Linux, macOS)
Invoke-Pester ./tests/Analyzers.Tests.ps1

# Lint (policy documented in PSScriptAnalyzerSettings.psd1)
Invoke-ScriptAnalyzer -Path ./WinForensicX -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Rebuild the single-file distributable (deterministic)
pwsh -File tools/build.ps1
```

Every rule pack is self-testing: the suite asserts each rule matches its own samples, avoids its
counter-samples, references a known ATT&CK id, and cannot be hung by a catastrophic-backtracking input.
Redaction is verified end-to-end — a planted secret never appears in any output.

---

## Honest limitations

- WinForensicX produces **leads for an analyst, not verdicts.** A finding means "look here," not "this host
  is compromised." Read findings alongside the **collection gaps**: on a host with no process auditing and
  no Sysmon, "nothing found" mostly means "nothing could be seen," and the report says so.
- It is a **triage** tool, not a full forensic imager. It does not acquire disk/memory images or carve
  deleted files. Use it to decide *where* to dig; use heavyweight tools to dig.
- Detections are heuristic and will have false positives and false negatives. Tune with custom rule packs
  and the finding allowlist (by `Id` + `Entity`).
- It will not extract, decrypt, or dump secrets — that is a deliberate boundary, not a missing feature.

---

## License

MIT. See [LICENSE](LICENSE). Use it, fork it, ship it in your IR kit, and send improvements back to the
community.
