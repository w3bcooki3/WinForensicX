# Changelog

## 2.0.0

A ground-up rebuild of the toolkit around a clean, testable architecture.

### Added
- **Normalized collector/analyzer split.** Windows-only collectors gather OS-neutral data; analyzers are
  pure functions over that data, unit-tested on any OS.
- **Data-driven rule packs** (JSON) mapped to MITRE ATT&CK: ~62 command-line / event / AI rules, each with
  match & counter-match samples the test suite enforces. Regexes compiled once with a 250 ms ReDoS timeout.
- **Detection coverage** across process tradecraft, living-off-the-land, persistence, network/C2 (incl.
  low-jitter beaconing), event logs, files (web shells, droppers, ransomware), and security posture.
- **AI-era threats:** exposed local LLM runtimes (Ollama/LM Studio on `0.0.0.0`), leaked AI provider API
  keys, AI agents with shell access, ClickFix / fake-CAPTCHA artifacts.
- **Defensive secrets-exposure audit** — reports *that* secrets are exposed (GPP cPassword, unattend
  passwords, accessible SAM/NTDS, world-readable cloud credentials, auto-logon, unencrypted SSH keys,
  secrets in env/history/config) with every value **redacted to type + length**. Never extracts or decrypts.
- **Composable risk scoring:** `risk = 1 − Π(1 − wᵢ/40)` — many low-confidence leads can't sum to a critical.
- **Commands:** `Invoke-WfxTriage` (local / remote-WinRM / offline-evtx / re-analyze), `Invoke-WfxAnalyze`,
  `Start-WfxMonitor`, `Invoke-WfxHunt`, `Save-WfxEvidence`, `Show-WfxMenu`.
- **Self-contained HTML report** — risk gauge, filterable findings with ATT&CK deep-links, tactic coverage,
  timeline, host info, and a collection-gaps section so "nothing found" is never mistaken for "nothing there."
- **Chain of custody:** timestamped case folder with JSON/CSV outputs, a JSON-lines audit log, and a
  SHA-256 manifest of every output.
- **Deterministic single-file build** (`tools/build.ps1` → `dist/WinForensicX.ps1`) with rule packs embedded.
- Pester test suite (runs on any OS), PSScriptAnalyzer policy, and Windows PowerShell 5.1 + PowerShell 7+
  compatibility.

### Security
- Strictly read-only; no credential extraction, decryption, memory/LSASS access, or exfiltration.
- Command lines, event messages and file contents are secret-scrubbed **at collection time**, so the raw
  evidence bundle is safe to persist and ship over WinRM.
- The HTML report escapes its embedded data island so attacker-influenced finding fields cannot break out
  into executable markup.
