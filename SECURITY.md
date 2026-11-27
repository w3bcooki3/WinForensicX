# Security model & boundaries

WinForensicX is a **defensive** triage toolkit, **read-only except Respond mode**. This document states exactly what it does and —
just as importantly — what it will never do, so that defenders, reviewers, and security teams can trust it
inside an investigation and on sensitive hosts.

## Read-only by design

WinForensicX **observes**. It enumerates processes, connections, DNS cache, autostart locations, event
logs, files in a bounded set of high-signal locations, and security configuration. It does not install
anything, does not change system settings, and never executes, opens with a handler, or loads anything it
finds (file triage and the decoder work on bytes/text only). It writes only its own **case folder**
(outputs, audit log, SHA-256 manifest) in a location you choose. Prefer `-OutputPath` on external media:
by default the case goes to the Desktop of the host being examined, which writes to the evidence volume.

Side effects you should know about, as for any live-response tool:
- Reading files (hashing, entropy, web-shell scanning) can update NTFS **last-access** timestamps on volumes
  where that is enabled.
- Running PowerShell itself creates artifacts: process creation, Prefetch, and, if script-block logging is
  on, 4104 events containing this tool's code.

## Respond mode: the only part that changes anything

`Invoke-WfxRespond`, `Start-WfxIsolation`, `Undo-WfxAction`, `Invoke-WfxDefenderScan` and menu 7 change the
computer, and only when you confirm each action (`-WhatIf` previews). Before each change the tool records what
it is about to change in `Downloads\WinForensicX-Quarantine\actions`, a folder locked to Administrators and
SYSTEM. Everything except stopping a process can be undone. Hard refusals (critical Windows processes and
services, security products, Microsoft-signed Windows files, registry values outside the Run keys, loopback or
"everything" firewall blocks, the account in use, the last local administrator) cannot be overridden by any
option. Quarantined files are AES-encrypted with a per-file key stored in the file header: the point is that
they cannot run and are not re-detected, not secrecy. Isolation uses firewall block rules and, unless told
otherwise, a one-time scheduled task (SYSTEM) that removes them after 30 minutes; its command line is plain,
readable text.

The opt-in injected-code scan (`-DeepScan`) opens other processes with query and read access, walks their
memory map and reads at most the first 1 KB of executable regions that no file accounts for, only to detect a
program header. It never opens LSASS, other critical processes or security products, keeps no memory contents,
and some EDR products report this kind of scan.

## Artifacts, Sigma and YARA (3.0)

- **Registry hives** (live `NTUSER.DAT` / `UsrClass.dat` of logged-off users, and every hive under `-ArtifactPath`)
  are read as files with read/write sharing and parsed in memory. They are never loaded into the registry
  (`reg load`), and transaction logs are replayed only in memory; the files are not modified.
- **Browser databases** (`History`, `places.sqlite`) are copied into memory with sharing and only the
  download tables are read: no cookies, saved logins, form data or browsing history.
- **Jump Lists, shortcuts, PCA and Defender logs** are read as bytes or text; shortcuts are never resolved
  or opened.
- **Sigma rules** are parsed as data (a small YAML reader written for this purpose); nothing in a rule is
  executed.
- **YARA** runs only when you pass rules (`-YaraRules` / `WFX_YARA`) and only with a `yara` executable you
  installed (`-YaraExe`, `WFX_YARA_EXE` or PATH). YARA reads the files it scans. The list of scanned files is
  written to `raw\yara-scan-list.txt` inside the case folder as a record; nothing is written elsewhere.
- **Exports** (`Export-WfxCase`, `New-WfxFleetReport`) write next to the case folder, never into it, so a
  closed case still verifies.

## Network behaviour

The tool sends **no network traffic of its own** during local triage. It performs no reverse-DNS lookups,
fetches no updates, and makes no telemetry or download calls. Exceptions, both explicit:
- `-ComputerName` uses the WinRM session you ask for. Only the collection code (Private + Collectors) is sent,
  and its SHA-256 is recorded in the case audit log and manifest.
- `-ExposureScan` on a domain member reads the domain `SYSVOL` share for GPP passwords.

## Credential & secret exposure: audit, never extract

This is the most important boundary. When WinForensicX reports on credentials or secrets, it is performing
an **exposure audit** — it tells you *that* sensitive material exists and is exposed or misconfigured, so
you can remediate it. It does **not** obtain the secret.

**What it does:**
- Detects exposed/misconfigured credential material: GPP `cPassword`, unattend passwords, SAM/SYSTEM/
  SECURITY/NTDS hives that are present and readable by the wrong principals (existence + ACL check only),
  world-readable cloud-credential files (`.aws/credentials`, `.kube/config`, …), auto-logon passwords,
  unencrypted SSH private keys, AI provider API keys, and secrets in environment variables, shell history,
  or config files.
- **Redacts every value** to its type and length before it leaves the collector (e.g.
  `Anthropic API key: sk-a…[redacted, 60 chars]`). Raw values are discarded immediately and never written
  to a bundle, report, or log.
- Keeps *tool command strings* visible for the analyst (e.g. a `mimikatz sekurlsa::logonpasswords` command
  line found in an event stays readable as evidence) while redacting any actual password embedded in it.

**What it deliberately does NOT do — and must never be extended to do:**
- No LSASS access or memory dumping.
- No reading, copying, parsing, or decrypting of credential stores: SAM/NTDS hashes, LSA secrets, DPAPI
  blobs, browser login databases, Credential Manager, keychains.
- No decryption of the GPP `cPassword` (reversible though it is) — reporting its presence is enough.
- No exfiltration of any kind.

Detecting exposure requires none of these capabilities. Any change that adds secret *extraction* or
*decryption* is out of scope for this project and should be rejected in review.

## Safe on hostile input

- **Rule regexes** are compiled once with a **250 ms match timeout**; a catastrophic-backtracking pattern
  (whether a buggy community rule or a malicious one) returns "no match" instead of hanging the triage.
- **File reads are bounded** by count, per-file size, and read length — a triage never walks an entire disk
  or slurps a huge file into memory.
- **Collectors never throw.** Every collection step runs through a guard that turns a failure (missing
  privilege, disabled log, absent key) into a recorded **collection gap**, so the run completes and the
  report distinguishes "clean" from "couldn't see."
- **Downloaded/offline artifacts are treated as untrusted data** — parsed, never executed.

## Report safety

The HTML report is self-contained (no external scripts, styles, or network calls) and embeds only
already-redacted findings data — never the raw collected bundle. Embedded JSON is escaped so report
content can never break out of its data block into executable markup.

## Reporting a vulnerability

If you find a way to make WinForensicX leak a secret value, execute untrusted input, modify the host, or
hang on crafted data, please open a private report to the maintainers rather than a public issue, with a
minimal reproduction. Redaction leaks and read-only violations are treated as the highest priority.

## Integrity of the tool itself

- Every case manifest records the SHA-256 of the code and rule packs that produced it (`toolIntegrity`).
- Built-in and custom rule packs are validated when loaded: invalid ids, severities or ATT&CK ids are
  rejected and reported as gaps, and every regex runs with a 250 ms timeout. Built-in regexes over collected
  data also use timeouts, and redaction fails closed (content is withheld if it can't be scrubbed in time).
- The HTML report escapes all data and builds ATT&CK links only from well-formed technique ids.
- Rule-pack self-test samples are short, **non-functional** fragments that use reserved `example.invalid`
  hosts. The repository contains no working payloads, exploits or malware samples.
- No obfuscation is used anywhere in the code. Because the rule packs necessarily describe attacker
  techniques, some antivirus engines may flag them. Verify the release hash and report false positives to
  the vendor. Never disable protection to run the tool.
