# Security model & boundaries

WinForensicX is a **defensive, read-only** triage toolkit. This document states exactly what it does and —
just as importantly — what it will never do, so that defenders, reviewers, and security teams can trust it
inside an investigation and on sensitive hosts.

## Read-only by design

WinForensicX **observes**. It enumerates processes, connections, DNS cache, autostart locations, event
logs, files in a bounded set of high-signal locations, and security configuration. It does not install
anything, does not modify system state, and does not alter the artifacts it reads. The one thing it
writes is its own **case folder** (outputs, audit log, SHA-256 manifest) in a location you choose.

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
