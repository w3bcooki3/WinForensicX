# Writing and tuning rules

Rule packs are JSON files in `WinForensicX/Rules/` and are the source of truth (the single-file build
embeds them). Add your own without editing the engine:

```powershell
$env:WFX_RULES = 'C:\my-rules'     # files named <pack>.<label>.json, e.g. lotl.acme.json
```

Custom rules are merged after the built-in ones; if an `id` already exists, the first definition wins.

## Command-line rules (`lotl`)

```json
{
  "id": "ACME-RCLONE-EXFIL",
  "title": "rclone copying to a cloud remote",
  "pattern": "(?i)\\brclone(?:\\.exe)?[\"']?\\s+(?:copy|sync)\\s",
  "images": ["rclone.exe"],
  "exclude": "(?i)--dry-run",
  "technique": ["T1567.002"],
  "severity": "High",
  "confidence": "Medium",
  "description": "Why this matters, in one or two sentences.",
  "recommendation": "What the analyst should do next.",
  "tests": { "match": ["rclone copy C:\\data remote:bkt"], "nomatch": ["rclone version"] }
}
```

| Field | Meaning |
|---|---|
| `id` | Stable identifier (letters, digits, `_ . -`). Used for dedupe and allowlists. |
| `pattern` | .NET regex, compiled once with a 250 ms timeout (a timeout counts as no match). |
| `images` | Optional. Executable names the rule applies to. The rule also fires if one of them is named inside the command line (e.g. via `cmd /c`). |
| `exclude` | Optional regex. A match suppresses the rule. |
| `technique` | ATT&CK ids (`T1234` or `T1234.567`). Malformed ids cause the rule to be **rejected**. |
| `severity` / `confidence` | `Info/Low/Medium/High/Critical` / `Low/Medium/High`. Weight = severity × confidence. |
| `tests` | Samples the test suite enforces. Keep them short, **non-functional**, and use reserved hosts such as `example.invalid`. |

Command-line rules run over process command lines, **decoded** `-EncodedCommand` payloads, autostart
commands, RunMRU entries, 4688 / Sysmon 1 command lines and 4104 script blocks.

## Event rules (`events`)

Same fields plus `eventIds`, `logs` (exact channel names, e.g. `Security`,
`Microsoft-Windows-Sysmon/Operational`) and `fields` (event-data names whose values are joined and matched).
Use `"pattern": "__lotl__"` to run the command-line pack over the fields. Leave out `pattern` to fire on
every matching event. `"perEvent": false` marks rules implemented as aggregates in code.

## Allowlist

```json
[ { "Id": "PERSIST-RUNKEY-*", "Entity": "autostart:RunKey:CorpAgent", "Host": "*", "Reason": "IT agent, CHG-1234" } ]
```

Pass it with `-AllowlistPath` or `$env:WFX_ALLOWLIST`. Suppressed findings remain visible in the report.
