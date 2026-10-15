# File and web-shell analyzer. Operates on normalized file records the collector produces:
#   { Path, Directory, Extension, Length, LastWrite, Content (first N KB, optional), Entropy (optional),
#     SignatureStatus, Zone (MOTW), InWebRoot }
# Content is only read for small text files in web roots / script locations, and is never emitted raw —
# only rule ids, a short redacted snippet and line numbers.

# Signatures that indicate a web shell. Each: id, regex, languages, description.
$script:WfxWebShellSigs = @(
    @{ Id = 'eval-request'; Rx = '(?i)\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|request|base64_decode|gzinflate|str_rot13)'; Desc = 'Executes attacker-supplied input from an HTTP request.' }
    @{ Id = 'aspx-process'; Rx = '(?i)(?:Process\.Start|ProcessStartInfo|cmd\.exe|/c\s|Server\.CreateObject\("WScript\.Shell"\)|Runtime\.getRuntime\(\)\.exec)'; Desc = 'Spawns an OS process from a web page.' }
    @{ Id = 'jsp-runtime'; Rx = '(?i)Runtime\.getRuntime\(\)\.exec|ProcessBuilder\(|<%@\s*page\s+import="java\.(?:io|lang)'; Desc = 'Java/JSP page that executes commands.' }
    @{ Id = 'webshell-named'; Rx = '(?i)\b(?:c99|r57|b374k|wso|weevely|china\s*chopper|antsword|behinder|godzilla|p0wny|reGeorg|tunna)\b'; Desc = 'Matches a known web-shell family name/marker.' }
    @{ Id = 'obf-eval'; Rx = '(?i)(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\('; Desc = 'Obfuscated code execution (packed/encoded payload).' }
    @{ Id = 'preg-e'; Rx = '(?i)preg_replace\s*\(\s*["''][^"'']*/[a-z]*e[a-z]*["'']'; Desc = 'preg_replace /e modifier — legacy PHP code execution.' }
    @{ Id = 'create-function'; Rx = '(?i)\b(?:create_function|call_user_func(?:_array)?)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|base64_decode)'; Desc = 'Builds and calls a function from request input.' }
)

function Invoke-WfxFileAnalyzer {
    param([object[]]$File, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $files = @($File | Where-Object { $_ })
    if ($files.Count -eq 0) { return , $findings.ToArray() }
    $executable = @('.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.sys', '.ocx')
    $script = @('.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.jar')

    foreach ($rec in $files) {
        $path = [string](Get-WfxValue $rec 'Path' '')
        $ext = ([string](Get-WfxValue $rec 'Extension' '')).ToLowerInvariant()
        if (-not $ext -and $path) { $ext = [IO.Path]::GetExtension($path).ToLowerInvariant() }
        $content = [string](Get-WfxValue $rec 'Content' '')
        $inWeb = [bool](Get-WfxValue $rec 'InWebRoot' $false)
        $zone = [string](Get-WfxValue $rec 'Zone' '')
        $entity = "file:$path"

        # 1. Web shells
        if ($content -and ($inWeb -or $ext -in @('.php', '.asp', '.aspx', '.ashx', '.asmx', '.jsp', '.jspx', '.phtml', '.php5', '.cfm'))) {
            foreach ($sig in $script:WfxWebShellSigs) {
                $m = [regex]::Match($content, $sig.Rx)
                if ($m.Success) {
                    $line = ($content.Substring(0, $m.Index) -split "`n").Count
                    $snippet = Protect-WfxText ($content.Substring([Math]::Max(0, $m.Index - 10), [Math]::Min(90, $content.Length - [Math]::Max(0, $m.Index - 10))))
                    $findings.Add((New-WfxFinding -Id 'FILE-WEBSHELL' -Title "Possible web shell in $(Get-WfxLeaf $path)" `
                                -Severity 'Critical' -Confidence 'Medium' -Category 'File' -Technique @('T1505.003', 'T1190') `
                                -Description "A file served by a web application contains code that runs commands or executes request input ($($sig.Desc)). Web shells give attackers remote control of a server." `
                                -Recommendation "Isolate the web server, preserve the file, and review web access logs for requests to it. Determine how it was written (upload flaw, vulnerable app)." `
                                -Entity $entity -HostName $HostName -Time (Get-WfxValue $rec 'LastWrite') -Source 'file' `
                                -Evidence ([ordered]@{ Path = $path; Signature = $sig.Id; Line = $line; Snippet = $snippet; LastWrite = (Get-WfxValue $rec 'LastWrite') })))
                    break
                }
            }
        }

        # 2. Double extension masquerade (e.g. invoice.pdf.exe)
        if ($path -match '(?i)\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|csv|zip|rtf)\.(exe|scr|com|pif|bat|cmd|vbs|js|hta|lnk)$') {
            $findings.Add((New-WfxFinding -Id 'FILE-DOUBLE-EXT' -Title "Double-extension file: $(Get-WfxLeaf $path)" `
                        -Severity 'High' -Confidence 'High' -Category 'File' -Technique @('T1036') `
                        -Description "The file name hides its real type behind a fake document/image extension — a classic trick to get users to run malware." `
                        -Recommendation "Do not open it. Hash and analyze it, and find how it reached the host." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $rec 'LastWrite') -Source 'file' `
                        -Evidence ([ordered]@{ Path = $path; LastWrite = (Get-WfxValue $rec 'LastWrite') })))
        }

        # 3. Executable/script downloaded from the internet (Mark-of-the-Web), in a user folder
        if (($ext -in $executable -or $ext -in $script) -and $zone -match '3|4' -and (Test-WfxUserWritablePath $path)) {
            $findings.Add((New-WfxFinding -Id 'FILE-MOTW-EXEC' -Title "Internet-downloaded executable in a user folder: $(Get-WfxLeaf $path)" `
                        -Severity 'Medium' -Confidence 'Medium' -Category 'File' -Technique @('T1105', 'T1204.002') `
                        -Description "An executable or script carrying a Mark-of-the-Web (downloaded from the internet) sits in a user-writable folder." `
                        -Recommendation "Hash it and check reputation; confirm the user intended to download and run it." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $rec 'LastWrite') -Source 'file' `
                        -Evidence ([ordered]@{ Path = $path; Zone = $zone; SHA256 = (Get-WfxValue $rec 'SHA256'); LastWrite = (Get-WfxValue $rec 'LastWrite') })))
        }

        # 4. High-entropy executable in a user folder (packed/encrypted payload)
        $entropy = [double](Get-WfxValue $rec 'Entropy' 0)
        if ($ext -in $executable -and $entropy -ge 7.2 -and (Test-WfxUserWritablePath $path)) {
            $findings.Add((New-WfxFinding -Id 'FILE-PACKED' -Title "Highly compressed/encrypted executable: $(Get-WfxLeaf $path)" `
                        -Severity 'Low' -Confidence 'Low' -Category 'File' -Technique @('T1027') `
                        -Description "The executable's content is near-random (entropy $entropy/8), which is typical of packed or encrypted malware (but also of some legitimate installers)." `
                        -Recommendation "Submit the hash to threat intelligence; treat as suspicious if from an unknown source." `
                        -Entity $entity -HostName $HostName -Time (Get-WfxValue $rec 'LastWrite') -Source 'file' `
                        -Evidence ([ordered]@{ Path = $path; Entropy = $entropy; SHA256 = (Get-WfxValue $rec 'SHA256') })))
        }
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}

# ─────────────────────────── ransomware note / mass-change heuristic ───────────────────────────
function Invoke-WfxRansomwareAnalyzer {
    <#
    .SYNOPSIS Flags ransom notes and bursts of newly-created encrypted-looking files.
    .PARAMETER Note  Candidate ransom-note files: { Path, Content }
    .PARAMETER RecentFile  Recently modified files: { Path, Extension, Entropy, LastWrite }
    #>
    param([object[]]$Note = @(), [object[]]$RecentFile = @(), [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    $noteRx = '(?i)(your files (?:have been|are) (?:encrypted|locked)|all your (?:files|data|documents)|decrypt(?:ion)?\s+(?:key|tool|service|id)|bitcoin|\.onion|recover (?:your )?files|how_to_(?:decrypt|recover)|readme.*decrypt|pay(?:ment)? .*(?:ransom|decrypt)|contact us.*(?:tox|telegram|protonmail|session id))'
    foreach ($n in @($Note | Where-Object { $_ })) {
        $c = [string](Get-WfxValue $n 'Content' '')
        $hits = ([regex]::Matches($c, $noteRx)).Count
        if ($hits -ge 2) {
            $findings.Add((New-WfxFinding -Id 'RANSOM-NOTE' -Title "Possible ransom note: $(Get-WfxLeaf ([string](Get-WfxValue $n 'Path' '')))" `
                        -Severity 'Critical' -Confidence 'Medium' -Category 'Ransomware' -Technique @('T1486') `
                        -Description "A file reads like a ransomware ransom note (encryption claim, payment/decryption instructions)." `
                        -Recommendation "Isolate the host from the network immediately. Preserve evidence, identify the family, and check backups and other hosts." `
                        -Entity "file:$([string](Get-WfxValue $n 'Path' ''))" -HostName $HostName -Source 'file' `
                        -Evidence ([ordered]@{ Path = (Get-WfxValue $n 'Path'); Markers = $hits })))
        }
    }
    $recent = @($RecentFile | Where-Object { $_ })
    $encLike = @($recent | Where-Object {
            $e = ([string](Get-WfxValue $_ 'Extension' '')).ToLowerInvariant()
            $e -match '^\.(?:encrypt(?:ed)?|locked|crypt(?:ed)?|enc|crypto|[a-z0-9]{5,8})$' -and $e -notmatch '^\.(?:exe|dll|docx|xlsx|pptx|jpeg|config|manifest)$' -and ([double](Get-WfxValue $_ 'Entropy' 0) -ge 7.4)
        })
    if ($encLike.Count -ge 25) {
        $exts = @($encLike | ForEach-Object { ([string](Get-WfxValue $_ 'Extension' '')).ToLowerInvariant() } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1)
        $findings.Add((New-WfxFinding -Id 'RANSOM-MASS-ENCRYPT' -Title "Mass creation of encrypted-looking files ($($encLike.Count))" `
                    -Severity 'Critical' -Confidence 'Medium' -Category 'Ransomware' -Technique @('T1486') `
                    -Description "A large number of recently written files have random (high-entropy) content and uniform unusual extensions — consistent with active ransomware encryption." `
                    -Recommendation "Isolate the host now and stop the responsible process. Preserve a sample and the ransom note before any remediation." `
                    -Entity 'ransom:mass-encrypt' -HostName $HostName -Source 'file' `
                    -Evidence ([ordered]@{ Files = $encLike.Count; TopExtension = ($exts.Name); Sample = (@($encLike | Select-Object -First 5 | ForEach-Object { Get-WfxValue $_ 'Path' })) })))
    }
    return , (Merge-WfxFinding -Finding $findings.ToArray())
}
