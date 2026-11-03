$script:WfxMagic = @(
    @{ T = 'PE executable (MZ)'; O = 0; H = '4D5A'; E = @('.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.com', '.efi', '.mui', '.drv', '.ax', '.node') }
    @{ T = 'ELF executable'; O = 0; H = '7F454C46'; E = @('', '.so', '.elf', '.bin', '.o') }
    @{ T = 'Mach-O (64-bit)'; O = 0; H = 'CFFAEDFE'; E = @('', '.dylib', '.bundle') }
    @{ T = 'Java class / Mach-O fat'; O = 0; H = 'CAFEBABE'; E = @('.class', '') }
    @{ T = 'PDF document'; O = 0; H = '25504446'; E = @('.pdf') }
    @{ T = 'ZIP container (also OOXML / JAR / APK / VSIX)'; O = 0; H = '504B0304'; E = @('.zip', '.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.jar', '.apk', '.vsix', '.nupkg', '.odt', '.ods', '.epub', '.xpi', '.whl', '.appx', '.msix', '.kmz', '.ipa') }
    @{ T = 'OLE2 compound file (legacy Office / MSI / MSG)'; O = 0; H = 'D0CF11E0A1B11AE1'; E = @('.doc', '.xls', '.ppt', '.msi', '.msg', '.msp', '.pub', '.vsd', '.mst') }
    @{ T = 'RAR archive'; O = 0; H = '526172211A07'; E = @('.rar') }
    @{ T = '7-Zip archive'; O = 0; H = '377ABCAF271C'; E = @('.7z') }
    @{ T = 'gzip'; O = 0; H = '1F8B'; E = @('.gz', '.tgz') }
    @{ T = 'bzip2'; O = 0; H = '425A68'; E = @('.bz2', '.tbz2') }
    @{ T = 'xz'; O = 0; H = 'FD377A585A00'; E = @('.xz', '.txz') }
    @{ T = 'Microsoft Cabinet'; O = 0; H = '4D534346'; E = @('.cab', '.msu') }
    @{ T = 'Windows shortcut (LNK)'; O = 0; H = '4C0000000114020000000000C000000000000046'; E = @('.lnk') }
    @{ T = 'Windows Event Log (EVTX)'; O = 0; H = '456C6646696C6500'; E = @('.evtx') }
    @{ T = 'Windows registry hive'; O = 0; H = '72656766'; E = @('', '.dat', '.hiv', '.hve', '.log1', '.log2') }
    @{ T = 'SQLite database'; O = 0; H = '53514C69746520666F726D61742033'; E = @('.db', '.sqlite', '.sqlite3', '.db3', '') }
    @{ T = 'PNG image'; O = 0; H = '89504E470D0A1A0A'; E = @('.png') }
    @{ T = 'JPEG image'; O = 0; H = 'FFD8FF'; E = @('.jpg', '.jpeg', '.jfif') }
    @{ T = 'GIF image'; O = 0; H = '474946383'; E = @('.gif') }
    @{ T = 'BMP image'; O = 0; H = '424D'; E = @('.bmp', '.dib') }
    @{ T = 'RIFF container (WAV / AVI / WEBP)'; O = 0; H = '52494646'; E = @('.wav', '.avi', '.webp', '.ani') }
    @{ T = 'Ogg'; O = 0; H = '4F676753'; E = @('.ogg', '.oga', '.ogv', '.opus') }
    @{ T = 'MP3 (ID3)'; O = 0; H = '494433'; E = @('.mp3') }
    @{ T = 'pcap capture'; O = 0; H = 'D4C3B2A1'; E = @('.pcap', '.cap') }
    @{ T = 'pcap capture (big-endian)'; O = 0; H = 'A1B2C3D4'; E = @('.pcap', '.cap') }
    @{ T = 'pcapng capture'; O = 0; H = '0A0D0D0A'; E = @('.pcapng') }
    @{ T = 'RTF document'; O = 0; H = '7B5C727466'; E = @('.rtf', '.doc') }
    @{ T = 'Compiled HTML Help (CHM)'; O = 0; H = '49545346'; E = @('.chm') }
    @{ T = 'WebAssembly'; O = 0; H = '0061736D'; E = @('.wasm') }
    @{ T = 'Android DEX'; O = 0; H = '6465780A'; E = @('.dex') }
    @{ T = 'PostScript'; O = 0; H = '2521'; E = @('.ps', '.eps') }
    @{ T = 'Windows minidump'; O = 0; H = '4D444D5093A7'; E = @('.dmp', '.mdmp') }
    @{ T = 'Windows hibernation / page file'; O = 0; H = '48494245'; E = @('.sys', '') }
    @{ T = 'ISO 9660 disk image'; O = 32769; H = '4344303031'; E = @('.iso', '.img') }
    @{ T = 'VHDX disk image'; O = 0; H = '7668647866696C65'; E = @('.vhdx') }
    @{ T = 'OneNote section'; O = 0; H = 'E4525C7B8CD8A74D'; E = @('.one') }
)

function Get-WfxFileMagic {
    <# Identifies a file by its header bytes (magic number). Returns the type name or ''. #>
    param([byte[]]$Head, [byte[]]$IsoProbe = $null)
    $hex = -join ($Head | Select-Object -First 32 | ForEach-Object { $_.ToString('X2') })
    foreach ($m in $script:WfxMagic) {
        if ($m.O -eq 0 -and $hex.StartsWith($m.H)) { return $m }
        if ($m.O -gt 0 -and $IsoProbe) { $ph = -join ($IsoProbe | ForEach-Object { $_.ToString('X2') }); if ($ph.StartsWith($m.H)) { return $m } }
    }
    # Text-ish fallbacks
    $s = [Text.Encoding]::ASCII.GetString($Head, 0, [Math]::Min(64, $Head.Length))
    if ($s -match '^#!') { return @{ T = 'Script (shebang)'; E = @() } }
    if ($s -match '^(?i)<\?xml') { return @{ T = 'XML'; E = @('.xml', '.config', '.manifest', '.xaml', '.svg', '.plist', '.xsl') } }
    if ($s -match '^(?i)\s*<(?:!doctype html|html)') { return @{ T = 'HTML'; E = @('.html', '.htm', '.hta', '.mht') } }
    return $null
}

function Get-WfxPrintableString {
    <# ASCII and UTF-16LE printable strings from a byte buffer (like `strings`). #>
    param([byte[]]$Bytes, [int]$MinLength = 6, [int]$Max = 5000)
    $out = New-Object System.Collections.Generic.List[string]
    $ascii = [Text.Encoding]::ASCII.GetString($Bytes)
    foreach ($m in (Get-WfxRxMatches ("[\x20-\x7E]{$MinLength,}") $ascii)) { if ($out.Count -ge $Max) { break }; $out.Add($m.Value) }
    $u16 = [Text.Encoding]::Unicode.GetString($Bytes, 0, $Bytes.Length - ($Bytes.Length % 2))
    foreach ($m in (Get-WfxRxMatches ("[\x20-\x7E]{$MinLength,}") $u16)) { if ($out.Count -ge $Max) { break }; $out.Add($m.Value) }
    , $out.ToArray()
}

function Get-WfxIocFromText {
    <# Extracts URLs, IPv4 addresses, domains, e-mail addresses and registry paths from text. #>
    param([string[]]$Text)
    $joined = $Text -join "`n"
    $pick = { param($rx) @(Get-WfxRxMatches $rx $joined | ForEach-Object { $_.Value.TrimEnd('.', ',', ')', ']', "'", '"') } | Sort-Object -Unique | Select-Object -First 200) }
    $urls = & $pick '(?i)\b(?:https?|ftp|wss?)://[^\s"''<>{}|\\^`]{4,300}'
    $ips = @(& $pick '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b' | Where-Object { $_ -notmatch '^(?:0\.|255\.)' })
    $mails = & $pick '(?i)\b[A-Z0-9._%+\-]{1,64}@[A-Z0-9.\-]{1,190}\.[A-Z]{2,24}\b'
    $doms = @(& $pick '(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|online|site|club|app|dev|cloud|me|cc|tk|su|onion|in|co|uk|de|fr|br|ir|kp|pw|ws|live|shop|link|click)\b' |
            Where-Object { $_ -notmatch '(?i)^(?:microsoft|windows|w3|xmlsoap|openxmlformats|purl|schemas)\.' })
    $reg = & $pick '(?i)\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U))\\[^\s"''<>]{3,200}'
    [pscustomobject]@{ Urls = $urls; IPv4 = $ips; Domains = $doms; Emails = $mails; RegistryPaths = $reg }
}

function Get-WfxPeInfo {
    <# Minimal, read-only PE header parse: machine, compile time (UTC), DLL/EXE, subsystem, section names. #>
    param([byte[]]$Bytes)
    try {
        if ($Bytes.Length -lt 0x40 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $null }
        $pe = [BitConverter]::ToInt32($Bytes, 0x3C)
        if ($pe -le 0 -or $pe + 24 -gt $Bytes.Length -or [BitConverter]::ToUInt32($Bytes, $pe) -ne 0x00004550) { return $null }
        $machine = [BitConverter]::ToUInt16($Bytes, $pe + 4)
        $nsec = [BitConverter]::ToUInt16($Bytes, $pe + 6)
        $ts = [BitConverter]::ToUInt32($Bytes, $pe + 8)
        $optSize = [BitConverter]::ToUInt16($Bytes, $pe + 20)
        $chars = [BitConverter]::ToUInt16($Bytes, $pe + 22)
        $opt = $pe + 24
        $magic = [BitConverter]::ToUInt16($Bytes, $opt)
        $subsys = if ($opt + 70 -le $Bytes.Length) { [BitConverter]::ToUInt16($Bytes, $opt + 68) } else { 0 }
        $secs = New-Object System.Collections.Generic.List[string]
        $so = $opt + $optSize
        for ($i = 0; $i -lt [Math]::Min($nsec, 40) -and ($so + 40 * $i + 8) -le $Bytes.Length; $i++) {
            $secs.Add(([Text.Encoding]::ASCII.GetString($Bytes, $so + 40 * $i, 8)).TrimEnd([char]0))
        }
        [pscustomobject]@{
            Machine      = switch ($machine) { 0x14c { 'x86' } 0x8664 { 'x64' } 0xaa64 { 'ARM64' } 0x1c4 { 'ARMNT' } default { '0x{0:X}' -f $machine } }
            Format       = switch ($magic) { 0x10b { 'PE32' } 0x20b { 'PE32+' } default { '?' } }
            IsDll        = [bool]($chars -band 0x2000)
            Subsystem    = switch ($subsys) { 1 { 'Native/driver' } 2 { 'GUI' } 3 { 'Console' } 10 { 'EFI app' } default { [string]$subsys } }
            CompiledUtc  = if ($ts) { ConvertTo-WfxUtcString ([DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddSeconds($ts)) } else { '' }
            Sections     = @($secs)
            PackerHint   = (@($secs | Where-Object { $_ -match '(?i)^(?:UPX\d?|\.aspack|\.adata|\.themida|\.vmp\d|\.petite|\.nsp\d|MPRESS\d)$' }) -join ',')
        }
    } catch { return $null }
}

function Get-WfxFileTriage {
    <#
    .SYNOPSIS
        Read-only forensic profile of one or more files — the "what is this file?" Swiss-army knife for
        incident responders and CTF players. Nothing is ever executed or modified.
    .DESCRIPTION
        For each file: size and UTC timestamps; MD5 / SHA-1 / SHA-256; true type from magic bytes and whether
        the extension lies about it; entropy (packed/encrypted?); Mark-of-the-Web zone + download URL;
        alternate data streams; Authenticode status and signer; PE header facts (machine, compile time,
        sections, packer hints); and optionally printable strings with extracted IOCs (URLs, IPs, domains,
        e-mails, registry paths). Reads at most -MaxReadMB of each file.
    .PARAMETER Path        Files (wildcards allowed) or pipeline input from Get-ChildItem.
    .PARAMETER Strings     Also extract printable strings and IOCs.
    .PARAMETER MinStringLength Minimum string length (default 6).
    .PARAMETER MaxReadMB   Bytes read per file for entropy/strings/PE parsing (default 8).
    .EXAMPLE
        Get-WfxFileTriage .\suspicious.bin -Strings | Format-List
    .EXAMPLE
        Get-ChildItem $env:USERPROFILE\Downloads -File | Get-WfxFileTriage | Where-Object ExtensionMismatch
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][Alias('FullName')][string[]]$Path,
        [switch]$Strings,
        [ValidateRange(3, 64)][int]$MinStringLength = 6,
        [ValidateRange(1, 512)][int]$MaxReadMB = 8
    )
    process {
        foreach ($pp in $Path) {
            $items = @(Get-Item -Path $pp -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })
            if (-not $items.Count) { Write-Warning "Not found or not a file: $pp"; continue }
            foreach ($it in $items) {
                $full = $it.FullName
                $bytes = [byte[]]@()
                $iso = $null
                try {
                    $fs = [IO.File]::Open($full, 'Open', 'Read', 'ReadWrite')
                    try {
                        $len = [int][Math]::Min([int64]$MaxReadMB * 1MB, $fs.Length)
                        $bytes = New-Object byte[] $len
                        $read = 0; while ($read -lt $len) { $n = $fs.Read($bytes, $read, $len - $read); if ($n -le 0) { break }; $read += $n }
                        if ($fs.Length -gt 32774) {
                            $iso = New-Object byte[] 5; [void]$fs.Seek(32769, 'Begin'); [void]$fs.Read($iso, 0, 5)
                        }
                    } finally { $fs.Dispose() }
                } catch { Write-Warning "Cannot read $full`: $($_.Exception.Message)"; continue }

                $hashes = @{}
                foreach ($alg in 'MD5', 'SHA1', 'SHA256') { try { $hashes[$alg] = (Get-FileHash -LiteralPath $full -Algorithm $alg -ErrorAction Stop).Hash } catch { $hashes[$alg] = '' } }
                $magic = if ($bytes.Length) { Get-WfxFileMagic -Head ($bytes[0..([Math]::Min(63, $bytes.Length - 1))]) -IsoProbe $iso } else { $null }
                $ext = $it.Extension.ToLowerInvariant()
                $mismatch = [bool]($magic -and @($magic.E).Count -and ($ext -notin @($magic.E)))
                $motw = Get-WfxZoneId $full
                $streams = @()
                if (Test-WfxWindows) { try { $streams = @(Get-Item -LiteralPath $full -Stream * -ErrorAction Stop | Where-Object { $_.Stream -ne ':$DATA' } | ForEach-Object { "$($_.Stream) ($($_.Length) B)" }) } catch {} }
                $sig = $null
                if ((Test-WfxWindows) -and ($magic.T -like 'PE*' -or $ext -in @('.ps1', '.psm1', '.msi', '.cab', '.cat', '.vbs', '.js'))) {
                    try { $a = Get-AuthenticodeSignature -LiteralPath $full -ErrorAction Stop; $sig = [pscustomobject]@{ Status = [string]$a.Status; Signer = if ($a.SignerCertificate) { $a.SignerCertificate.Subject } else { '' }; Thumbprint = if ($a.SignerCertificate) { $a.SignerCertificate.Thumbprint } else { '' } } } catch {}
                }
                $str = @(); $iocs = $null
                if ($Strings -and $bytes.Length) {
                    $str = Get-WfxPrintableString -Bytes $bytes -MinLength $MinStringLength
                    $iocs = Get-WfxIocFromText -Text $str
                }
                $ent = if ($bytes.Length) { Get-WfxEntropy ([byte[]]$bytes) } else { 0.0 }
                [pscustomobject]@{
                    PSTypeName        = 'WinForensicX.FileTriage'
                    Path              = $full
                    Size              = $it.Length
                    CreatedUtc        = ConvertTo-WfxUtcString $it.CreationTimeUtc
                    ModifiedUtc       = ConvertTo-WfxUtcString $it.LastWriteTimeUtc
                    AccessedUtc       = ConvertTo-WfxUtcString $it.LastAccessTimeUtc
                    MD5               = $hashes.MD5
                    SHA1              = $hashes.SHA1
                    SHA256            = $hashes.SHA256
                    FileType          = if ($magic) { $magic.T } else { 'unknown / data' }
                    Extension         = $ext
                    ExtensionMismatch = $mismatch
                    Entropy           = $ent
                    EntropyHint       = if ($ent -ge 7.5) { 'near-random: compressed, encrypted or packed' } elseif ($ent -ge 6.5) { 'high: compressed sections likely' } elseif ($ent -le 1) { 'very low: mostly constant / padding' } else { 'normal' }
                    Zone              = $motw.Zone
                    HostUrl           = $motw.HostUrl
                    ReferrerUrl       = $motw.ReferrerUrl
                    AlternateStreams  = @($streams)
                    Signature         = $sig
                    PE                = (Get-WfxPeInfo -Bytes $bytes)
                    BytesExamined     = $bytes.Length
                    StringCount       = @($str).Count
                    Strings           = if ($Strings) { @($str | Select-Object -First 300) } else { @() }
                    Iocs              = $iocs
                }
            }
        }
    }
}
