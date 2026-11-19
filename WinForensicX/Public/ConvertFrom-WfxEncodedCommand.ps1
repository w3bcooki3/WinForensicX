function ConvertFrom-WfxEncodedCommand {
    <#
    .SYNOPSIS
        Safely decodes obfuscated command payloads for analysis — PowerShell -EncodedCommand, Base64
        (UTF-16LE / UTF-8), gzip-wrapped Base64, and nested FromBase64String('...') layers.
        DECODE ONLY: nothing is ever executed.
    .PARAMETER InputObject A full command line (the -enc argument is located automatically) or a raw Base64 string.
    .PARAMETER Depth       How many nested FromBase64String layers to follow (default 3).
    .EXAMPLE
        ConvertFrom-WfxEncodedCommand 'powershell -nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAaQAnAA=='
    .EXAMPLE
        Get-Content .\blob.txt -Raw | ConvertFrom-WfxEncodedCommand
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$InputObject,
        [ValidateRange(1, 10)][int]$Depth = 3
    )
    process {
        $layers = [System.Collections.Generic.List[object]]::new()
        $text = Get-WfxEncodedCommandPayload $InputObject
        $how = '-EncodedCommand argument'
        if (-not $text) { $text = ConvertFrom-WfxBase64Text $InputObject; $how = 'raw Base64' }
        if (-not $text) {
            Write-Warning 'No decodable -EncodedCommand argument or Base64 payload was found.'
            return
        }
        $layers.Add([pscustomobject]@{ Layer = 1; Source = $how; Text = $text })
        $cur = $text
        for ($i = 2; $i -le $Depth; $i++) {
            $m = [regex]::Match($cur, '(?i)FromBase64String\s*\(\s*["'']([A-Za-z0-9+/=\s]{16,})["'']')
            if (-not $m.Success) { $m = [regex]::Match($cur, '(?i)(?:^|\s)[-/]e(?:nc\w*|c)?\s+([A-Za-z0-9+/=]{16,})') }
            if (-not $m.Success) { break }
            $next = ConvertFrom-WfxBase64Text $m.Groups[1].Value
            if (-not $next) { break }
            $layers.Add([pscustomobject]@{ Layer = $i; Source = 'nested Base64'; Text = $next })
            $cur = $next
        }
        $iocs = Get-WfxIocFromText -Text @($layers | ForEach-Object Text)
        [pscustomobject]@{
            PSTypeName = 'WinForensicX.DecodedCommand'
            Decoded    = $cur
            Layers     = $layers.ToArray()
            Rules      = @(try { Test-WfxCommandLine -CommandLine $cur -Image 'powershell.exe' | ForEach-Object { "$($_.id): $($_.title)" } } catch { "rule pack unavailable: $($_.Exception.Message)" })
            Iocs       = $iocs
            Note       = 'Decoded for analysis only. Nothing was executed.'
        }
    }
}
