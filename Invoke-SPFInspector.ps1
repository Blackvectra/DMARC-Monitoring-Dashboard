#Requires -Version 5.1
<#
.SYNOPSIS
    DMARC Monitoring - SPF Chain Inspector + DKIM Key Inspector

.DESCRIPTION
    Recursively traverses SPF include chains showing full tree with lookup counts.
    Inspects DKIM public key records for known selectors.
    Called by the dashboard to generate HTML visualization.

.PARAMETER Domain
    Domain to inspect

.PARAMETER OutputHTML
    Return HTML output for WebBrowser control (default: $true)

.PARAMETER OutputPath
    Write HTML to file instead of returning it

.EXAMPLE
    .\Invoke-SPFInspector.ps1 -Domain "yourdomain.com"
    .\Invoke-SPFInspector.ps1 -Domain "ndaco.org" -OutputPath "D:\DMARC\Reports\spf_ndaco.html"

.NOTES
    Version  : 1.0.0
    Engineer : Matthew Levorson, DMARC Monitoring
    Updated  : 2026-05-10
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]  [string]$Domain,
    [Parameter(Mandatory=$false)] [switch]$OutputHTML = $true,
    [Parameter(Mandatory=$false)] [string]$OutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region SPF Chain Traversal
$script:LookupCount = 0

function Get-SPFNode {
    param(
        [string]$Domain,
        [int]$Depth=0,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    if (-not $Visited) { $Visited = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase) }

    $node = [PSCustomObject]@{
        Domain      = $Domain
        Record      = ''
        Mechanisms  = [System.Collections.Generic.List[PSCustomObject]]::new()
        Children    = [System.Collections.Generic.List[PSCustomObject]]::new()
        Depth       = $Depth
        NodeLookups = 0
        Error       = ''
        IsRedirect  = $false
    }

    if ($Depth -gt 10) { $node.Error = "Max depth reached"; return $node }
    if (-not $Visited.Add($Domain)) {
        $node.Error = "SPF cycle detected at $Domain (already traversed in this chain)"
        return $node
    }

    try {
        $dns  = Resolve-DnsName -Name $Domain -Type TXT -EA Stop
        $spfRec = $dns | Where-Object { $_.Strings -match 'v=spf1' } | Select-Object -First 1
        if (-not $spfRec) {
            $node.Error = "No SPF record found"
            return $node
        }
        $spf = ($spfRec.Strings -join '')
        if ([string]::IsNullOrWhiteSpace($spf)) {
            $node.Error = "No SPF record found"
            return $node
        }
        $node.Record = $spf

        $terms = $spf -split '\s+' | Where-Object { $_ -and $_ -ne 'v=spf1' }

        foreach ($term in $terms) {
            $qualifier = if ($term -match '^([+~?-])') { $Matches[1] } else { '+' }
            $mechTerm  = $term -replace '^[+~?-]',''

            if ($mechTerm -match '^include:(.+)') {
                $incDomain = $Matches[1]
                $script:LookupCount++; $node.NodeLookups++
                $node.Mechanisms.Add([PSCustomObject]@{ Type='include'; Value=$incDomain; Qualifier=$qualifier; CountsAsLookup=$true })
                if ($Depth -lt 10) { $node.Children.Add((Get-SPFNode -Domain $incDomain -Depth ($Depth+1) -Visited $Visited)) }

            } elseif ($mechTerm -match '^redirect=(.+)') {
                $reDomain = $Matches[1]
                $script:LookupCount++; $node.NodeLookups++; $node.IsRedirect = $true
                $node.Mechanisms.Add([PSCustomObject]@{ Type='redirect'; Value=$reDomain; Qualifier=$qualifier; CountsAsLookup=$true })
                if ($Depth -lt 10) { $node.Children.Add((Get-SPFNode -Domain $reDomain -Depth ($Depth+1) -Visited $Visited)) }

            } elseif ($mechTerm -match '^(a|mx|exists)') {
                $script:LookupCount++; $node.NodeLookups++
                $node.Mechanisms.Add([PSCustomObject]@{ Type=($mechTerm -split ':')[0]; Value=$mechTerm; Qualifier=$qualifier; CountsAsLookup=$true })

            } elseif ($mechTerm -match '^ip[46]:(.+)') {
                $node.Mechanisms.Add([PSCustomObject]@{ Type='ip'; Value=$mechTerm; Qualifier=$qualifier; CountsAsLookup=$false })

            } elseif ($mechTerm -match '^([+~?-]?all)$') {
                $node.Mechanisms.Add([PSCustomObject]@{ Type='all'; Value=$mechTerm; Qualifier=$qualifier; CountsAsLookup=$false })
            } else {
                $node.Mechanisms.Add([PSCustomObject]@{ Type='other'; Value=$mechTerm; Qualifier=$qualifier; CountsAsLookup=$false })
            }
        }
    } catch {
        $node.Error = "DNS lookup failed: $_"
    }

    return $node
}
#endregion

#region DKIM Key Inspector
function Get-DKIMKeys {
    param([string]$Domain)

    $knownSelectors = @(
        'google','selector1','selector2','s1','s2','s3','k1','k2',
        'dkim','mail','email','default','exchange','smtp','proofpoint',
        'mimecast','barracuda','amazonses','mandrill','sendgrid','brevo',
        'fm1','fm2','fm3','everlytickey1','everlytickey2','m1','m2',
        'sig1','sig2','postfix','zoho','office365','em','em1','em2',
        'google._domainkey','scph0816','scph1217','scph0718'
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($selector in $knownSelectors) {
        try {
            $dns    = Resolve-DnsName -Name "$selector._domainkey.$Domain" -Type TXT -EA Stop
            $dkimTxt = ($dns | Where-Object { $_.Strings -match 'v=DKIM1|p=' } | Select-Object -First 1).Strings -join ''
            if (-not $dkimTxt) { continue }

            # Extract key
            $pMatch  = [regex]::Match($dkimTxt, 'p=([A-Za-z0-9+/=]+)')
            $keyData = if ($pMatch.Success) { $pMatch.Groups[1].Value } else { '' }
            $alg     = if ($dkimTxt -match 'a=([^;]+)') { $Matches[1] } else { 'rsa' }
            $flags   = if ($dkimTxt -match 'f=([^;]+)') { $Matches[1] } else { '' }

            # Check key strength
            $keyLength = 0; $keyStatus = 'unknown'
            if ($keyData) {
                try {
                    $keyBytes  = [Convert]::FromBase64String($keyData)
                    $keyLength = $keyBytes.Length * 8  # approximate bit length
                    $keyStatus = if ($keyLength -ge 2048)     { 'strong'    } `
                            elseif ($keyLength -ge 1024)      { 'acceptable'} `
                            elseif ($keyLength -gt 0)         { 'WEAK'      } `
                            else                              { 'empty-key' }
                } catch { $keyStatus = 'parse-error' }
            } elseif ($dkimTxt -match 'p=\s*;|p=\s*$') {
                $keyStatus = 'REVOKED'
            }

            $results.Add([PSCustomObject]@{
                Domain    = $Domain
                Selector  = $selector
                Algorithm = $alg
                KeyLength = $keyLength
                KeyStatus = $keyStatus
                Flags     = $flags
                RawRecord = ($dkimTxt -replace 'p=[A-Za-z0-9+/=]{20,}','p=[...key truncated...]')
            })
        } catch {}
    }

    return $results
}
#endregion

#region HTML Rendering
# Encode third-party text (domain names, mechanism values, error text)
# before interpolating into HTML so a malicious upstream SPF can't break
# the page layout or inject script.
function HtmlEnc {
    param([object]$s)
    if ($null -eq $s) { return '' }
    return [System.Web.HttpUtility]::HtmlEncode([string]$s)
}

function ConvertTo-SPFNodeHTML {
    param([PSCustomObject]$Node, [int]$TotalLookups)

    $indent    = $Node.Depth * 28
    $hasErr    = -not [string]::IsNullOrWhiteSpace($Node.Error)
    $domColor  = if ($hasErr) { '#F85149' } elseif ($Node.Depth -eq 0) { '#79C0FF' } else { '#CDD9E5' }
    $bgColor   = if ($Node.Depth -eq 0) { '#1A2332' } else { '#0D1117' }

    $lookupPill = if ($Node.Depth -eq 0) {
        $color = if ($TotalLookups -ge 10) { '#F85149' } elseif ($TotalLookups -ge 8) { '#D29922' } else { '#3FB950' }
        "<span style='background:$color;color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:bold;margin-left:8px'>$TotalLookups / 10 DNS lookups</span>"
    } else { '' }

    $mechHTML = ''
    foreach ($m in $Node.Mechanisms) {
        $mColor = switch ($m.Qualifier) {
            '+' { if ($m.Type -eq 'all') { '#F85149' } else { '#3FB950' } }
            '-' { '#F85149' }
            '~' { '#D29922' }
            '?' { '#6E7681' }
            default { '#3FB950' }
        }
        $icon = switch ($m.Type) {
            'include'  { '&#x21AA;' }
            'redirect' { '&#x2192;' }
            'ip'       { '&#x1F310;' }
            'a'        { 'A' }
            'mx'       { 'MX' }
            'all'      { '&#x2731;' }
            default    { '&bull;' }
        }
        $lookupBadge = if ($m.CountsAsLookup) { "<span style='background:#21262D;color:#6E7681;padding:1px 5px;border-radius:3px;font-size:9px;margin-left:4px'>DNS lookup</span>" } else { '' }
        $mechHTML += "<div style='display:inline-block;background:#21262D;border-radius:4px;padding:2px 8px;margin:2px;font-size:11px;font-family:monospace'><span style='color:$mColor'>$icon $(HtmlEnc $m.Qualifier)$(HtmlEnc $m.Type)</span><span style='color:#8B949E'>:$(HtmlEnc $m.Value)</span>$lookupBadge</div>"
    }

    $errHTML = if ($hasErr) { "<div style='color:#F85149;font-size:11px;margin-top:4px'>&#x26A0; $(HtmlEnc $Node.Error)</div>" } else { '' }
    $recordHTML = if ($Node.Record) { "<div style='font-family:monospace;font-size:10px;color:#6E7681;word-break:break-all;margin-top:4px;background:#0A0D13;padding:4px 8px;border-radius:3px'>$(HtmlEnc $Node.Record)</div>" } else { '' }

    $html = @"
<div style='margin-left:${indent}px;margin-bottom:6px'>
<div style='background:$bgColor;border:1px solid #30363D;border-radius:6px;padding:10px 14px'>
<div style='display:flex;align-items:center;margin-bottom:6px'>
<span style='color:$domColor;font-weight:600;font-size:13px'>$(HtmlEnc $Node.Domain)</span>$lookupPill
</div>
<div>$mechHTML</div>
$recordHTML$errHTML
</div>
"@

    foreach ($child in $Node.Children) {
        $html += ConvertTo-SPFNodeHTML -Node $child -TotalLookups $TotalLookups
    }

    $html += "</div>"
    return $html
}

function Build-SPFInspectorHTML {
    param([string]$Domain)

    $script:LookupCount = 0
    $tree   = Get-SPFNode -Domain $Domain -Depth 0
    $total  = $script:LookupCount
    $status = if ($total -ge 10) { "<span style='color:#F85149'>⛔ PermError risk ($total/10 lookups)</span>" } `
         elseif ($total -ge 8)   { "<span style='color:#D29922'>⚠ Near limit ($total/10 lookups)</span>" } `
         else                    { "<span style='color:#3FB950'>✓ OK ($total/10 lookups)</span>" }

    $dkimKeys = Get-DKIMKeys -Domain $Domain
    $dkimHTML = if ($dkimKeys.Count -gt 0) {
        $rows = ($dkimKeys | ForEach-Object {
            $kColor = switch ($_.KeyStatus) { 'strong' { '#3FB950' } 'acceptable' { '#D29922' } 'WEAK' { '#F85149' } 'REVOKED' { '#F85149' } default { '#6E7681' } }
            $bg = if ($_.KeyStatus -eq 'WEAK' -or $_.KeyStatus -eq 'REVOKED') { '#2D1A1A' } else { '' }
            "<tr style='background:$bg'><td style='padding:7px 10px;font-family:monospace;color:#79C0FF'>$(HtmlEnc $_.Selector)</td><td style='padding:7px 10px'>$(HtmlEnc $_.Algorithm)</td><td style='padding:7px 10px;color:$kColor;font-weight:600'>$(HtmlEnc $_.KeyStatus)</td><td style='padding:7px 10px;color:#6E7681'>~$($_.KeyLength) bits</td></tr>"
        }) -join ''
        @"
<div style='margin-top:20px'>
<h3 style='color:#CDD9E5;font-size:13px;margin:0 0 10px'>DKIM Key Inspector &#8212; $($dkimKeys.Count) selector(s) found</h3>
<table style='width:100%;border-collapse:collapse;font-size:12px'>
<tr style='background:#21262D'><th style='padding:7px 10px;text-align:left;color:#6E7681'>SELECTOR</th><th style='padding:7px 10px;text-align:left;color:#6E7681'>ALGORITHM</th><th style='padding:7px 10px;text-align:left;color:#6E7681'>STATUS</th><th style='padding:7px 10px;text-align:left;color:#6E7681'>KEY LENGTH</th></tr>
$rows
</table>
</div>
"@
    } else { "<div style='color:#6E7681;font-size:12px;margin-top:16px'>No DKIM keys found for common selectors on $(HtmlEnc $Domain).</div>" }

    $treeHTML = ConvertTo-SPFNodeHTML -Node $tree -TotalLookups $total
    $domEnc = HtmlEnc $Domain

    return @"
<!DOCTYPE html>
<html><head>
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta charset="UTF-8">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0D1117;color:#E6EDF3;font-family:'Segoe UI',Arial,sans-serif;padding:16px;overflow-y:auto}</style>
</head>
<body>
<div style='max-width:900px'>
<div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:16px'>
<div>
<h2 style='color:#E6EDF3;font-size:16px;margin-bottom:4px'>SPF Chain Inspector &#8212; $domEnc</h2>
<div style='font-size:13px'>$status</div>
</div>
</div>
$treeHTML
$dkimHTML
</div>
</body></html>
"@
}
#endregion

# Main
$html = Build-SPFInspectorHTML -Domain $Domain

if ($OutputPath) {
    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "SPF/DKIM report: $OutputPath" -ForegroundColor Green
} else {
    return $html
}
