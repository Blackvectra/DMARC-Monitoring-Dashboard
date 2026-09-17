#Requires -Version 5.1
<#
.SYNOPSIS
    DMARC Monitor Dashboard v5.0.0
.DESCRIPTION
    Full DMARCian/Valimail-class dashboard for the DMARC monitoring engine.
    Domain sidebar with compliance scores. 8 tabs. Per-domain views.
    Settings persist to Windows Registry (DPAPI-encrypted for secrets).
.NOTES
    Engineer: DMARC Monitoring Dashboard
    Launch:   pwsh -STA -ExecutionPolicy Bypass -File .\Start-DMARCDashboard.ps1
#>

#region Relaunch (PS7 + STA)
if (-not $env:DMARCMONITOR_LAUNCHED) {
    $env:DMARCMONITOR_LAUNCHED = "1"
    $pwsh7 = Get-Command pwsh -EA SilentlyContinue
    if ($PSVersionTable.PSVersion.Major -lt 7 -and $pwsh7) {
        & pwsh -STA -ExecutionPolicy Bypass -File $MyInvocation.MyCommand.Path
        $env:DMARCMONITOR_LAUNCHED = $null; exit
    }
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        $exe = if ($pwsh7) { "pwsh" } else { "powershell" }
        & $exe -STA -ExecutionPolicy Bypass -File $MyInvocation.MyCommand.Path
        $env:DMARCMONITOR_LAUNCHED = $null; exit
    }
    $env:DMARCMONITOR_LAUNCHED = $null
}
#endregion

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem

# TLS 1.2+1.3 hardening
try {
    $tls12 = [System.Net.SecurityProtocolType]::Tls12
    $tls13 = [System.Enum]::ToObject([System.Net.SecurityProtocolType], 12288)
    [System.Net.ServicePointManager]::SecurityProtocol = $tls12 -bor $tls13
} catch { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 }

# IE11 emulation for WebBrowser control (required for Chart.js + Leaflet)
try {
    $wbReg = "HKCU:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"
    $wbExe = [System.IO.Path]::GetFileName([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
    if (-not (Test-Path $wbReg)) { New-Item -Path $wbReg -Force | Out-Null }
    Set-ItemProperty -Path $wbReg -Name $wbExe -Value 11001 -Type DWord -Force -EA Stop
} catch {}

$script:RegPath        = "HKCU:\Software\DMARCMonitor"
$script:ScriptDir      = Split-Path $MyInvocation.MyCommand.Path -Parent
$script:EngineScript   = Join-Path $script:ScriptDir "Invoke-DMARCReporter.ps1"
$script:SPFScript      = Join-Path $script:ScriptDir "Invoke-SPFInspector.ps1"
$script:ReportScript   = Join-Path $script:ScriptDir "Invoke-HTMLReportGenerator.ps1"
$script:RemediationScript = Join-Path $script:ScriptDir "Invoke-DNSRemediation.ps1"
$script:PSVer          = $PSVersionTable.PSVersion.Major
$script:SelectedDomain = "All Domains"

#region Registry helpers
function Set-RegEncrypted { param([string]$Name,[string]$Value)
    if (-not (Test-Path $script:RegPath)) { New-Item -Path $script:RegPath -Force | Out-Null }
    $enc = (ConvertTo-SecureString -String $Value -AsPlainText -Force) | ConvertFrom-SecureString
    Set-ItemProperty -Path $script:RegPath -Name $Name -Value $enc
}
function Get-RegDecrypted { param([string]$Name)
    try {
        $enc = (Get-ItemProperty -Path $script:RegPath -Name $Name -EA Stop).$Name
        $ss  = $enc | ConvertTo-SecureString
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        $val = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        return $val
    } catch { return $null }
}
function Set-RegPlain { param([string]$Name,$Value)
    if (-not (Test-Path $script:RegPath)) { New-Item -Path $script:RegPath -Force | Out-Null }
    Set-ItemProperty -Path $script:RegPath -Name $Name -Value $Value
}
function Get-RegPlain { param([string]$Name)
    try { return (Get-ItemProperty -Path $script:RegPath -Name $Name -EA Stop).$Name } catch { return $null }
}

function Get-AllSettings {
    return [PSCustomObject]@{
        TenantId       = Get-RegDecrypted "TenantId"
        ClientId       = Get-RegDecrypted "ClientId"
        MailboxAddress = Get-RegDecrypted "MailboxAddress"
        CertThumbprint = Get-RegPlain     "CertThumbprint"
        CertStore      = Get-RegPlain     "CertStore"
        WorkingDir     = Get-RegPlain     "WorkingDir"
        RetentionDays  = Get-RegPlain     "RetentionDays"
        SourceFolder   = Get-RegPlain     "SourceFolder"
        EnableGeoLookup             = Get-RegPlain "EnableGeoLookup"
        GeoAPIToken                 = Get-RegPlain "GeoAPIToken"
        EnableAlerts                = Get-RegPlain "EnableAlerts"
        AlertThresholdPct           = Get-RegPlain "AlertThresholdPct"
        AlertEmailTo                = Get-RegPlain "AlertEmailTo"
        TeamsWebhookUrl             = Get-RegDecrypted "TeamsWebhookUrl"
        EnableNewSenderAlerts       = Get-RegPlain "EnableNewSenderAlerts"
        EnableVolumeAnomalyAlerts   = Get-RegPlain "EnableVolumeAnomalyAlerts"
        VolumeMultiplier            = Get-RegPlain "VolumeMultiplier"
        EnableDNSHealthCheck        = Get-RegPlain "EnableDNSHealthCheck"
        EnableCousinDomainDetection = Get-RegPlain "EnableCousinDomainDetection"
        EnableReportingCoverage     = Get-RegPlain "EnableReportingCoverage"
        EnableDailyDigest           = Get-RegPlain "EnableDailyDigest"
        DigestEmailTo               = Get-RegPlain "DigestEmailTo"
        DigestHour                  = Get-RegPlain "DigestHour"
        EnableMTASTSCheck           = Get-RegPlain "EnableMTASTSCheck"
        EnableBIMI                  = Get-RegPlain "EnableBIMI"
        EnableDKIMTracking          = Get-RegPlain "EnableDKIMTracking"
    }
}

function Test-SettingsComplete {
    $s = Get-AllSettings
    return (-not [string]::IsNullOrWhiteSpace($s.TenantId) -and -not [string]::IsNullOrWhiteSpace($s.ClientId) -and
            -not [string]::IsNullOrWhiteSpace($s.MailboxAddress) -and -not [string]::IsNullOrWhiteSpace($s.CertThumbprint) -and
            -not [string]::IsNullOrWhiteSpace($s.CertStore) -and -not [string]::IsNullOrWhiteSpace($s.WorkingDir) -and
            $s.RetentionDays -gt 0 -and -not [string]::IsNullOrWhiteSpace($s.SourceFolder))
}
function Test-GraphModule { return ($null -ne (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) }
#endregion

#region Culture-invariant + HTML-encode helpers
# PowerShell's "$double" interpolation uses CurrentCulture, which produces
# "12,5" instead of "12.5" on non-en-US locales - that breaks every SVG
# attribute and any JS/JSON we emit. These helpers force invariant output.
function Inv { param($n) ([double]$n).ToString('0.###', [cultureinfo]::InvariantCulture) }
# HTML-encode third-party text (org names, fail reasons, override reasons)
# before interpolating into the generated dashboard panels.
function HtmlEnc {
    param([object]$s)
    if ($null -eq $s) { return '' }
    $t = [string]$s
    if ([string]::IsNullOrEmpty($t)) { return '' }
    return $t.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}
#endregion

#region Data loading
function Get-AllKnownDomains {
    $cfg = Get-AllSettings; $domains = @()
    if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return @("All Domains") }
    $progFile = Join-Path $cfg.WorkingDir "State\progression.json"
    if (Test-Path $progFile) { try { (Get-Content $progFile -Raw | ConvertFrom-Json).domains.PSObject.Properties | ForEach-Object { $domains += $_.Value.domain } } catch {} }
    $rptDir = Join-Path $cfg.WorkingDir "Reports"
    Get-ChildItem $rptDir -Filter "dmarc_aggregate_*.csv" -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3 |
        ForEach-Object { try { (Import-Csv $_.FullName | Select-Object -ExpandProperty Domain -Unique) | ForEach-Object { $domains += $_ } } catch {} }
    return @("All Domains") + ($domains | Sort-Object -Unique)
}

function Get-DomainScore {
    param([string]$Domain)
    $cfg = Get-AllSettings; if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return 0 }
    $score = 0; $policy = 'unknown'; $safeKey = $Domain -replace '[^a-zA-Z0-9_]','_'
    $rptDir = Join-Path $cfg.WorkingDir "Reports"; $cutoff = (Get-Date).AddDays(-7)
    $data = @()
    Get-ChildItem $rptDir -Filter "dmarc_aggregate_*.csv" -EA SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cutoff } |
        ForEach-Object { try { $data += Import-Csv $_.FullName | Where-Object { $_.Domain -eq $Domain } } catch {} }
    $pFile = Join-Path $cfg.WorkingDir "State\progression.json"
    if (Test-Path $pFile) { try { $p = (Get-Content $pFile -Raw | ConvertFrom-Json).domains.$safeKey; if ($p) { $policy = $p.currentPolicy } } catch {} }
    if ($policy -eq 'unknown' -and $data.Count -gt 0) { $policy = $data[0].Policy }
    switch ($policy) { 'reject' { $score += 35 } 'quarantine' { $score += 20 } }
    $pct = if ($data.Count -gt 0 -and $data[0].PCTPct) { [int]$data[0].PCTPct } else { 100 }
    if ($pct -ge 100) { $score += 10 } elseif ($pct -ge 50) { $score += 5 }
    if ($data.Count -gt 0) {
        $p = ($data | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
        $f = ($data | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
        $t = [int]$p + [int]$f; $r = if ($t -gt 0) { [math]::Round(($p/$t)*100,1) } else { 0 }
        if ($r -ge 98) { $score += 20 } elseif ($r -ge 95) { $score += 15 } elseif ($r -ge 85) { $score += 10 } elseif ($r -ge 70) { $score += 5 }
    }
    $dFile = Join-Path $cfg.WorkingDir "State\dns-health.json"
    if (Test-Path $dFile) { try { $d = (Get-Content $dFile -Raw | ConvertFrom-Json).domains.$safeKey
        if ($d) { if ($d.SPFStatus -eq 'hard-fail') { $score += 10 } elseif ($d.SPFStatus -eq 'soft-fail') { $score += 5 }
            if ($d.SPFLookups -ge 10) { $score -= 5 }; if ($d.IssueCount -eq 0) { $score += 5 } } } catch {} }
    $mFile = Join-Path $cfg.WorkingDir "State\mta-sts.json"
    if (Test-Path $mFile) { try { $m = (Get-Content $mFile -Raw | ConvertFrom-Json).domains.$safeKey
        if ($m) { if ($m.PolicyMode -eq 'enforce') { $score += 10 } elseif ($m.PolicyMode -eq 'testing') { $score += 5 } } } catch {} }
    $kFile = Join-Path $cfg.WorkingDir "State\dkim-selectors.json"
    if (Test-Path $kFile) { try { $k = (Get-Content $kFile -Raw | ConvertFrom-Json).domains.$safeKey
        if ($k -and -not [string]::IsNullOrWhiteSpace($k.dkimDomains)) { $score += 10 } } catch {} }
    return [math]::Max(0,[math]::Min(100,$score))
}

function Load-CSVData {
    param([string]$Pattern, [string]$DomainFilter="", [string]$ResultFilter="All", [string]$IPFilter="", [int]$DaysBack=7)
    $table = New-Object System.Data.DataTable
    $cfg = Get-AllSettings; if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return $table }
    $rptDir = Join-Path $cfg.WorkingDir "Reports"; $cutoff = (Get-Date).AddDays(-$DaysBack)
    if (-not (Test-Path $rptDir)) { return $table }
    $all = @()
    Get-ChildItem $rptDir -Filter $Pattern -EA SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cutoff } |
        Sort-Object LastWriteTime -Descending | ForEach-Object { try { $all += Import-Csv $_.FullName } catch {} }
    if (-not $all) { return $table }
    if ($DomainFilter -and $DomainFilter -ne "All Domains") { $all = $all | Where-Object { $_.Domain -eq $DomainFilter } }
    if ($ResultFilter -ne "All") {
        if ($Pattern -like "*dmarc*") { $all = $all | Where-Object { $_.DMARCResult -eq $ResultFilter } }
        else { $all = $all | Where-Object { $_.ResultType -eq $ResultFilter } }
    }
    if ($IPFilter) { $all = $all | Where-Object { $_.SourceIP -like "*$IPFilter*" -or ($_.SendingMtaIP -and $_.SendingMtaIP -like "*$IPFilter*") } }
    if (-not $all) { return $table }
    $all[0].PSObject.Properties.Name | ForEach-Object { $table.Columns.Add($_) | Out-Null }
    foreach ($r in $all) { $dr = $table.NewRow(); $r.PSObject.Properties | ForEach-Object { try { $dr[$_.Name] = $_.Value } catch {} }; $table.Rows.Add($dr) }
    return $table
}
#endregion

#region HTML builders
function New-OverviewHTML {
    param([string]$Domain)
    $cfg = Get-AllSettings
    if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>Configure settings first.</body></html>" }
    $cutoff = (Get-Date).AddDays(-7); $rptDir = Join-Path $cfg.WorkingDir "Reports"
    $all = @(); Get-ChildItem $rptDir -Filter "dmarc_aggregate_*.csv" -EA SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cutoff } |
        ForEach-Object { try { $d = Import-Csv $_.FullName; if ($Domain -ne "All Domains") { $d = $d | Where-Object { $_.Domain -eq $Domain } }; $all += $d } catch {} }
    $totalMsgs=0; $totalPass=0; $totalFail=0; $passRate=0; $policy='none'
    if ($all.Count -gt 0) {
        $p = ($all | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
        $f = ($all | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
        $totalPass=[int]$p; $totalFail=[int]$f; $totalMsgs=$totalPass+$totalFail
        $passRate = if ($totalMsgs -gt 0) { [math]::Round(($totalPass/$totalMsgs)*100,1) } else { 0 }
        $policy = if ($all[0].Policy) { $all[0].Policy } else { 'none' }
    }
    $score = if ($Domain -ne "All Domains") { Get-DomainScore -Domain $Domain } else {
        $doms = @($all | Select-Object -ExpandProperty Domain -Unique)
        if ($doms.Count -gt 0) { [math]::Round(($doms | ForEach-Object { Get-DomainScore -Domain $_ } | Measure-Object -Average).Average) } else { 0 }
    }
    $sColor = if ($score -ge 80) { '#3FB950' } elseif ($score -ge 60) { '#D29922' } else { '#F85149' }
    $pColor = switch ($policy) { 'reject' { '#3FB950' } 'quarantine' { '#D29922' } default { '#F85149' } }
    $rColor = if ($passRate -ge 95) { '#3FB950' } elseif ($passRate -ge 80) { '#D29922' } else { '#F85149' }
    $recHTML = ''
    if ($Domain -ne "All Domains") {
        $progFile = Join-Path $cfg.WorkingDir "State\progression.json"
        if (Test-Path $progFile) {
            $prog = $null; try { $prog = (Get-Content $progFile -Raw | ConvertFrom-Json).domains.($Domain -replace '[^a-zA-Z0-9_]','_') } catch {}
            if ($prog) {
                $currP = $prog.currentPolicy
                $tgtP = switch ($currP) { 'none' { 'quarantine' } 'quarantine' { 'reject' } default { 'optimized' } }
                $rThresh = if ($currP -eq 'none') { 90 } else { 95 }
                $rClr = if (($passRate -ge $rThresh -and $currP -ne 'reject') -or $currP -eq 'reject') { '#3FB950' } else { '#D29922' }
                $rTxt = if ($passRate -ge $rThresh -and $currP -ne 'reject') { "Ready to advance to p=$tgtP based on 7-day pass rate of $passRate%" } `
                   elseif ($currP -eq 'reject') { "Fully enforced at p=reject" } `
                   else { "Not ready - pass rate $passRate% (need at least $rThresh% to advance)" }
                $recHTML = "<div style='background:#161B22;border:1px solid #30363D;border-radius:6px;padding:14px;margin-bottom:16px'><div style='font-size:11px;color:#6E7681;margin-bottom:6px;font-weight:600'>ENFORCEMENT RECOMMENDATION</div><div style='color:$rClr;font-size:13px'>$rTxt</div><div style='color:#484F58;font-size:11px;margin-top:6px'>Current: p=$currP | Target: p=$tgtP | Pass rate: $passRate% (7d)</div></div>"
            }
        }
    }
    $overrideHTML = ''
    if ($all.Count -gt 0) {
        $overrides = $all | Where-Object { $_.OverrideReason -and $_.OverrideReason -ne 'none' -and $_.OverrideReason -ne '' }
        if ($overrides) {
            $orRows = ($overrides | Group-Object OverrideReason | Sort-Object Count -Descending | Select-Object -First 6 | ForEach-Object {
                $cnt = ($_.Group | Measure-Object MessageCount -Sum).Sum
                "<tr><td style='padding:5px 10px;color:#CDD9E5'>$(HtmlEnc $_.Name)</td><td style='padding:5px 10px;color:#D29922'>$cnt msgs</td><td style='padding:5px 10px;color:#6E7681;font-size:11px'>$($_.Count) records</td></tr>"
            }) -join ''
            $overrideHTML = "<div style='background:#161B22;border:1px solid #30363D;border-radius:6px;padding:14px;margin-bottom:16px'><div style='font-size:11px;color:#6E7681;margin-bottom:8px;font-weight:600'>POLICY OVERRIDE BREAKDOWN</div><table style='width:100%;border-collapse:collapse;font-size:12px'><tr style='background:#21262D'><th style='padding:5px 10px;text-align:left;color:#6E7681'>REASON</th><th style='padding:5px 10px;text-align:left;color:#6E7681'>MESSAGES</th><th style='padding:5px 10px;text-align:left;color:#6E7681'>RECORDS</th></tr>$orRows</table></div>"
        }
    }
    $failHTML = ''
    if ($all.Count -gt 0) {
        $failData = $all | Where-Object { $_.DMARCResult -eq 'fail' }
        if ($failData) {
            $frRows = ($failData | Group-Object FailReason | Sort-Object Count -Descending | ForEach-Object {
                $cnt = ($_.Group | Measure-Object MessageCount -Sum).Sum
                $c = if ($_.Name -eq 'both-fail') { '#F85149' } else { '#D29922' }
                "<tr><td style='padding:5px 10px;color:$c'>$(HtmlEnc $_.Name)</td><td style='padding:5px 10px'>$cnt msgs</td></tr>"
            }) -join ''
            $failHTML = "<div style='background:#161B22;border:1px solid #30363D;border-radius:6px;padding:14px;margin-bottom:16px'><div style='font-size:11px;color:#6E7681;margin-bottom:8px;font-weight:600'>FAILURE REASON BREAKDOWN</div><table style='width:100%;border-collapse:collapse;font-size:12px'><tr style='background:#21262D'><th style='padding:5px 10px;text-align:left;color:#6E7681'>REASON</th><th style='padding:5px 10px;text-align:left;color:#6E7681'>MESSAGES</th></tr>$frRows</table></div>"
        }
    }
    $covHTML = ''
    $covFile = Join-Path $cfg.WorkingDir "State\reporting-coverage.json"
    if (Test-Path $covFile) {
        try {
            $cov = Get-Content $covFile -Raw | ConvertFrom-Json
            $orgs = if ($Domain -ne "All Domains") { $e = $cov.domains.($Domain -replace '[^a-zA-Z0-9_]','_'); if ($e) { $e.reportingOrgs } else { '' } } `
                else { ($cov.domains.PSObject.Properties | ForEach-Object { $_.Value.reportingOrgs } | Where-Object { $_ } | Sort-Object -Unique) -join ', ' }
            if ($orgs) {
                $orgBadges = ($orgs -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { "<span style='background:#21262D;color:#CDD9E5;padding:2px 8px;border-radius:10px;font-size:11px;margin:2px;display:inline-block'>$(HtmlEnc $_)</span>" }) -join ''
                $covHTML = "<div style='background:#161B22;border:1px solid #30363D;border-radius:6px;padding:14px;margin-bottom:16px'><div style='font-size:11px;color:#6E7681;margin-bottom:8px;font-weight:600'>REPORTING ORG COVERAGE</div><div>$orgBadges</div></div>"
            }
        } catch {}
    }
    $domainTitle = if ($Domain -eq "All Domains") { "Portfolio Overview" } else { HtmlEnc $Domain }
    return @"
<!DOCTYPE html><html><head><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta charset="UTF-8">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0D1117;font-family:'Segoe UI',Arial;padding:16px;overflow-y:auto;color:#E6EDF3}</style></head><body>
<div style='max-width:880px'>
<div style='display:flex;gap:12px;margin-bottom:16px'>
<div style='background:#161B22;border:1px solid #30363D;border-radius:8px;padding:18px;text-align:center;min-width:135px'>
<div style='font-size:46px;font-weight:900;color:$sColor;line-height:1'>$score</div>
<div style='font-size:11px;color:#6E7681;margin-top:6px'>COMPLIANCE SCORE</div>
<div style='margin-top:8px;height:4px;background:#21262D;border-radius:2px'><div style='width:$($score)%;height:100%;background:$sColor;border-radius:2px'></div></div>
</div>
<div style='background:#161B22;border:1px solid #30363D;border-radius:8px;padding:18px;text-align:center;min-width:135px'>
<div style='font-size:46px;font-weight:900;color:$rColor;line-height:1'>${passRate}%</div>
<div style='font-size:11px;color:#6E7681;margin-top:6px'>PASS RATE (7d)</div>
<div style='margin-top:4px;font-size:12px;color:#3FB950'>$totalPass pass</div>
<div style='font-size:12px;color:#F85149'>$totalFail fail</div>
</div>
<div style='background:#161B22;border:1px solid #30363D;border-radius:8px;padding:18px;text-align:center;min-width:135px'>
<div style='font-size:22px;font-weight:900;color:$pColor;line-height:1.4;margin-top:10px'>p=$policy</div>
<div style='font-size:11px;color:#6E7681;margin-top:6px'>DMARC POLICY</div>
<div style='margin-top:8px;font-size:11px;color:#6E7681'>$totalMsgs total msgs</div>
</div>
<div style='background:#161B22;border:1px solid #30363D;border-radius:8px;padding:18px;flex:1'>
<div style='font-size:14px;font-weight:600;color:#E6EDF3;margin-bottom:6px'>$domainTitle</div>
<div style='font-size:11px;color:#6E7681'>7-day reporting window</div>
<div style='margin-top:10px;height:3px;background:#21262D;border-radius:2px'><div style='width:$($passRate)%;height:100%;background:$rColor;border-radius:2px'></div></div>
<div style='margin-top:8px;font-size:10px;color:#484F58'>Polled every 30 minutes</div>
</div>
</div>
$recHTML$failHTML$overrideHTML$covHTML
</div></body></html>
"@
}

function New-TrendChartHTML {
    param([string]$DomainFilter="All Domains", [int]$Days=7)
    $cfg = Get-AllSettings
    if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>Configure settings first.</body></html>" }
    $rptDir = Join-Path $cfg.WorkingDir "Reports"; $cutoff = (Get-Date).AddDays(-$Days)
    $all = @(); Get-ChildItem $rptDir -Filter "dmarc_aggregate_*.csv" -EA SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cutoff } | Sort-Object Name |
        ForEach-Object { try { $all += Import-Csv $_.FullName } catch {} }
    if (-not $all) { return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>No data for last $Days days.</body></html>" }
    $domains = if ($DomainFilter -ne "All Domains") { @($DomainFilter) } else { @($all | Select-Object -ExpandProperty Domain -Unique | Sort-Object) }
    $dates = @($all | Select-Object -ExpandProperty ReportDate -Unique | Sort-Object)
    if ($dates.Count -lt 2) {
        return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>Need at least 2 days of reports to plot a trend. Currently have $($dates.Count) day(s) of data.</body></html>"
    }
    $colors = @('#3FB950','#79C0FF','#D29922','#F85149','#BC8CFF','#FFA657','#56D364','#FF7B72','#58A6FF','#E6EDF3')

    # SVG layout. Pixel coords are always [int] so we never hit
    # CurrentCulture decimal-comma issues in the resulting markup.
    $w = 880; $h = 380; $padL = 56; $padR = 24; $padT = 44; $padB = 110
    $plotW = $w - $padL - $padR; $plotH = $h - $padT - $padB
    $xStep = $plotW / ($dates.Count - 1)

    $gridLines = ''
    foreach ($pct in 0,25,50,75,100) {
        $y = [int]($padT + $plotH - ($pct / 100.0) * $plotH)
        $gridLines += "<line x1='$padL' y1='$y' x2='$($padL + $plotW)' y2='$y' stroke='#21262D' stroke-width='1'/>"
        $gridLines += "<text x='$($padL - 8)' y='$($y + 4)' fill='#6E7681' font-size='11' font-family='Segoe UI' text-anchor='end'>$pct%</text>"
    }

    $xLabels = ''
    for ($i = 0; $i -lt $dates.Count; $i++) {
        $x = [int]($padL + ($i * $xStep))
        $xLabels += "<line x1='$x' y1='$($padT + $plotH)' x2='$x' y2='$($padT + $plotH + 4)' stroke='#30363D' stroke-width='1'/>"
        $xLabels += "<text x='$x' y='$($padT + $plotH + 18)' fill='#6E7681' font-size='10' font-family='Segoe UI' text-anchor='middle'>$(HtmlEnc $dates[$i])</text>"
    }

    $lines = ''; $legendItems = @(); $ci = 0
    foreach ($domain in $domains) {
        $color = $colors[$ci % $colors.Count]; $ci++
        $pts = @()
        for ($i = 0; $i -lt $dates.Count; $i++) {
            $d = $dates[$i]
            $rows = $all | Where-Object { $_.Domain -eq $domain -and $_.ReportDate -eq $d }
            $p = ($rows | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
            $f = ($rows | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
            $t = [int]$p + [int]$f
            if ($t -gt 0) {
                $rate = ($p / $t) * 100
                $x = [int]($padL + ($i * $xStep))
                $y = [int]($padT + $plotH - ($rate / 100.0) * $plotH)
                $pts += ,@($x, $y, [math]::Round($rate, 1))
            }
        }
        if ($pts.Count -gt 0) {
            $poly = ($pts | ForEach-Object { "$($_[0]),$($_[1])" }) -join ' '
            $lines += "<polyline points='$poly' fill='none' stroke='$color' stroke-width='2'/>"
            foreach ($pt in $pts) {
                $rateStr = (Inv $pt[2])
                $lines += "<circle cx='$($pt[0])' cy='$($pt[1])' r='4' fill='$color' stroke='#0D1117' stroke-width='1'><title>$(HtmlEnc $domain) &#8212; $rateStr%</title></circle>"
            }
        }
        $legendItems += "<span style='display:inline-block;margin:0 14px 4px 0;font-size:11px;color:#CDD9E5'><span style='display:inline-block;width:10px;height:10px;background:$color;border-radius:50%;margin-right:6px;vertical-align:middle'></span>$(HtmlEnc $domain)</span>"
    }

    $legendHTML = ($legendItems -join '')
    $title = "DMARC Pass Rate &#8212; Last $Days Days"
    $cx = [int]($w / 2); $cy = [int]($padT + $plotH / 2)

    return @"
<!DOCTYPE html><html><head><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta charset="UTF-8">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0D1117;padding:12px;font-family:'Segoe UI',Arial}</style></head><body>
<svg width="100%" viewBox="0 0 $w $h" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">
<text x="$cx" y="22" fill="#E6EDF3" font-size="14" font-weight="bold" font-family="Segoe UI" text-anchor="middle">$title</text>
<text x="14" y="$cy" fill="#6E7681" font-size="11" font-family="Segoe UI" transform="rotate(-90 14 $cy)" text-anchor="middle">Pass Rate (%)</text>
<rect x="$padL" y="$padT" width="$plotW" height="$plotH" fill="none" stroke="#30363D" stroke-width="1"/>
$gridLines
$xLabels
$lines
</svg>
<div style="margin-top:8px;color:#CDD9E5">$legendHTML</div>
</body></html>
"@
}

function New-GeoMapHTML {
    param([string]$DomainFilter="All Domains")
    $cfg = Get-AllSettings
    if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>Configure settings first.</body></html>" }
    $all=@(); Get-ChildItem (Join-Path $cfg.WorkingDir "Reports") -Filter "dmarc_aggregate_*.csv" -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3 |
        ForEach-Object { try { $all += Import-Csv $_.FullName } catch {} }
    if ($DomainFilter -ne "All Domains") { $all = $all | Where-Object { $_.Domain -eq $DomainFilter } }
    $coords = @{'US'=@(37.09,-95.71);'GB'=@(55.38,-3.44);'DE'=@(51.17,10.45);'FR'=@(46.23,2.21);'CA'=@(56.13,-106.35);'AU'=@(-25.27,133.78);'JP'=@(36.2,138.25);'CN'=@(35.86,104.20);'IN'=@(20.59,78.96);'BR'=@(-14.24,-51.93);'RU'=@(61.52,105.32);'NL'=@(52.13,5.29);'SE'=@(60.13,18.64);'NO'=@(60.47,8.47);'CH'=@(46.82,8.23);'SG'=@(1.35,103.82);'HK'=@(22.32,114.17);'KR'=@(35.91,127.77);'PL'=@(51.92,19.15);'UA'=@(48.38,31.17);'TR'=@(38.96,35.24);'ZA'=@(-30.56,22.94);'MX'=@(23.63,-102.55);'AR'=@(-38.42,-63.62);'IE'=@(53.41,-8.24);'IT'=@(41.87,12.57);'ES'=@(40.46,-3.75);'PT'=@(39.40,-8.22)}
    $countryData = @{}
    if ($all.Count -gt 0) {
        $all | Group-Object GeoCountry | Where-Object { $_.Name -and $coords.ContainsKey($_.Name) } | ForEach-Object {
            $c=$_.Name; $msgs=($_.Group|Measure-Object MessageCount -Sum).Sum
            $pass=($_.Group|Where-Object{$_.DMARCResult -eq 'pass'}|Measure-Object MessageCount -Sum).Sum
            $pct=if($msgs -gt 0){[math]::Round(($pass/$msgs)*100)}else{0}
            $color=if($pct -ge 95){'#3FB950'}elseif($pct -ge 80){'#D29922'}else{'#F85149'}
            $countryData[$c] = @{msgs=$msgs;pct=$pct;color=$color;lat=$coords[$c][0];lng=$coords[$c][1]}
        }
    }

    if ($countryData.Count -eq 0) {
        return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>No geolocated sender data yet. Enable IP geolocation in Settings and let the engine run.</body></html>"
    }

    # SVG world map: equirectangular projection (lon -> x, lat -> y).
    # Pixel coords kept as [int] to dodge CurrentCulture decimal-comma bugs.
    $mapW = 880; $mapH = 380; $mapPad = 16
    $maxMsgs = ($countryData.Values | ForEach-Object { $_.msgs } | Measure-Object -Maximum).Maximum
    if ($maxMsgs -lt 1) { $maxMsgs = 1 }

    function Get-MapXY {
        param([double]$lat, [double]$lng, [int]$w, [int]$h, [int]$pad)
        $x = [int]($pad + (($lng + 180.0) / 360.0) * ($w - 2 * $pad))
        $y = [int]($pad + ((90.0 - $lat)  / 180.0) * ($h - 2 * $pad))
        return @($x, $y)
    }

    $markers = ''
    foreach ($c in $countryData.Keys) {
        $d = $countryData[$c]
        $xy = Get-MapXY -lat $d.lat -lng $d.lng -w $mapW -h $mapH -pad $mapPad
        $r = [int][math]::Min([math]::Sqrt($d.msgs / $maxMsgs) * 22 + 5, 28)
        $cEnc = HtmlEnc $c
        $markers += "<circle cx='$($xy[0])' cy='$($xy[1])' r='$r' fill='$($d.color)' fill-opacity='0.45' stroke='$($d.color)' stroke-width='1.5'><title>$cEnc &#8212; $($d.msgs) msgs, $($d.pct)% pass</title></circle>"
        $markers += "<text x='$($xy[0])' y='$($xy[1] + 4)' fill='#E6EDF3' font-size='10' font-family='Segoe UI' font-weight='bold' text-anchor='middle' pointer-events='none'>$cEnc</text>"
    }

    # Per-country bar table sorted by volume
    $rows = ''
    foreach ($entry in ($countryData.GetEnumerator() | Sort-Object { $_.Value.msgs } -Descending)) {
        $c = $entry.Key; $d = $entry.Value
        $barW = [int]([math]::Round(($d.msgs / $maxMsgs) * 100))
        $cEnc = HtmlEnc $c
        $rows += "<tr><td style='padding:6px 10px;color:#CDD9E5;font-weight:600;width:50px'>$cEnc</td>" +
                 "<td style='padding:6px 10px;color:#6E7681;width:90px'>$($d.msgs) msgs</td>" +
                 "<td style='padding:6px 10px'><div style='background:#21262D;height:8px;border-radius:4px;width:200px'><div style='background:$($d.color);width:${barW}%;height:100%;border-radius:4px'></div></div></td>" +
                 "<td style='padding:6px 10px;color:$($d.color);width:60px;text-align:right;font-weight:600'>$($d.pct)%</td></tr>"
    }

    $mapInnerW = $mapW - 2 * $mapPad
    $mapInnerH = $mapH - 2 * $mapPad
    $mapMidX   = [int]($mapW / 2)
    $mapMidY   = [int]($mapH / 2)
    $mapRight  = $mapW - $mapPad
    $mapBottom = $mapH - $mapPad

    return @"
<!DOCTYPE html><html><head><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta charset="UTF-8">
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0D1117;font-family:'Segoe UI',Arial;padding:12px;color:#E6EDF3}</style></head><body>
<svg width="100%" viewBox="0 0 $mapW $mapH" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">
<rect x="0" y="0" width="$mapW" height="$mapH" fill="#0D1117"/>
<rect x="$mapPad" y="$mapPad" width="$mapInnerW" height="$mapInnerH" fill="none" stroke="#21262D" stroke-width="1"/>
<line x1="$mapPad" y1="$mapMidY" x2="$mapRight" y2="$mapMidY" stroke="#21262D" stroke-width="1" stroke-dasharray="3,4"/>
<line x1="$mapMidX" y1="$mapPad" x2="$mapMidX" y2="$mapBottom" stroke="#21262D" stroke-width="1" stroke-dasharray="3,4"/>
$markers
</svg>
<table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:12px">$rows</table>
</body></html>
"@
}
#endregion

#region XAML (Main Window)
[xml]$mainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="DMARC Monitor v5.0" Height="920" Width="1440" MinHeight="700" MinWidth="1100"
    Background="#0D1117" WindowStartupLocation="CenterScreen" FontFamily="Segoe UI">
<Window.Resources>
    <Style x:Key="Btn1" TargetType="Button"><Setter Property="Background" Value="#1F6FEB"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="14,7"/><Setter Property="FontSize" Value="12"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/>
        <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
            <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#388BFD"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#21262D"/><Setter Property="Foreground" Value="#484F58"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Btn2" TargetType="Button"><Setter Property="Background" Value="#21262D"/><Setter Property="Foreground" Value="#CDD9E5"/><Setter Property="BorderBrush" Value="#30363D"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="12,6"/><Setter Property="FontSize" Value="12"/><Setter Property="Cursor" Value="Hand"/>
        <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
            <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#30363D"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter Property="Foreground" Value="#484F58"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="ComboBox"><Setter Property="Background" Value="#161B22"/><Setter Property="Foreground" Value="#CDD9E5"/><Setter Property="BorderBrush" Value="#30363D"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="6,4"/><Setter Property="FontSize" Value="12"/></Style>
    <Style TargetType="TextBox"><Setter Property="Background" Value="#161B22"/><Setter Property="Foreground" Value="#CDD9E5"/><Setter Property="BorderBrush" Value="#30363D"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="6,4"/><Setter Property="FontSize" Value="12"/><Setter Property="CaretBrush" Value="#CDD9E5"/></Style>
    <Style TargetType="DataGrid"><Setter Property="Background" Value="#161B22"/><Setter Property="Foreground" Value="#CDD9E5"/><Setter Property="BorderThickness" Value="0"/><Setter Property="GridLinesVisibility" Value="Horizontal"/><Setter Property="HorizontalGridLinesBrush" Value="#21262D"/><Setter Property="RowBackground" Value="#161B22"/><Setter Property="AlternatingRowBackground" Value="#1C2028"/><Setter Property="ColumnHeaderHeight" Value="34"/><Setter Property="RowHeight" Value="30"/><Setter Property="FontSize" Value="12"/><Setter Property="SelectionMode" Value="Single"/></Style>
    <Style TargetType="DataGridColumnHeader"><Setter Property="Background" Value="#0D1117"/><Setter Property="Foreground" Value="#6E7681"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="FontSize" Value="11"/><Setter Property="Padding" Value="10,0"/><Setter Property="BorderBrush" Value="#21262D"/><Setter Property="BorderThickness" Value="0,0,1,1"/></Style>
    <Style TargetType="DataGridCell"><Setter Property="BorderThickness" Value="0"/>
        <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="DataGridCell"><Border Background="{TemplateBinding Background}" Padding="10,0"><ContentPresenter VerticalAlignment="Center"/></Border></ControlTemplate></Setter.Value></Setter>
        <Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#1F3A5F"/><Setter Property="Foreground" Value="#E6EDF3"/></Trigger></Style.Triggers>
    </Style>
    <Style TargetType="DataGridRow"><Style.Triggers>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#1F3A5F"/></Trigger>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#21262D"/></Trigger>
        <DataTrigger Binding="{Binding DMARCResult}" Value="fail"><Setter Property="Background" Value="#2D1A1A"/></DataTrigger>
        <DataTrigger Binding="{Binding isNew}" Value="True"><Setter Property="Background" Value="#2D2000"/></DataTrigger>
    </Style.Triggers></Style>
    <Style x:Key="TabStyle" TargetType="TabItem"><Setter Property="Background" Value="#161B22"/><Setter Property="Foreground" Value="#6E7681"/><Setter Property="BorderBrush" Value="#30363D"/><Setter Property="Padding" Value="14,7"/><Setter Property="FontSize" Value="12"/><Setter Property="FontWeight" Value="SemiBold"/>
        <Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Foreground" Value="#E6EDF3"/><Setter Property="Background" Value="#0D1117"/></Trigger></Style.Triggers>
    </Style>
    <Style x:Key="SidebarItem" TargetType="ListBoxItem"><Setter Property="Background" Value="Transparent"/><Setter Property="Foreground" Value="#CDD9E5"/><Setter Property="Padding" Value="10,8"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Cursor" Value="Hand"/>
        <Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#1F3A5F"/></Trigger><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#21262D"/></Trigger></Style.Triggers>
    </Style>
</Window.Resources>
<Grid>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="5"/><RowDefinition Height="170"/><RowDefinition Height="28"/></Grid.RowDefinitions>
    <Border x:Name="bannerModule" Grid.Row="0" Background="#2D2000" BorderBrush="#D29922" BorderThickness="0,0,0,1" Padding="14,7" Visibility="Collapsed">
        <DockPanel><TextBlock Text="Microsoft.Graph.Authentication module is not installed." Foreground="#D29922" FontSize="12" VerticalAlignment="Center" DockPanel.Dock="Left"/>
        <Button x:Name="btnInstallModule" Content="Install Now" DockPanel.Dock="Right" Style="{StaticResource Btn2}" Padding="10,3" FontSize="11" BorderBrush="#D29922" Foreground="#D29922" VerticalAlignment="Center"/></DockPanel>
    </Border>
    <Border x:Name="bannerCert" Grid.Row="0" Background="#2D1000" BorderBrush="#F85149" BorderThickness="0,0,0,1" Padding="14,7" Visibility="Collapsed">
        <TextBlock x:Name="txtCertBanner" Foreground="#F85149" FontSize="12" VerticalAlignment="Center"/>
    </Border>
    <Border Grid.Row="1" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
        <DockPanel Margin="16,0" Height="58">
            <StackPanel DockPanel.Dock="Left" VerticalAlignment="Center">
                <StackPanel Orientation="Horizontal">
                    <TextBlock Text="DMARC MONITOR" FontSize="15" FontWeight="Bold" Foreground="#E6EDF3"/>
                    <Border Background="#12261E" CornerRadius="4" Padding="5,2" Margin="8,0,0,0" VerticalAlignment="Center"><TextBlock x:Name="txtPSBadge" Text="PS7" Foreground="#3FB950" FontSize="10" FontWeight="SemiBold"/></Border>
                </StackPanel>
                <TextBlock x:Name="txtMailboxLabel" Text="Not configured" FontSize="11" Foreground="#6E7681"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                <Button x:Name="btnSettings"  Content="Settings"   Style="{StaticResource Btn2}" Margin="0,0,6,0"/>
                <Button x:Name="btnSchedule"  Content="Schedule"   Style="{StaticResource Btn2}" Margin="0,0,6,0"/>
                <Button x:Name="btnRefresh"   Content="Refresh"    Style="{StaticResource Btn2}" Margin="0,0,6,0"/>
                <Button x:Name="btnExport"    Content="Export"     Style="{StaticResource Btn2}" Margin="0,0,6,0"/>
                <Button x:Name="btnGenReport" Content="Report"     Style="{StaticResource Btn2}" Margin="0,0,6,0"/>
                <Button x:Name="btnRun"       Content="Run Now"    Style="{StaticResource Btn1}"/>
            </StackPanel>
        </DockPanel>
    </Border>
    <Grid Grid.Row="2">
        <Grid.ColumnDefinitions><ColumnDefinition Width="225"/><ColumnDefinition Width="1"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <Border Grid.Column="0" Background="#0A0D13">
            <DockPanel>
                <Border DockPanel.Dock="Top" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1" Padding="12,8">
                    <StackPanel><TextBlock Text="DOMAINS" Foreground="#6E7681" FontSize="10" FontWeight="SemiBold" Margin="0,0,0,6"/>
                    <TextBox x:Name="txtDomainSearch" Background="#0D1117" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="6,4" FontSize="11" CaretBrush="#CDD9E5"/></StackPanel>
                </Border>
                <ListBox x:Name="lbDomains" Background="Transparent" BorderThickness="0" ScrollViewer.HorizontalScrollBarVisibility="Disabled">
                    <ListBox.ItemContainerStyle><Style TargetType="ListBoxItem" BasedOn="{StaticResource SidebarItem}"/></ListBox.ItemContainerStyle>
                    <ListBox.ItemTemplate><DataTemplate>
                        <Grid Width="195">
                            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="42"/></Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0" VerticalAlignment="Center">
                                <TextBlock Text="{Binding DomainName}" Foreground="#CDD9E5" FontSize="12" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
                                <TextBlock Text="{Binding PolicyBadge}" Foreground="{Binding PolicyColor}" FontSize="10" Margin="0,1,0,0"/>
                            </StackPanel>
                            <Border Grid.Column="1" Background="{Binding ScoreBg}" CornerRadius="6" Width="36" Height="26" HorizontalAlignment="Right" VerticalAlignment="Center">
                                <TextBlock Text="{Binding Score}" Foreground="{Binding ScoreColor}" FontSize="12" FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                        </Grid>
                    </DataTemplate></ListBox.ItemTemplate>
                </ListBox>
            </DockPanel>
        </Border>
        <GridSplitter Grid.Column="1" Width="1" HorizontalAlignment="Stretch" Background="#21262D"/>
        <TabControl x:Name="tabMain" Grid.Column="2" Background="#0D1117" BorderThickness="0" Padding="0">
            <TabControl.Resources><Style TargetType="TabPanel"><Setter Property="Background" Value="#161B22"/></Style></TabControl.Resources>
            <TabItem Header="  Overview  " Style="{StaticResource TabStyle}"><WebBrowser x:Name="wbOverview"/></TabItem>
            <TabItem Header="  DMARC  " Style="{StaticResource TabStyle}">
                <Grid Background="#0D1117">
                    <Grid.RowDefinitions><RowDefinition Height="44"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
                            <TextBlock Text="Result" Foreground="#6E7681" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <ComboBox x:Name="cmbDMARCResult" Width="95" Margin="0,0,12,0"><ComboBoxItem Content="All" IsSelected="True"/><ComboBoxItem Content="pass"/><ComboBoxItem Content="fail"/></ComboBox>
                            <TextBlock Text="Fail Reason" Foreground="#6E7681" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <ComboBox x:Name="cmbFailReason" Width="125" Margin="0,0,12,0"><ComboBoxItem Content="All" IsSelected="True"/><ComboBoxItem Content="both-fail"/><ComboBoxItem Content="dkim-only"/><ComboBoxItem Content="spf-only"/><ComboBoxItem Content="aligned"/></ComboBox>
                            <TextBlock Text="IP" Foreground="#6E7681" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <TextBox x:Name="txtDMARCIP" Width="120" Margin="0,0,8,0"/>
                            <Button x:Name="btnDMARCFilter" Content="Apply" Style="{StaticResource Btn2}" Padding="10,4" Margin="0,0,4,0"/>
                            <Button x:Name="btnDMARCReset" Content="Clear" Style="{StaticResource Btn2}" Padding="10,4"/>
                            <TextBlock x:Name="txtDMARCCount" Foreground="#484F58" FontSize="12" VerticalAlignment="Center" Margin="14,0,0,0"/>
                        </StackPanel>
                    </Border>
                    <DataGrid Grid.Row="1" x:Name="dgDMARC" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserReorderColumns="True" CanUserResizeColumns="True" CanUserSortColumns="True" EnableRowVirtualization="True" VirtualizingPanel.IsVirtualizing="True" VirtualizingPanel.VirtualizationMode="Recycling" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Auto">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Date" Binding="{Binding ReportDate}" Width="95"/>
                            <DataGridTextColumn Header="Domain" Binding="{Binding Domain}" Width="155"/>
                            <DataGridTextColumn Header="Source IP" Binding="{Binding SourceIP}" Width="125"/>
                            <DataGridTextColumn Header="Org" Binding="{Binding OrgName}" Width="140"/>
                            <DataGridTextColumn Header="Sender" Binding="{Binding SenderClass}" Width="105"/>
                            <DataGridTextColumn Header="Count" Binding="{Binding MessageCount}" Width="60"/>
                            <DataGridTextColumn Header="DKIM" Binding="{Binding DKIMResult}" Width="55"/>
                            <DataGridTextColumn Header="SPF" Binding="{Binding SPFResult}" Width="55"/>
                            <DataGridTextColumn Header="DMARC" Binding="{Binding DMARCResult}" Width="65"/>
                            <DataGridTextColumn Header="Fail Reason" Binding="{Binding FailReason}" Width="105"/>
                            <DataGridTextColumn Header="Override" Binding="{Binding OverrideReason}" Width="115"/>
                            <DataGridTextColumn Header="Disp" Binding="{Binding Disposition}" Width="80"/>
                            <DataGridTextColumn Header="p=" Binding="{Binding Policy}" Width="55"/>
                            <DataGridTextColumn Header="pct" Binding="{Binding PCTPct}" Width="50"/>
                            <DataGridTextColumn Header="Sub?" Binding="{Binding IsSubdomain}" Width="60"/>
                            <DataGridTextColumn Header="Header From" Binding="{Binding HeaderFrom}" Width="155"/>
                            <DataGridTextColumn Header="Cousin?" Binding="{Binding IsCousinDomain}" Width="70"/>
                            <DataGridTextColumn Header="Country" Binding="{Binding GeoCountry}" Width="65"/>
                            <DataGridTextColumn Header="New?" Binding="{Binding IsNewSender}" Width="60"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            <TabItem Header="  TLS-RPT  " Style="{StaticResource TabStyle}">
                <Grid Background="#0D1117">
                    <Grid.RowDefinitions><RowDefinition Height="44"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
                            <TextBlock Text="Result Type" Foreground="#6E7681" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <ComboBox x:Name="cmbTLSResult" Width="185" Margin="0,0,12,0"><ComboBoxItem Content="All" IsSelected="True"/><ComboBoxItem Content="none"/><ComboBoxItem Content="certificate-expired"/><ComboBoxItem Content="certificate-not-trusted"/><ComboBoxItem Content="validation-failure"/><ComboBoxItem Content="starttls-not-supported"/><ComboBoxItem Content="sts-policy-fetch-error"/><ComboBoxItem Content="sts-policy-invalid"/></ComboBox>
                            <Button x:Name="btnTLSFilter" Content="Apply" Style="{StaticResource Btn2}" Padding="10,4" Margin="0,0,4,0"/>
                            <Button x:Name="btnTLSReset" Content="Clear" Style="{StaticResource Btn2}" Padding="10,4"/>
                            <TextBlock x:Name="txtTLSCount" Foreground="#484F58" FontSize="12" VerticalAlignment="Center" Margin="14,0,0,0"/>
                        </StackPanel>
                    </Border>
                    <DataGrid Grid.Row="1" x:Name="dgTLS" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserReorderColumns="True" CanUserResizeColumns="True" CanUserSortColumns="True" EnableRowVirtualization="True" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Auto">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Date" Binding="{Binding ReportDate}" Width="95"/>
                            <DataGridTextColumn Header="Domain" Binding="{Binding Domain}" Width="155"/>
                            <DataGridTextColumn Header="Org" Binding="{Binding OrgName}" Width="140"/>
                            <DataGridTextColumn Header="Policy" Binding="{Binding PolicyType}" Width="80"/>
                            <DataGridTextColumn Header="Success" Binding="{Binding TotalSuccess}" Width="85"/>
                            <DataGridTextColumn Header="Failure" Binding="{Binding TotalFailure}" Width="75"/>
                            <DataGridTextColumn Header="Result" Binding="{Binding ResultType}" Width="180"/>
                            <DataGridTextColumn Header="Failed" Binding="{Binding FailedSessionCount}" Width="80"/>
                            <DataGridTextColumn Header="Sending MTA" Binding="{Binding SendingMtaIP}" Width="130"/>
                            <DataGridTextColumn Header="Receiving MX" Binding="{Binding ReceivingMxHostname}" Width="170"/>
                            <DataGridTextColumn Header="Info" Binding="{Binding AdditionalInfo}" Width="200"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            <TabItem Header="  Senders  " Style="{StaticResource TabStyle}"><WebBrowser x:Name="wbSenders"/></TabItem>
            <TabItem Header="  Sources  " Style="{StaticResource TabStyle}">
                <Grid Background="#0D1117">
                    <Grid.RowDefinitions><RowDefinition Height="44"/><RowDefinition Height="32"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
                            <TextBlock Text="Status" Foreground="#6E7681" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <ComboBox x:Name="cmbSrcStatus" Width="160" Margin="0,0,12,0"><ComboBoxItem Content="All" IsSelected="True"/><ComboBoxItem Content="Unknown - Failing"/><ComboBoxItem Content="New Sender"/><ComboBoxItem Content="Unapproved"/></ComboBox>
                            <TextBlock Text="Service" Foreground="#6E7681" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <ComboBox x:Name="cmbSrcService" Width="200" Margin="0,0,12,0"><ComboBoxItem Content="All Services" IsSelected="True"/></ComboBox>
                            <Button x:Name="btnApprove" Content="Approve" Style="{StaticResource Btn2}" Padding="10,4" Margin="0,0,4,0"/>
                            <Button x:Name="btnUnapprove" Content="Unapprove" Style="{StaticResource Btn2}" Padding="10,4" Margin="0,0,4,0"/>
                            <Button x:Name="btnAuthorize" Content="Authorize..." Style="{StaticResource Btn2}" Padding="10,4" Margin="0,0,4,0"/>
                            <Button x:Name="btnRefreshSources" Content="Refresh" Style="{StaticResource Btn2}" Padding="10,4"/>
                            <TextBlock x:Name="txtSourceCount" Foreground="#484F58" FontSize="12" VerticalAlignment="Center" Margin="14,0,0,0"/>
                        </StackPanel>
                    </Border>
                    <Border Grid.Row="1" Background="#0D1117" BorderBrush="#21262D" BorderThickness="0,0,0,1">
                        <StackPanel x:Name="pnlSourceCrumb" Orientation="Horizontal" Margin="16,0" VerticalAlignment="Center">
                            <TextBlock Text="Drill:" Foreground="#6E7681" FontSize="11" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <TextBlock x:Name="txtSourceCrumb" Foreground="#79C0FF" FontSize="11" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Border>
                    <DataGrid Grid.Row="2" x:Name="dgSources" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserReorderColumns="True" CanUserResizeColumns="True" CanUserSortColumns="True" EnableRowVirtualization="True" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Auto">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Domain" Binding="{Binding domain}" Width="160"/>
                            <DataGridTextColumn Header="Source IP" Binding="{Binding sourceIP}" Width="125"/>
                            <DataGridTextColumn Header="Service" Binding="{Binding senderClass}" Width="155"/>
                            <DataGridTextColumn Header="Category" Binding="{Binding serviceCategory}" Width="90"/>
                            <DataGridTextColumn Header="Confidence" Binding="{Binding serviceConfidence}" Width="80"/>
                            <DataGridTextColumn Header="Org (rDNS)" Binding="{Binding orgName}" Width="160"/>
                            <DataGridTextColumn Header="Country" Binding="{Binding country}" Width="65"/>
                            <DataGridTextColumn Header="Pass" Binding="{Binding totalPass}" Width="60"/>
                            <DataGridTextColumn Header="Fail" Binding="{Binding totalFail}" Width="60"/>
                            <DataGridTextColumn Header="Total" Binding="{Binding totalMessages}" Width="65"/>
                            <DataGridTextColumn Header="First Seen" Binding="{Binding firstSeen}" Width="95"/>
                            <DataGridTextColumn Header="Last Seen" Binding="{Binding lastSeen}" Width="95"/>
                            <DataGridTextColumn Header="New?" Binding="{Binding isNew}" Width="55"/>
                            <DataGridTextColumn Header="Approved" Binding="{Binding isApproved}" Width="75"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            <TabItem Header="  DNS Drift  " Style="{StaticResource TabStyle}">
                <Grid Background="#0D1117">
                    <Grid.RowDefinitions><RowDefinition Height="44"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
                            <TextBlock Text="Record" Foreground="#6E7681" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <ComboBox x:Name="cmbDriftType" Width="150" Margin="0,0,12,0"><ComboBoxItem Content="All" IsSelected="True"/><ComboBoxItem Content="spf"/><ComboBoxItem Content="dmarc"/><ComboBoxItem Content="mta-sts"/><ComboBoxItem Content="bimi"/><ComboBoxItem Content="tls-rpt"/><ComboBoxItem Content="mx"/></ComboBox>
                            <Button x:Name="btnRefreshDrift" Content="Refresh" Style="{StaticResource Btn2}" Padding="10,4"/>
                            <TextBlock x:Name="txtDriftCount" Foreground="#484F58" FontSize="12" VerticalAlignment="Center" Margin="14,0,0,0"/>
                        </StackPanel>
                    </Border>
                    <DataGrid Grid.Row="1" x:Name="dgDrift" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserReorderColumns="True" CanUserResizeColumns="True" CanUserSortColumns="True" EnableRowVirtualization="True" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Auto">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Detected" Binding="{Binding detectedAt}" Width="140"/>
                            <DataGridTextColumn Header="Domain" Binding="{Binding domain}" Width="160"/>
                            <DataGridTextColumn Header="Record" Binding="{Binding recordType}" Width="80"/>
                            <DataGridTextColumn Header="Summary" Binding="{Binding summary}" Width="280"/>
                            <DataGridTextColumn Header="Old" Binding="{Binding oldValue}" Width="*"/>
                            <DataGridTextColumn Header="New" Binding="{Binding newValue}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            <TabItem Header="  DNS Health  " Style="{StaticResource TabStyle}">
                <Grid Background="#0D1117">
                    <Grid.RowDefinitions><RowDefinition Height="44"/><RowDefinition Height="240"/><RowDefinition Height="5"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
                            <Button x:Name="btnRefreshDNS" Content="Refresh" Style="{StaticResource Btn2}" Padding="10,4" Margin="0,0,8,0"/>
                            <Button x:Name="btnInspectSPF" Content="SPF + DKIM Inspector" Style="{StaticResource Btn2}" Padding="10,4" Margin="0,0,8,0"/>
                            <Button x:Name="btnSilentCheck" Content="Silent Failure Check" Style="{StaticResource Btn2}" Padding="10,4"/>
                            <TextBlock x:Name="txtDNSCount" Foreground="#484F58" FontSize="12" VerticalAlignment="Center" Margin="14,0,0,0"/>
                        </StackPanel>
                    </Border>
                    <DataGrid Grid.Row="1" x:Name="dgDNS" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserReorderColumns="True" CanUserResizeColumns="True" CanUserSortColumns="True" EnableRowVirtualization="True" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Auto">
                        <DataGrid.RowStyle><Style TargetType="DataGridRow" BasedOn="{StaticResource {x:Type DataGridRow}}">
                            <Style.Triggers><DataTrigger Binding="{Binding IssueCount}" Value="0"><Setter Property="Background" Value="#12261E"/></DataTrigger></Style.Triggers>
                        </Style></DataGrid.RowStyle>
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Domain" Binding="{Binding domain}" Width="175"/>
                            <DataGridTextColumn Header="DMARC" Binding="{Binding DMARCPolicy}" Width="100"/>
                            <DataGridTextColumn Header="pct" Binding="{Binding DMARCPct}" Width="55"/>
                            <DataGridTextColumn Header="SPF Status" Binding="{Binding SPFStatus}" Width="100"/>
                            <DataGridTextColumn Header="SPF Lookups" Binding="{Binding SPFLookups}" Width="95"/>
                            <DataGridTextColumn Header="Issues" Binding="{Binding IssueCount}" Width="60"/>
                            <DataGridTextColumn Header="Details" Binding="{Binding Issues}" Width="*"/>
                            <DataGridTextColumn Header="Checked" Binding="{Binding LastChecked}" Width="100"/>
                        </DataGrid.Columns>
                    </DataGrid>
                    <GridSplitter Grid.Row="2" Height="5" HorizontalAlignment="Stretch" Background="#21262D" Cursor="SizeNS"/>
                    <WebBrowser Grid.Row="3" x:Name="wbSPF"/>
                </Grid>
            </TabItem>
            <TabItem Header="  Forensic  " Style="{StaticResource TabStyle}">
                <Grid Background="#0D1117">
                    <Grid.RowDefinitions><RowDefinition Height="44"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
                            <Button x:Name="btnRefreshRUF" Content="Refresh" Style="{StaticResource Btn2}" Padding="10,4"/>
                            <TextBlock x:Name="txtRUFCount" Foreground="#484F58" FontSize="12" VerticalAlignment="Center" Margin="14,0,0,0"/>
                        </StackPanel>
                    </Border>
                    <DataGrid Grid.Row="1" x:Name="dgRUF" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserReorderColumns="True" CanUserResizeColumns="True" CanUserSortColumns="True" EnableRowVirtualization="True" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Auto">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Arrival" Binding="{Binding ArrivalDate}" Width="145"/>
                            <DataGridTextColumn Header="Domain" Binding="{Binding Domain}" Width="150"/>
                            <DataGridTextColumn Header="Source IP" Binding="{Binding SourceIP}" Width="125"/>
                            <DataGridTextColumn Header="DKIM" Binding="{Binding DKIMResult}" Width="55"/>
                            <DataGridTextColumn Header="SPF" Binding="{Binding SPFResult}" Width="55"/>
                            <DataGridTextColumn Header="Header From" Binding="{Binding HeaderFrom}" Width="180"/>
                            <DataGridTextColumn Header="Return Path" Binding="{Binding ReturnPath}" Width="180"/>
                            <DataGridTextColumn Header="Subject" Binding="{Binding Subject}" Width="220"/>
                            <DataGridTextColumn Header="Parsed" Binding="{Binding ParsedAt}" Width="135"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            <TabItem Header="  Trends  " Style="{StaticResource TabStyle}">
                <Grid Background="#0D1117">
                    <Grid.RowDefinitions><RowDefinition Height="44"/><RowDefinition Height="*"/><RowDefinition Height="5"/><RowDefinition Height="280"/></Grid.RowDefinitions>
                    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
                            <TextBlock Text="Period" Foreground="#6E7681" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
                            <ComboBox x:Name="cmbTrendPeriod" Width="110" Margin="0,0,12,0"><ComboBoxItem Content="7 days" IsSelected="True"/><ComboBoxItem Content="14 days"/><ComboBoxItem Content="30 days"/></ComboBox>
                            <Button x:Name="btnRefreshTrend" Content="Refresh" Style="{StaticResource Btn2}" Padding="10,4"/>
                        </StackPanel>
                    </Border>
                    <WebBrowser Grid.Row="1" x:Name="wbTrend"/>
                    <GridSplitter Grid.Row="2" Height="5" HorizontalAlignment="Stretch" Background="#21262D" Cursor="SizeNS"/>
                    <Border Grid.Row="3" Background="#0A0D13" BorderBrush="#21262D" BorderThickness="0,1,0,0">
                        <Grid>
                            <Grid.RowDefinitions><RowDefinition Height="26"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                            <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                                <TextBlock Text="GEOGRAPHIC SENDER MAP" Foreground="#6E7681" FontSize="10" FontWeight="SemiBold" VerticalAlignment="Center" Margin="14,0"/>
                            </Border>
                            <WebBrowser Grid.Row="1" x:Name="wbGeoMap"/>
                        </Grid>
                    </Border>
                </Grid>
            </TabItem>
            <TabItem Header="  Protocol  " Style="{StaticResource TabStyle}">
                <Grid Background="#0D1117">
                    <Grid.RowDefinitions><RowDefinition Height="44"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0">
                            <Button x:Name="btnRefreshProtocol" Content="Refresh" Style="{StaticResource Btn2}" Padding="10,4"/>
                            <TextBlock x:Name="txtProtocolCount" Foreground="#484F58" FontSize="12" VerticalAlignment="Center" Margin="14,0,0,0"/>
                        </StackPanel>
                    </Border>
                    <DataGrid Grid.Row="1" x:Name="dgProtocol" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserReorderColumns="True" CanUserResizeColumns="True" CanUserSortColumns="True" EnableRowVirtualization="True" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Auto">
                        <DataGrid.RowStyle><Style TargetType="DataGridRow" BasedOn="{StaticResource {x:Type DataGridRow}}">
                            <Style.Triggers>
                                <DataTrigger Binding="{Binding MTASTSMode}" Value="enforce"><Setter Property="Background" Value="#12261E"/></DataTrigger>
                                <DataTrigger Binding="{Binding MTASTSMode}" Value="not-deployed"><Setter Property="Background" Value="#2D1A1A"/></DataTrigger>
                            </Style.Triggers>
                        </Style></DataGrid.RowStyle>
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Domain" Binding="{Binding Domain}" Width="175"/>
                            <DataGridTextColumn Header="DMARC" Binding="{Binding DMARCPolicy}" Width="110"/>
                            <DataGridTextColumn Header="MTA-STS" Binding="{Binding MTASTSMode}" Width="110"/>
                            <DataGridTextColumn Header="STS Status" Binding="{Binding MTASTSStatus}" Width="140"/>
                            <DataGridTextColumn Header="BIMI" Binding="{Binding BIMIStatus}" Width="150"/>
                            <DataGridTextColumn Header="VMC" Binding="{Binding BIMIHasVMC}" Width="60"/>
                            <DataGridTextColumn Header="DKIM Domains" Binding="{Binding DKIMDomains}" Width="200"/>
                            <DataGridTextColumn Header="Changes" Binding="{Binding DKIMChangeCount}" Width="85"/>
                            <DataGridTextColumn Header="Checked" Binding="{Binding LastChecked}" Width="105"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
        </TabControl>
    </Grid>
    <GridSplitter Grid.Row="3" Height="5" HorizontalAlignment="Stretch" Background="#21262D" Cursor="SizeNS"/>
    <Grid Grid.Row="4" Background="#0A0D13">
        <Grid.RowDefinitions><RowDefinition Height="26"/><RowDefinition Height="*"/></Grid.RowDefinitions>
        <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,1,0,1">
            <DockPanel Margin="14,0"><TextBlock Text="RUN LOG" Foreground="#6E7681" FontSize="11" FontWeight="SemiBold" VerticalAlignment="Center" DockPanel.Dock="Left"/>
            <Button x:Name="btnClearLog" Content="Clear" DockPanel.Dock="Right" Style="{StaticResource Btn2}" Padding="8,2" FontSize="11" VerticalAlignment="Center"/>
            <TextBlock x:Name="txtRunStatus" Foreground="#6E7681" FontSize="11" VerticalAlignment="Center" DockPanel.Dock="Right" Margin="0,0,10,0"/></DockPanel>
        </Border>
        <TextBox Grid.Row="1" x:Name="txtLog" IsReadOnly="True" TextWrapping="NoWrap" ScrollViewer.HorizontalScrollBarVisibility="Auto" ScrollViewer.VerticalScrollBarVisibility="Auto" Background="#0A0D13" Foreground="#7EE787" FontFamily="Cascadia Code, Consolas, Courier New" FontSize="11" BorderThickness="0" Padding="14,6"/>
    </Grid>
    <Border Grid.Row="5" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,1,0,0">
        <DockPanel Margin="14,0">
            <TextBlock x:Name="txtStatus" Text="Ready" Foreground="#6E7681" FontSize="11" VerticalAlignment="Center"/>
            <TextBlock x:Name="txtLastRun" Foreground="#484F58" FontSize="11" VerticalAlignment="Center" HorizontalAlignment="Right" DockPanel.Dock="Right"/>
        </DockPanel>
    </Border>
</Grid></Window>
'@
#endregion

#region Load window + bind controls
$reader = New-Object System.Xml.XmlNodeReader $mainXaml
$window = [Windows.Markup.XamlReader]::Load($reader)

foreach ($n in @('bannerModule','bannerCert','txtCertBanner','btnInstallModule','btnRun','btnRefresh','btnSettings','btnSchedule','btnExport','btnGenReport','btnClearLog','txtLog','txtStatus','txtLastRun','txtRunStatus','txtMailboxLabel','txtPSBadge','lbDomains','txtDomainSearch','tabMain','wbOverview','wbSenders','wbTrend','wbGeoMap','wbSPF','dgDMARC','cmbDMARCResult','cmbFailReason','txtDMARCIP','btnDMARCFilter','btnDMARCReset','txtDMARCCount','dgTLS','cmbTLSResult','btnTLSFilter','btnTLSReset','txtTLSCount','dgSources','cmbSrcStatus','cmbSrcService','btnApprove','btnUnapprove','btnAuthorize','btnRefreshSources','txtSourceCount','txtSourceCrumb','dgDNS','btnRefreshDNS','btnInspectSPF','btnSilentCheck','txtDNSCount','dgRUF','btnRefreshRUF','txtRUFCount','cmbTrendPeriod','btnRefreshTrend','dgProtocol','btnRefreshProtocol','txtProtocolCount','dgDrift','cmbDriftType','btnRefreshDrift','txtDriftCount')) {
    Set-Variable -Name $n -Value $window.FindName($n) -Scope Script
}
$txtPSBadge.Text = "PS$($script:PSVer)"

# Suppress IE WebBrowser script-error dialogs (popups from any failed JS / mixed-content notice)
function Set-WBSilent {
    param($wb)
    if ($null -eq $wb) { return }
    $wb.Add_Navigated({
        try {
            $bf  = [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
            $fld = $this.GetType().GetField("_axIWebBrowser2", $bf)
            if ($fld) {
                $ax = $fld.GetValue($this)
                if ($ax) { $ax.GetType().InvokeMember("Silent", [Reflection.BindingFlags]::SetProperty, $null, $ax, @($true)) | Out-Null }
            }
        } catch {}
    })
}
Set-WBSilent $wbOverview
Set-WBSilent $wbSenders
Set-WBSilent $wbTrend
Set-WBSilent $wbGeoMap
Set-WBSilent $wbSPF
#endregion

#region Sidebar
function Update-Sidebar {
    param([string]$Filter="")
    $domains = Get-AllKnownDomains
    $items = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]
    $cfg = Get-AllSettings
    foreach ($domain in $domains) {
        if ($Filter -and $domain -ne "All Domains" -and $domain -notmatch [regex]::Escape($Filter)) { continue }
        $score = if ($domain -eq "All Domains") { 0 } else { Get-DomainScore -Domain $domain }
        $sColor = if ($score -ge 80) { "#3FB950" } elseif ($score -ge 60) { "#D29922" } else { "#F85149" }
        $sBg = if ($score -ge 80) { "#12261E" } elseif ($score -ge 60) { "#2D2000" } else { "#2D1010" }
        $policy = 'unknown'
        if (-not [string]::IsNullOrWhiteSpace($cfg.WorkingDir)) {
            $pFile = Join-Path $cfg.WorkingDir "State\progression.json"
            if (Test-Path $pFile) { try { $p = (Get-Content $pFile -Raw | ConvertFrom-Json).domains.($domain -replace '[^a-zA-Z0-9_]','_'); if ($p) { $policy = $p.currentPolicy } } catch {} }
        }
        $pBadge = if ($domain -eq "All Domains") { "Portfolio view" } else { switch ($policy) { 'reject' { "p=reject" } 'quarantine' { "p=quarantine" } 'none' { "p=none" } default { "monitoring" } } }
        $pColor = switch ($policy) { 'reject' { "#3FB950" } 'quarantine' { "#D29922" } 'none' { "#F85149" } default { "#6E7681" } }
        if ($domain -eq "All Domains") { $pColor = "#6E7681" }
        $items.Add([PSCustomObject]@{ DomainName=$domain; Score=(if ($domain -eq "All Domains") { "" } else { $score }); ScoreColor=$sColor; ScoreBg=$sBg; PolicyBadge=$pBadge; PolicyColor=$pColor })
    }
    $lbDomains.ItemsSource = $items
}
#endregion

#region Refresh
function Refresh-Overview {
    try { $html = New-OverviewHTML -Domain $script:SelectedDomain
        $tmp = [System.IO.Path]::GetTempPath() + "dmarcmonitor_overview.html"
        $html | Set-Content $tmp -Encoding UTF8
        $wbOverview.Navigate("file:///$($tmp.Replace('\','/'))") } catch { $txtLog.AppendText("[WARN] Overview: $_`n") }
}
function Refresh-DMARCData {
    $result = if ($cmbDMARCResult.SelectedItem) { $v = ($cmbDMARCResult.SelectedItem).Content; if ($v -eq "All") { "All" } else { $v } } else { "All" }
    $table = Load-CSVData -Pattern "dmarc_aggregate_*.csv" -DomainFilter $script:SelectedDomain -ResultFilter $result -IPFilter $txtDMARCIP.Text.Trim()
    $failReason = if ($cmbFailReason.SelectedItem) { ($cmbFailReason.SelectedItem).Content } else { "All" }
    if ($failReason -ne "All" -and $table.Rows.Count -gt 0) {
        $filt = $table.Clone()
        $table.AsEnumerable() | Where-Object { $_["FailReason"] -eq $failReason } | ForEach-Object { $filt.ImportRow($_) }
        $dgDMARC.ItemsSource = $filt.DefaultView; $txtDMARCCount.Text = "$($filt.Rows.Count) records"
    } else { $dgDMARC.ItemsSource = $table.DefaultView; $txtDMARCCount.Text = "$($table.Rows.Count) records" }
}
function Refresh-TLSData {
    $result = if ($cmbTLSResult.SelectedItem) { $v = ($cmbTLSResult.SelectedItem).Content; if ($v -eq "All") { "All" } else { $v } } else { "All" }
    $table = Load-CSVData -Pattern "tlsrpt_aggregate_*.csv" -DomainFilter $script:SelectedDomain -ResultFilter $result
    $dgTLS.ItemsSource = $table.DefaultView; $txtTLSCount.Text = "$($table.Rows.Count) records"
}
# Drill-through state shared between the Senders tab and the Sources tab.
# Clicking a service card on Senders sets $script:DrillService; the Sources
# tab honors it and shows the breadcrumb at the top.
$script:DrillService = $null

function Refresh-Sources {
    $cfg = Get-AllSettings; if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return }
    $invFile = Join-Path $cfg.WorkingDir "State\source-inventory.json"
    $table = New-Object System.Data.DataTable
    @('domain','sourceIP','senderClass','serviceCategory','serviceConfidence','orgName','country','totalPass','totalFail','totalMessages','firstSeen','lastSeen','isNew','isApproved') | ForEach-Object { $table.Columns.Add($_) | Out-Null }
    $allServices = New-Object System.Collections.Generic.HashSet[string]
    if (Test-Path $invFile) {
        try {
            $inv = Get-Content $invFile -Raw | ConvertFrom-Json
            $sf = if ($cmbSrcStatus.SelectedItem) { ($cmbSrcStatus.SelectedItem).Content } else { "All" }
            $svcFilter = if ($cmbSrcService.SelectedItem) { ($cmbSrcService.SelectedItem).Content } else { "All Services" }
            $sources = @($inv.sources.PSObject.Properties | ForEach-Object { $_.Value })
            foreach ($s in $sources) {
                $cls = if ($s.senderClass) { [string]$s.senderClass } else { 'Unknown' }
                if ($cls) { [void]$allServices.Add($cls) }
            }
            if ($script:SelectedDomain -ne "All Domains") { $sources = $sources | Where-Object { $_.domain -eq $script:SelectedDomain } }
            if ($sf -eq "Unknown - Failing") { $sources = $sources | Where-Object { $_.senderClass -eq 'Unknown' -and [int]$_.totalFail -gt 0 } }
            if ($sf -eq "New Sender")        { $sources = $sources | Where-Object { $_.isNew -eq $true } }
            if ($sf -eq "Unapproved")        { $sources = $sources | Where-Object { $_.isApproved -ne $true } }
            # Drill-through filter from Senders tab takes precedence over the dropdown
            $effectiveSvc = if ($script:DrillService) { $script:DrillService } elseif ($svcFilter -and $svcFilter -ne 'All Services') { $svcFilter } else { $null }
            if ($effectiveSvc) { $sources = $sources | Where-Object { ([string]$_.senderClass) -eq $effectiveSvc } }
            foreach ($s in $sources) {
                $dr = $table.NewRow()
                foreach ($col in $table.Columns) { try { $dr[$col.ColumnName] = $s.($col.ColumnName) } catch {} }
                $table.Rows.Add($dr)
            }
        } catch {}
    }
    $dgSources.ItemsSource = $table.DefaultView
    $txtSourceCount.Text = "$($table.Rows.Count) sources"

    # Repopulate the Service filter dropdown to match observed services
    $current = if ($cmbSrcService.SelectedItem) { ($cmbSrcService.SelectedItem).Content } else { "All Services" }
    $cmbSrcService.Items.Clear()
    $allItem = New-Object System.Windows.Controls.ComboBoxItem; $allItem.Content = "All Services"; $cmbSrcService.Items.Add($allItem) | Out-Null
    foreach ($svc in ($allServices | Sort-Object)) {
        $i = New-Object System.Windows.Controls.ComboBoxItem; $i.Content = $svc
        $cmbSrcService.Items.Add($i) | Out-Null
        if ($svc -eq $current) { $cmbSrcService.SelectedItem = $i }
    }
    if (-not $cmbSrcService.SelectedItem) { $cmbSrcService.SelectedItem = $allItem }

    # Breadcrumb
    $crumb = @()
    if ($script:SelectedDomain -and $script:SelectedDomain -ne 'All Domains') { $crumb += $script:SelectedDomain } else { $crumb += 'All Domains' }
    if ($script:DrillService) { $crumb += $script:DrillService }
    elseif ($cmbSrcService.SelectedItem -and ($cmbSrcService.SelectedItem).Content -ne 'All Services') { $crumb += ($cmbSrcService.SelectedItem).Content }
    $txtSourceCrumb.Text = ($crumb -join '  >  ')
}
# Sender catalog loader (read by Senders panel + Authorization Wizard)
$script:LoadedCatalog = $null
function Get-LoadedSenderCatalog {
    if ($script:LoadedCatalog) { return $script:LoadedCatalog }
    $catFile = Join-Path $PSScriptRoot 'sender-catalog.json'
    if (Test-Path $catFile) {
        try { $script:LoadedCatalog = Get-Content $catFile -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch { $script:LoadedCatalog = [PSCustomObject]@{ services=@() } }
    } else { $script:LoadedCatalog = [PSCustomObject]@{ services=@() } }
    return $script:LoadedCatalog
}

function Get-CatalogServiceById {
    param([string]$Id)
    if (-not $Id -or $Id -eq 'unknown') { return $null }
    $cat = Get-LoadedSenderCatalog
    return ($cat.services | Where-Object { $_.id -eq $Id } | Select-Object -First 1)
}

function New-SendersHTML {
    param([string]$Domain)
    $cfg = Get-AllSettings
    if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) {
        return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>Configure settings first.</body></html>"
    }
    $invFile = Join-Path $cfg.WorkingDir "State\source-inventory.json"
    if (-not (Test-Path $invFile)) {
        return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>No sender inventory yet - click Run Now to ingest reports.</body></html>"
    }
    $inv = $null; try { $inv = Get-Content $invFile -Raw | ConvertFrom-Json } catch { return "<html><body style='background:#0D1117;color:#F85149;font-family:Segoe UI;padding:20px'>source-inventory.json parse error.</body></html>" }
    $rows = @($inv.sources.PSObject.Properties | ForEach-Object { $_.Value })
    if ($Domain -and $Domain -ne 'All Domains') { $rows = $rows | Where-Object { $_.domain -eq $Domain } }

    # Group by service name (senderClass)
    $groups = $rows | Group-Object senderClass | Sort-Object { ($_.Group | Measure-Object totalMessages -Sum).Sum } -Descending
    if (-not $groups -or $groups.Count -eq 0) {
        return "<html><body style='background:#0D1117;color:#6E7681;font-family:Segoe UI;padding:20px'>No senders observed for $(HtmlEnc $Domain) yet.</body></html>"
    }

    $totalMsgs = ($rows | Measure-Object totalMessages -Sum).Sum
    $totalPass = ($rows | Measure-Object totalPass -Sum).Sum
    $portfolioRate = if ($totalMsgs -gt 0) { [math]::Round(($totalPass/$totalMsgs)*100,1) } else { 0 }
    $rateStr = (Inv $portfolioRate)

    $catColors = @{
        'transactional'='#79C0FF'; 'marketing'='#BC8CFF'; 'productivity'='#3FB950'
        'sales'='#FFA657'; 'support'='#56D364'; 'security'='#F85149'; 'alerts'='#D29922'
        'crm'='#58A6FF'; 'ecommerce'='#FF7B72'; 'consumer'='#6E7681'; 'relay'='#8B949E'
    }

    $cards = ''
    foreach ($g in $groups) {
        $svcName = $g.Name; if (-not $svcName) { $svcName = 'Unknown' }
        $msgs = ($g.Group | Measure-Object totalMessages -Sum).Sum
        $pass = ($g.Group | Measure-Object totalPass -Sum).Sum
        $fail = ($g.Group | Measure-Object totalFail -Sum).Sum
        $rate = if ($msgs -gt 0) { [math]::Round(($pass/$msgs)*100,1) } else { 0 }
        $ips  = ($g.Group | Select-Object -ExpandProperty sourceIP -Unique).Count
        $unappr = @($g.Group | Where-Object { -not $_.isApproved }).Count
        $first = ($g.Group[0])
        $cat   = if ($first.serviceCategory) { [string]$first.serviceCategory } else { '' }
        $vendor = if ($first.serviceVendor) { [string]$first.serviceVendor } else { '' }
        $conf  = if ($first.serviceConfidence) { [string]$first.serviceConfidence } else { 'none' }
        $rateColor = if ($rate -ge 95) { '#3FB950' } elseif ($rate -ge 80) { '#D29922' } else { '#F85149' }
        $catColor  = if ($cat -and $catColors.ContainsKey($cat)) { $catColors[$cat] } else { '#6E7681' }
        $confBadge = switch ($conf) { 'high' { "<span style='background:#0E2F1A;color:#3FB950;padding:1px 6px;border-radius:3px;font-size:9px;margin-left:6px'>HIGH</span>" } 'medium' { "<span style='background:#2F2210;color:#D29922;padding:1px 6px;border-radius:3px;font-size:9px;margin-left:6px'>MED</span>" } default { "<span style='background:#2F1010;color:#F85149;padding:1px 6px;border-radius:3px;font-size:9px;margin-left:6px'>UNCLASSIFIED</span>" } }
        $vendorLine = if ($vendor -and $vendor -ne $svcName) { "<div style='font-size:11px;color:#6E7681;margin-bottom:6px'>by $(HtmlEnc $vendor)</div>" } else { '' }
        $unapprBadge = if ($unappr -gt 0 -and $svcName -ne 'Unknown') { "<span style='background:#2F2210;color:#D29922;padding:1px 6px;border-radius:3px;font-size:10px;margin-left:6px'>$unappr unapproved</span>" } elseif ($svcName -eq 'Unknown') { "<span style='background:#2F1010;color:#F85149;padding:1px 6px;border-radius:3px;font-size:10px;margin-left:6px'>review</span>" } else { '' }
        $drillUrl = "dmarc:drill?service=$([uri]::EscapeDataString($svcName))"
        $cards += @"
<div style='background:#161B22;border:1px solid #30363D;border-radius:8px;padding:16px;margin:8px;width:300px;display:inline-block;vertical-align:top'>
  <div style='display:flex;align-items:center;margin-bottom:4px'>
    <span style='display:inline-block;width:8px;height:8px;background:$catColor;border-radius:50%;margin-right:8px'></span>
    <a href='$drillUrl' style='color:#E6EDF3;text-decoration:none;font-weight:600;font-size:14px'>$(HtmlEnc $svcName)</a>
    $confBadge
  </div>
  $vendorLine
  <div style='display:flex;justify-content:space-between;align-items:baseline;margin-top:10px'>
    <span style='color:$rateColor;font-size:24px;font-weight:600'>$(Inv $rate)%</span>
    <span style='color:#6E7681;font-size:11px'>$msgs msgs / $ips IPs</span>
  </div>
  <div style='font-size:11px;color:#6E7681;margin-top:6px'>$(if ($cat) { "$(HtmlEnc $cat) &middot; " }) pass $pass &middot; fail $fail $unapprBadge</div>
</div>
"@
    }

    $head = "<div style='color:#6E7681;font-size:11px;margin-bottom:8px;font-weight:600'>SENDING SERVICES &mdash; $(HtmlEnc $Domain)</div><div style='color:#E6EDF3;font-size:14px;margin-bottom:14px'>$($groups.Count) service(s) sending mail. Portfolio pass rate: <span style='color:#3FB950;font-weight:600'>$rateStr%</span>. Click a card to drill into the Sources tab filtered to that service.</div>"

    return @"
<!DOCTYPE html><html><head><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta charset="UTF-8">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0D1117;color:#E6EDF3;font-family:'Segoe UI',Arial;padding:14px;overflow-y:auto}a{cursor:pointer}</style></head>
<body>
$head
<div>$cards</div>
</body></html>
"@
}

function Refresh-Senders {
    try {
        $html = New-SendersHTML -Domain $script:SelectedDomain
        $tmp = [System.IO.Path]::GetTempPath() + "dmarcmonitor_senders.html"
        $html | Set-Content $tmp -Encoding UTF8
        $wbSenders.Navigate("file:///$($tmp.Replace('\','/'))")
    } catch { $txtLog.AppendText("[WARN] Senders: $_`n") }
}

function Refresh-Drift {
    $cfg = Get-AllSettings; if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return }
    $driftFile = Join-Path $cfg.WorkingDir "State\dns-drift.json"
    $table = New-Object System.Data.DataTable
    @('detectedAt','domain','recordType','summary','oldValue','newValue') | ForEach-Object { $table.Columns.Add($_) | Out-Null }
    if (Test-Path $driftFile) {
        try {
            $state = Get-Content $driftFile -Raw | ConvertFrom-Json
            $events = @($state.events)
            if ($script:SelectedDomain -ne "All Domains") { $events = $events | Where-Object { $_.domain -eq $script:SelectedDomain } }
            $rt = if ($cmbDriftType.SelectedItem) { ($cmbDriftType.SelectedItem).Content } else { "All" }
            if ($rt -and $rt -ne 'All') { $events = $events | Where-Object { $_.recordType -eq $rt } }
            # Newest first
            $events = $events | Sort-Object { [datetime]$_.detectedAt } -Descending
            foreach ($e in $events) {
                $dr = $table.NewRow()
                foreach ($col in $table.Columns) { try { $dr[$col.ColumnName] = $e.($col.ColumnName) } catch {} }
                $table.Rows.Add($dr)
            }
        } catch {}
    }
    $dgDrift.ItemsSource = $table.DefaultView
    $txtDriftCount.Text = if ($table.Rows.Count -gt 0) { "$($table.Rows.Count) drift events" } else { "No drift events yet - history builds over successive runs" }
}

function Show-AuthorizationWizard {
    $sel = $dgSources.SelectedItem
    if (-not $sel) { [System.Windows.MessageBox]::Show("Select a sender row first.", "No Selection", "OK", "Information") | Out-Null; return }
    $domain   = [string]$sel.Row["domain"]
    $ip       = [string]$sel.Row["sourceIP"]
    $service  = [string]$sel.Row["senderClass"]
    $category = [string]$sel.Row["serviceCategory"]
    $confidence = [string]$sel.Row["serviceConfidence"]

    # Look up by service name (catalog uses name; sourceInventory stores it)
    $cat = Get-LoadedSenderCatalog
    $svc = $cat.services | Where-Object { $_.name -eq $service } | Select-Object -First 1

    $headerColor = if ($svc) { '#3FB950' } else { '#D29922' }
    $headerText  = if ($svc) { "Authorize $($svc.name) for $domain" } else { "Unknown sender for $domain" }
    $body = ""
    if ($svc) {
        $spfBlock = if ($svc.spfInclude) {
            "<div style='font-family:Consolas,monospace;background:#0D1117;border:1px solid #30363D;border-radius:4px;padding:10px;color:#E6EDF3;font-size:12px'>v=spf1 include:$($svc.spfInclude) -all</div>" +
            "<div style='font-size:11px;color:#6E7681;margin-top:4px'>Append <code style='color:#79C0FF'>include:$($svc.spfInclude)</code> to your existing SPF TXT at the apex of <b>$domain</b>.</div>"
        } else {
            "<div style='font-size:12px;color:#D29922'>No SPF include published by this service. They likely send through your connected mailbox (Salesloft / Apollo / Mixmax pattern). Authentication uses your existing DKIM.</div>"
        }
        $dkimBlock = if ($svc.dkimCnameTemplate) {
            $tmpl = ($svc.dkimCnameTemplate -replace '\{your-domain\}', $domain) -replace '\{your-domain-hyphens\}', ($domain -replace '\.','-')
            # Preserve newlines for readability but escape the rest of the
            # template (catalog data could in theory be hostile).
            $tmplEnc = (HtmlEnc $tmpl) -replace "`r?`n", "<br/>"
            "<div style='font-family:Consolas,monospace;background:#0D1117;border:1px solid #30363D;border-radius:4px;padding:10px;color:#E6EDF3;font-size:12px;white-space:pre-wrap'>$tmplEnc</div>" +
            "<div style='font-size:11px;color:#6E7681;margin-top:4px'>Fill in placeholders (account-id, tenant, token) from your $(HtmlEnc $svc.name) admin console.</div>"
        } elseif ($svc.dkimSelectors -and $svc.dkimSelectors.Count -gt 0) {
            $sels = HtmlEnc ($svc.dkimSelectors -join ', ')
            "<div style='font-size:12px;color:#CDD9E5'>Known selectors: <code style='color:#79C0FF'>$sels</code>. Look for them in $(HtmlEnc $svc.name)'s admin console under DKIM / email authentication.</div>"
        } else { "<div style='font-size:12px;color:#6E7681'>This service does not publish a custom DKIM key.</div>" }
        $authBlock = if ($svc.authInstructions) { "<div style='color:#CDD9E5;font-size:12px;line-height:1.5'>$(HtmlEnc $svc.authInstructions)</div>" } else { '' }
        $catLine = "<span style='background:#21262D;color:#CDD9E5;padding:2px 8px;border-radius:10px;font-size:11px;margin-right:8px'>$(HtmlEnc $svc.category)</span><span style='background:#21262D;color:#CDD9E5;padding:2px 8px;border-radius:10px;font-size:11px'>$(HtmlEnc $svc.vendor)</span>"
        $linkLine = if ($svc.website) { $w = HtmlEnc $svc.website; "<a href='$w' style='color:#79C0FF;font-size:11px'>$w</a>" } else { '' }
        $body = @"
<div style='margin-bottom:14px'>$catLine</div>
<div style='margin-bottom:14px'>$linkLine</div>
<h3 style='color:#E6EDF3;font-size:13px;margin-bottom:6px'>1. SPF</h3>
$spfBlock
<h3 style='color:#E6EDF3;font-size:13px;margin:14px 0 6px'>2. DKIM</h3>
$dkimBlock
<h3 style='color:#E6EDF3;font-size:13px;margin:14px 0 6px'>3. Provider Setup</h3>
$authBlock
"@
    } else {
        $orgEnc = HtmlEnc $sel.Row['orgName']
        $ctEnc  = HtmlEnc $sel.Row['country']
        $ipEnc  = HtmlEnc $ip
        $body = @"
<div style='color:#D29922;font-size:13px;margin-bottom:14px'>This source IP did not match any catalog entry. Investigate before authorizing:</div>
<ul style='color:#CDD9E5;font-size:12px;line-height:1.8'>
  <li>Source IP: <code style='color:#79C0FF'>$ipEnc</code></li>
  <li>rDNS / Org: <code style='color:#79C0FF'>$orgEnc</code></li>
  <li>Country: <code style='color:#79C0FF'>$ctEnc</code></li>
  <li>Pass / fail: <span style='color:#3FB950'>$($sel.Row['totalPass'])</span> / <span style='color:#F85149'>$($sel.Row['totalFail'])</span></li>
</ul>
<div style='color:#6E7681;font-size:11px;margin-top:12px'>Steps: identify the sender (whois the IP, ask the org); if it's legitimate, add its SPF include or DKIM record per the vendor's docs; mark it Approved here. If it's not a legitimate sender, leave Unapproved and watch the failure rate.</div>
"@
    }

    # Build a minimal WPF dialog
    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Authorize Sender" Height="600" Width="720" Background="#0D1117" WindowStartupLocation="CenterOwner">
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="60"/><RowDefinition Height="*"/><RowDefinition Height="50"/></Grid.RowDefinitions>
    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
      <StackPanel Margin="20,10" Orientation="Vertical">
        <TextBlock Foreground="#$($headerColor.TrimStart('#'))" FontSize="15" FontWeight="SemiBold" Text="$([System.Net.WebUtility]::HtmlEncode($headerText))"/>
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,4,0,0" Text="Source IP $([System.Net.WebUtility]::HtmlEncode($ip))   ·   Detection: $([System.Net.WebUtility]::HtmlEncode($confidence)) confidence"/>
      </StackPanel>
    </Border>
    <WebBrowser Grid.Row="1" x:Name="wbAuth" Margin="0"/>
    <Border Grid.Row="2" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,1,0,0">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="20,8" VerticalAlignment="Center">
        <Button x:Name="btnPlanFix" Content="Plan DNS Fix..." Width="130" Height="28" Background="#1F6FEB" Foreground="White" BorderBrush="#1F6FEB" Margin="0,0,8,0"/>
        <Button x:Name="btnMarkApproved" Content="Mark Approved" Width="130" Height="28" Background="#3FB950" Foreground="White" BorderBrush="#3FB950" Margin="0,0,8,0"/>
        <Button x:Name="btnClose" Content="Close" Width="80" Height="28" Background="#21262D" Foreground="#CDD9E5" BorderBrush="#30363D"/>
      </StackPanel>
    </Border>
  </Grid>
</Window>
"@
    $win = [Windows.Markup.XamlReader]::Parse($xaml)
    $win.Owner = $window
    $wbAuth = $win.FindName('wbAuth')
    Set-WBSilent $wbAuth
    $tmp = [System.IO.Path]::GetTempPath() + "dmarcmonitor_auth.html"
    $page = "<!DOCTYPE html><html><head><meta http-equiv='X-UA-Compatible' content='IE=edge'><meta charset='UTF-8'><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0D1117;color:#E6EDF3;font-family:Segoe UI,Arial;padding:18px;overflow-y:auto;line-height:1.5}h3{margin-top:12px}code{background:#21262D;padding:1px 4px;border-radius:3px}</style></head><body>$body</body></html>"
    $page | Set-Content $tmp -Encoding UTF8
    # Intercept clicks on the vendor website link so they open in the system
    # default browser instead of clobbering the wizard's WebBrowser content.
    # Allow only file:/// (the wizard's own page) and about:blank through.
    $wbAuth.Add_Navigating({
        param($s, $e)
        $u = [string]$e.Uri
        if ($u -and -not ($u.StartsWith('file:') -or $u.StartsWith('about:'))) {
            $e.Cancel = $true
            try { Start-Process $u } catch {}
        }
    })
    $wbAuth.Navigate("file:///$($tmp.Replace('\','/'))")
    $win.FindName('btnMarkApproved').Add_Click({
        Set-SourceApproval -Approved $true
        $win.Close()
    })
    # Closes the loop competitors leave open: instead of only naming the record
    # the operator should publish, plan the exact change against the domain's
    # live SPF and show whether it is safe to apply.
    $win.FindName('btnPlanFix').Add_Click({
        $spfInclude = if ($svc -and $svc.PSObject.Properties.Name -contains 'spfInclude') { [string]$svc.spfInclude } else { '' }
        Show-DNSFixPlan -Domain $domain -IncludeDomain $spfInclude -ServiceName $service -Owner $win
    })
    $win.FindName('btnClose').Add_Click({ $win.Close() })
    $win.ShowDialog() | Out-Null
}

function Show-DNSProviderDialog {
    <#
        Captures where a domain's DNS lives and the credential to write it.

        The credential goes straight to the secret store; the dashboard keeps
        only an opaque ref. The field is a PasswordBox so the token is not
        shoulder-surfable and does not land in a screenshot of the settings
        screen.

        Returns $true when something was saved.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        $Owner
    )

    $cfg = Get-AllSettings
    if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) {
        [System.Windows.MessageBox]::Show("Set a working directory in Settings first.", "Not Configured", "OK", "Information") | Out-Null
        return $false
    }
    if (-not (Test-Path $script:RemediationScript)) {
        [System.Windows.MessageBox]::Show("Invoke-DNSRemediation.ps1 not found.", "Missing", "OK", "Warning") | Out-Null
        return $false
    }
    . $script:RemediationScript

    $existing = $null
    try { $existing = Get-DNSProviderConfig -WorkingDir $cfg.WorkingDir -Domain $Domain } catch {}
    $exProvider = if ($existing -and $existing.PSObject.Properties['provider']) { $existing.provider } else { 'manual' }
    $exCoords   = @{}
    if ($existing -and $existing.PSObject.Properties['config_json'] -and $existing.config_json) {
        try { (ConvertFrom-Json $existing.config_json).PSObject.Properties | ForEach-Object { $exCoords[$_.Name] = $_.Value } } catch {}
    }
    $hasSecret = $false
    if ($existing -and $existing.PSObject.Properties['credential_ref'] -and $existing.credential_ref) {
        $b = if ($existing.PSObject.Properties['secret_backend'] -and $existing.secret_backend) { $existing.secret_backend } else { 'dpapi' }
        try { $hasSecret = Test-StoredSecret -Ref $existing.credential_ref -Backend $b } catch {}
    }

    $dpapiOk = Test-SecretBackendAvailable -Name 'dpapi'
    $backendNote = if ($dpapiOk) {
        'The credential is encrypted with DPAPI to this Windows account on this machine. Another account cannot read it.'
    } else {
        'DPAPI is not available here, so no credential can be saved. Automatic publishing needs Windows PowerShell on the machine that runs the tool.'
    }
    $secretNote = if ($hasSecret) { 'A credential is already saved. Leave the box empty to keep it.' } else { 'No credential saved yet.' }

    $x = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DNS Provider" Height="470" Width="560" Background="#0D1117" WindowStartupLocation="CenterOwner" ResizeMode="NoResize">
  <Grid Margin="20">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="44"/>
    </Grid.RowDefinitions>
    <StackPanel Grid.Row="0" Margin="0,0,0,12">
      <TextBlock Foreground="#E6EDF3" FontSize="15" FontWeight="SemiBold" Text="Where does this domain's DNS live?"/>
      <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,4,0,0" TextWrapping="Wrap" Text="$([System.Net.WebUtility]::HtmlEncode($Domain))"/>
    </StackPanel>
    <StackPanel Grid.Row="1">
      <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4" Text="Provider"/>
      <ComboBox x:Name="cmbProv" Height="26" Margin="0,0,0,10">
        <ComboBoxItem Content="manual"/><ComboBoxItem Content="cloudflare"/><ComboBoxItem Content="azuredns"/>
      </ComboBox>

      <StackPanel x:Name="pnlCf">
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4" Text="Cloudflare Zone ID"/>
        <TextBox x:Name="txtZoneId" Height="26" Margin="0,0,0,10" Background="#0D1117" Foreground="#C9D1D9" BorderBrush="#30363D"/>
      </StackPanel>

      <StackPanel x:Name="pnlAz">
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4" Text="Subscription ID"/>
        <TextBox x:Name="txtSub" Height="26" Margin="0,0,0,8" Background="#0D1117" Foreground="#C9D1D9" BorderBrush="#30363D"/>
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4" Text="Resource Group"/>
        <TextBox x:Name="txtRg" Height="26" Margin="0,0,0,8" Background="#0D1117" Foreground="#C9D1D9" BorderBrush="#30363D"/>
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4" Text="Zone Name"/>
        <TextBox x:Name="txtZoneName" Height="26" Margin="0,0,0,10" Background="#0D1117" Foreground="#C9D1D9" BorderBrush="#30363D"/>
      </StackPanel>

      <StackPanel x:Name="pnlSecret">
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4" Text="API token"/>
        <PasswordBox x:Name="pwToken" Height="26" Margin="0,0,0,6" Background="#0D1117" Foreground="#C9D1D9" BorderBrush="#30363D"/>
        <TextBlock Foreground="#6E7681" FontSize="10" TextWrapping="Wrap" Margin="0,0,0,6" Text="$([System.Net.WebUtility]::HtmlEncode($secretNote))"/>
        <TextBlock Foreground="#6E7681" FontSize="10" TextWrapping="Wrap" Text="Use a scoped token limited to DNS edit on this zone, never a global API key."/>
      </StackPanel>

      <TextBlock Foreground="#484F58" FontSize="10" TextWrapping="Wrap" Margin="0,12,0,0" Text="$([System.Net.WebUtility]::HtmlEncode($backendNote))"/>
    </StackPanel>
    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="btnProvRemove" Content="Remove" Width="90" Height="28" Background="#21262D" Foreground="#CDD9E5" BorderBrush="#30363D" Margin="0,0,8,0"/>
      <Button x:Name="btnProvSave" Content="Save" Width="90" Height="28" Background="#238636" Foreground="#FFFFFF" BorderBrush="#2EA043" Margin="0,0,8,0"/>
      <Button x:Name="btnProvCancel" Content="Cancel" Width="80" Height="28" Background="#21262D" Foreground="#CDD9E5" BorderBrush="#30363D"/>
    </StackPanel>
  </Grid>
</Window>
"@

    $w = [Windows.Markup.XamlReader]::Parse($x)
    if ($Owner) { $w.Owner = $Owner }

    $cmbProv = $w.FindName('cmbProv'); $pnlCf = $w.FindName('pnlCf'); $pnlAz = $w.FindName('pnlAz'); $pnlSecret = $w.FindName('pnlSecret')
    $txtZoneId = $w.FindName('txtZoneId'); $txtSub = $w.FindName('txtSub'); $txtRg = $w.FindName('txtRg'); $txtZoneName = $w.FindName('txtZoneName')
    $pwToken = $w.FindName('pwToken')

    if ($exCoords.ContainsKey('zoneId'))         { $txtZoneId.Text   = [string]$exCoords['zoneId'] }
    if ($exCoords.ContainsKey('subscriptionId')) { $txtSub.Text      = [string]$exCoords['subscriptionId'] }
    if ($exCoords.ContainsKey('resourceGroup'))  { $txtRg.Text       = [string]$exCoords['resourceGroup'] }
    if ($exCoords.ContainsKey('zoneName'))       { $txtZoneName.Text = [string]$exCoords['zoneName'] }

    $syncPanels = {
        $sel = if ($cmbProv.SelectedItem) { [string]$cmbProv.SelectedItem.Content } else { 'manual' }
        $pnlCf.Visibility     = if ($sel -eq 'cloudflare') { 'Visible' } else { 'Collapsed' }
        $pnlAz.Visibility     = if ($sel -eq 'azuredns')   { 'Visible' } else { 'Collapsed' }
        $pnlSecret.Visibility = if ($sel -eq 'manual')     { 'Collapsed' } else { 'Visible' }
    }.GetNewClosure()

    foreach ($i in $cmbProv.Items) { if ([string]$i.Content -eq $exProvider) { $cmbProv.SelectedItem = $i } }
    if (-not $cmbProv.SelectedItem) { $cmbProv.SelectedIndex = 0 }
    & $syncPanels
    $cmbProv.Add_SelectionChanged($syncPanels)

    $script:ProvDialogSaved = $false

    $w.FindName('btnProvSave').Add_Click({
        $sel = if ($cmbProv.SelectedItem) { [string]$cmbProv.SelectedItem.Content } else { 'manual' }
        $coords = @{}
        if ($sel -eq 'cloudflare') {
            if ([string]::IsNullOrWhiteSpace($txtZoneId.Text)) {
                [System.Windows.MessageBox]::Show("Cloudflare needs a Zone ID.", "Missing", "OK", "Warning") | Out-Null; return
            }
            $coords['zoneId'] = $txtZoneId.Text.Trim()
        } elseif ($sel -eq 'azuredns') {
            foreach ($pair in @(@('subscriptionId',$txtSub), @('resourceGroup',$txtRg), @('zoneName',$txtZoneName))) {
                if ([string]::IsNullOrWhiteSpace($pair[1].Text)) {
                    [System.Windows.MessageBox]::Show("Azure DNS needs $($pair[0]).", "Missing", "OK", "Warning") | Out-Null; return
                }
                $coords[$pair[0]] = $pair[1].Text.Trim()
            }
        }

        $secret = $pwToken.Password
        if ($sel -ne 'manual' -and [string]::IsNullOrEmpty($secret) -and -not $hasSecret) {
            [System.Windows.MessageBox]::Show("Enter the API token for $sel.", "Missing", "OK", "Warning") | Out-Null; return
        }

        try {
            Set-DNSProviderConfig -WorkingDir $cfg.WorkingDir -Domain $Domain -Provider $sel `
                -Coordinates $coords -Secret $secret | Out-Null
            $script:ProvDialogSaved = $true
            $txtLog.AppendText("[SUCCESS] DNS provider for $Domain set to $sel.`n")
            $w.Close()
        } catch {
            # Most often: DPAPI unavailable. The store refuses rather than
            # writing plaintext, and the operator needs to be told that
            # nothing was saved.
            [System.Windows.MessageBox]::Show("Nothing was saved.`n`n$($_.Exception.Message)", "Could not save credential", "OK", "Error") | Out-Null
        }
    }.GetNewClosure())

    $w.FindName('btnProvRemove').Add_Click({
        $c = [System.Windows.MessageBox]::Show("Remove the DNS provider for $Domain and delete its stored credential?", "Confirm", "YesNo", "Warning")
        if ($c -ne 'Yes') { return }
        try {
            Remove-DNSProviderConfig -WorkingDir $cfg.WorkingDir -Domain $Domain
            $script:ProvDialogSaved = $true
            $txtLog.AppendText("[INFO] DNS provider for $Domain removed.`n")
            $w.Close()
        } catch { [System.Windows.MessageBox]::Show("$($_.Exception.Message)", "Remove failed", "OK", "Error") | Out-Null }
    }.GetNewClosure())

    $w.FindName('btnProvCancel').Add_Click({ $w.Close() }.GetNewClosure())

    $w.ShowDialog() | Out-Null
    return $script:ProvDialogSaved
}

function Invoke-DNSPlanApply {
    <#
        Publishes a plan, verifies it, and offers rollback if verification
        fails.

        Everything dangerous already lives in Invoke-DNSChangePlan: a plan
        that is not safe is refused with no override, the live value is
        snapshotted immediately before the write, and nothing is written
        without -Confirm. This is the UI around it.
    #>
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] $ProviderInfo,
        [Parameter(Mandatory)] [string]$Domain,
        $Window
    )

    $txtLog.AppendText("[INFO] Publishing DNS change for $Domain...`n"); $txtLog.ScrollToEnd()
    try {
        . $script:RemediationScript
        $res = Invoke-DNSChangePlan -Plan $Plan -Provider $ProviderInfo.Provider -Confirm -AppliedBy $env:USERNAME

        if (-not $res.Applied) {
            $why = if ($res.Error) { $res.Error } elseif (@($res.Blockers).Count -gt 0) { @($res.Blockers) -join '; ' } else { 'The plan was refused.' }
            $txtLog.AppendText("[ERROR] DNS change failed: $why`n")
            [System.Windows.MessageBox]::Show("The change was not published.`n`n$why", "Publish failed", "OK", "Error") | Out-Null
            return
        }

        $txtLog.AppendText("[SUCCESS] Published. Verifying propagation...`n")
        $verified = $false
        try {
            $prop = Test-DNSChangePropagation -Name $res.Name -ExpectedValue $res.NewValue -RecordType $res.RecordType
            $verified = [bool]$prop.IsPropagated
        } catch { $txtLog.AppendText("[WARN] Propagation check: $_`n") }

        if ($verified) {
            $txtLog.AppendText("[SUCCESS] Verified live in DNS.`n")
            $txtStatus.Text = "DNS updated: $Domain"
            $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
            [System.Windows.MessageBox]::Show("Published and verified.`n`n$Domain now serves the new record.", "Done", "OK", "Information") | Out-Null
            if ($Window) { $Window.Close() }
            return
        }

        # Written but not yet visible. Usually TTL, occasionally a real
        # failure, so the operator decides rather than the tool guessing.
        $txtLog.AppendText("[WARN] Published but not yet visible in DNS.`n")
        $undo = [System.Windows.MessageBox]::Show(
            "The record was written but is not visible in DNS yet.`n`nThis is usually propagation delay. Roll back to the previous value now?",
            "Not yet visible", "YesNo", "Warning")
        if ($undo -eq 'Yes') {
            try {
                # Takes the APPLIED RESULT, not the plan: the snapshot it
                # restores was taken from the live zone at write time, which
                # the plan does not carry.
                $u = Undo-DNSChangePlan -AppliedResult $res -Provider $ProviderInfo.Provider -Confirm
                if ($u.Restored) { $txtLog.AppendText("[INFO] Rolled back to: $($u.RestoredTo)`n") }
                else { $txtLog.AppendText("[ERROR] Rollback failed: $($u.Error)`n") }
            } catch { $txtLog.AppendText("[ERROR] Rollback failed: $_`n") }
        }
    } catch {
        $txtLog.AppendText("[ERROR] Publish: $_`n")
        [System.Windows.MessageBox]::Show("$($_.Exception.Message)", "Publish failed", "OK", "Error") | Out-Null
    }
    $txtLog.ScrollToEnd()
}

function Show-DNSFixPlan {
    <#
        Renders a plan produced by Invoke-DNSRemediation for human review.

        Deliberately stops at "here is exactly what would change and whether
        it is safe". Actually writing to a client's zone needs provider
        credentials the dashboard does not hold yet, and publishing DNS on a
        single click with no configured provider is how you break a customer's
        mail. The plan, the before/after and the refusal reasons are the part
        that has value today; Apply lights up once a provider is configured.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [AllowEmptyString()] [string]$IncludeDomain,
        [string]$ServiceName = '',
        $Owner
    )

    if (-not (Test-Path $script:RemediationScript)) {
        [System.Windows.MessageBox]::Show("Invoke-DNSRemediation.ps1 not found at $script:RemediationScript", "Missing", "OK", "Warning") | Out-Null
        return
    }

    if ([string]::IsNullOrWhiteSpace($IncludeDomain)) {
        [System.Windows.MessageBox]::Show(
            "$ServiceName does not publish an SPF include, so there is no SPF change to plan.`n`nIt most likely relays through your own mailbox and authenticates with your existing DKIM.",
            "Nothing to plan", "OK", "Information") | Out-Null
        return
    }

    # Read the domain's live SPF so the plan is costed against reality rather
    # than against whatever the last ingest happened to record.
    $currentSpf = ''
    try {
        $dns = Resolve-DnsName -Name $Domain -Type TXT -EA Stop
        $rec = $dns | Where-Object { $_.Strings -match 'v=spf1' } | Select-Object -First 1
        if ($rec) { $currentSpf = ($rec.Strings -join '') }
    } catch {
        $txtLog.AppendText("[WARN] Could not read live SPF for $Domain`: $_`n")
    }

    $plan = $null
    try {
        . $script:RemediationScript
        $plan = New-SPFIncludePlan -Domain $Domain -CurrentRecord $currentSpf -IncludeDomain $IncludeDomain
    } catch {
        [System.Windows.MessageBox]::Show("Could not build a plan: $_", "Plan failed", "OK", "Error") | Out-Null
        return
    }

    $statusColor = if ($plan.IsNoOp) { '#6E7681' } elseif ($plan.IsSafe) { '#3FB950' } else { '#F85149' }
    $statusText  = if ($plan.IsNoOp) { 'ALREADY IN PLACE' } elseif ($plan.IsSafe) { 'SAFE TO APPLY' } else { 'REFUSED' }

    # What can actually be published, and why. Resolved once here so the prose
    # and the button state cannot disagree.
    $cfg      = Get-AllSettings
    $provCfg  = $null
    $provInfo = $null
    try {
        if ($cfg.WorkingDir) { $provCfg = Get-DNSProviderConfig -WorkingDir $cfg.WorkingDir -Domain $Domain }
        $provInfo = New-DNSProviderFromConfig -ProviderConfig $provCfg
    } catch { $txtLog.AppendText("[WARN] Provider lookup: $_`n") }

    $canApply = ($null -ne $provInfo) -and $provInfo.IsAutomatic -and $plan.IsSafe -and (-not $plan.IsNoOp)

    $pubColor = '#8B949E'
    $pubText  = ''
    if ($plan.IsNoOp) {
        $pubText = 'This record already says what it needs to say. Nothing to publish.'
    } elseif (-not $plan.IsSafe) {
        $pubColor = '#FFA198'
        $pubText  = 'This plan is refused, so it cannot be published. Resolve the blockers above first.'
    } elseif ($canApply) {
        $pubColor = '#7EE787'
        $pubText  = "$($provInfo.Reason) The current value is snapshotted immediately before the write, so this change can be rolled back."
    } else {
        $reason = if ($provInfo) { $provInfo.Reason } else { 'No DNS provider is configured for this domain yet.' }
        $pubText = "$reason Copy the After value into the TXT record for $Domain, or configure a provider to publish, verify and roll back automatically."
    }

    $blockHtml = ''
    if ($plan.Blockers.Count -gt 0) {
        $items = ($plan.Blockers | ForEach-Object { "<li>$(HtmlEnc $_)</li>" }) -join ''
        $blockHtml = "<h3 style='color:#F85149;font-size:13px;margin:14px 0 6px'>Blockers</h3><ul style='color:#FFA198;font-size:12px;line-height:1.7;padding-left:18px'>$items</ul>"
    }
    $warnHtml = ''
    if ($plan.Warnings.Count -gt 0) {
        $items = ($plan.Warnings | ForEach-Object { "<li>$(HtmlEnc $_)</li>" }) -join ''
        $warnHtml = "<h3 style='color:#D29922;font-size:13px;margin:14px 0 6px'>Warnings</h3><ul style='color:#E3B341;font-size:12px;line-height:1.7;padding-left:18px'>$items</ul>"
    }

    $diffHtml = if ($plan.IsNoOp) { '' } else { @"
<h3 style='color:#E6EDF3;font-size:13px;margin:14px 0 6px'>Before</h3>
<div style='font-family:Consolas,monospace;background:#2D1A1A;border-left:3px solid #F85149;padding:10px;color:#FFA198;font-size:12px;word-break:break-all'>$(HtmlEnc $(if ($plan.CurrentValue) { $plan.CurrentValue } else { '(no SPF record published)' }))</div>
<h3 style='color:#E6EDF3;font-size:13px;margin:14px 0 6px'>After</h3>
<div style='font-family:Consolas,monospace;background:#12261E;border-left:3px solid #3FB950;padding:10px;color:#7EE787;font-size:12px;word-break:break-all'>$(HtmlEnc $plan.NewValue)</div>
"@ }

    $body = @"
<div style='display:inline-block;background:$statusColor;color:#fff;padding:3px 12px;border-radius:12px;font-size:11px;font-weight:bold;margin-bottom:12px'>$statusText</div>
<div style='color:#CDD9E5;font-size:13px;margin-bottom:12px'>$(HtmlEnc $plan.Summary)</div>
<div style='color:#6E7681;font-size:12px'>DNS lookups: <b style='color:#E6EDF3'>$($plan.LookupsBefore)</b> &rarr; <b style='color:#E6EDF3'>$($plan.LookupsAfter)</b> of 10 (RFC 7208)</div>
$diffHtml
$blockHtml
$warnHtml
<h3 style='color:#E6EDF3;font-size:13px;margin:16px 0 6px'>Publishing</h3>
<div style='color:$pubColor;font-size:12px;line-height:1.6'>$(HtmlEnc $pubText)</div>
"@

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DNS Fix Plan" Height="620" Width="760" Background="#0D1117" WindowStartupLocation="CenterOwner">
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="56"/><RowDefinition Height="*"/><RowDefinition Height="50"/></Grid.RowDefinitions>
    <Border Grid.Row="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1">
      <StackPanel Margin="20,9">
        <TextBlock Foreground="#E6EDF3" FontSize="15" FontWeight="SemiBold" Text="DNS fix plan"/>
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,3,0,0" Text="$([System.Net.WebUtility]::HtmlEncode("$Domain  -  authorize $ServiceName"))"/>
      </StackPanel>
    </Border>
    <WebBrowser Grid.Row="1" x:Name="wbPlan"/>
    <Border Grid.Row="2" Background="#161B22" BorderBrush="#30363D" BorderThickness="0,1,0,0">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="20,8">
        <Button x:Name="btnConfigProvider" Content="Configure Provider..." Width="150" Height="28" Background="#21262D" Foreground="#CDD9E5" BorderBrush="#30363D" Margin="0,0,8,0"/>
        <Button x:Name="btnCopy" Content="Copy New Record" Width="150" Height="28" Background="#21262D" Foreground="#CDD9E5" BorderBrush="#30363D" Margin="0,0,8,0"/>
        <Button x:Name="btnApply" Content="Apply to DNS" Width="120" Height="28" Background="#238636" Foreground="#FFFFFF" BorderBrush="#2EA043" Margin="0,0,8,0" IsEnabled="$(if ($canApply) { 'True' } else { 'False' })"/>
        <Button x:Name="btnPlanClose" Content="Close" Width="80" Height="28" Background="#21262D" Foreground="#CDD9E5" BorderBrush="#30363D"/>
      </StackPanel>
    </Border>
  </Grid>
</Window>
"@

    $pw = [Windows.Markup.XamlReader]::Parse($xaml)
    if ($Owner) { $pw.Owner = $Owner }
    $wbPlan = $pw.FindName('wbPlan')
    Set-WBSilent $wbPlan
    $tmp = [System.IO.Path]::GetTempPath() + "dmarcmonitor_plan.html"
    $page = "<!DOCTYPE html><html><head><meta http-equiv='X-UA-Compatible' content='IE=edge'><meta charset='UTF-8'><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0D1117;color:#E6EDF3;font-family:Segoe UI,Arial;padding:18px;overflow-y:auto;line-height:1.5}</style></head><body>$body</body></html>"
    $page | Set-Content $tmp -Encoding UTF8
    $wbPlan.Navigate("file:///$($tmp.Replace('\','/'))")

    $newValueForCopy = $plan.NewValue
    $pw.FindName('btnCopy').Add_Click({
        if ($newValueForCopy) {
            try { Set-Clipboard -Value $newValueForCopy; $txtStatus.Text = 'New SPF record copied to clipboard'; $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen } catch {}
        }
    }.GetNewClosure())
    $pw.FindName('btnConfigProvider').Add_Click({
        if (Show-DNSProviderDialog -Domain $Domain -Owner $pw) {
            # Re-plan so the publishing prose and the Apply button reflect the
            # provider that was just configured, rather than a stale read.
            $pw.Close()
            Show-DNSFixPlan -Domain $Domain -IncludeDomain $IncludeDomain -ServiceName $ServiceName -Owner $Owner
        }
    }.GetNewClosure())

    $pw.FindName('btnApply').Add_Click({
        $confirm = [System.Windows.MessageBox]::Show(
            "Publish this record to $Domain now?`n`nThis edits live DNS for a production mail domain. The current value is snapshotted first so the change can be rolled back.`n`nAfter:`n$($plan.NewValue)",
            "Confirm DNS change", "YesNo", "Warning")
        if ($confirm -ne 'Yes') { return }
        Invoke-DNSPlanApply -Plan $plan -ProviderInfo $provInfo -Domain $Domain -Window $pw
    }.GetNewClosure())

    $pw.FindName('btnPlanClose').Add_Click({ $pw.Close() })
    $pw.ShowDialog() | Out-Null
}
function Set-SourceApproval {
    param([bool]$Approved)
    $cfg = Get-AllSettings; if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return }
    $invFile = Join-Path $cfg.WorkingDir "State\source-inventory.json"
    if (-not (Test-Path $invFile)) { return }
    $sel = $dgSources.SelectedItem
    if (-not $sel) { [System.Windows.MessageBox]::Show("Select a row first.", "No Selection", "OK", "Information") | Out-Null; return }
    try {
        $inv = Get-Content $invFile -Raw | ConvertFrom-Json
        $domain = $sel.Row["domain"]; $ip = $sel.Row["sourceIP"]
        $key = "$($domain)__$($ip -replace '\.','_')"
        if ($inv.sources.$key) {
            $inv.sources.$key.isApproved = $Approved
            $inv | ConvertTo-Json -Depth 10 | Set-Content $invFile -Encoding UTF8
            $txtStatus.Text = if ($Approved) { "Approved: $ip" } else { "Unapproved: $ip" }
            $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
            Refresh-Sources
        }
    } catch { $txtLog.AppendText("[WARN] Approval: $_`n") }
}
function Refresh-DNSHealth {
    $cfg = Get-AllSettings; if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return }
    $dnsFile = Join-Path $cfg.WorkingDir "State\dns-health.json"
    $table = New-Object System.Data.DataTable
    @('domain','DMARCPolicy','DMARCPct','SPFStatus','SPFLookups','IssueCount','Issues','LastChecked') | ForEach-Object { $table.Columns.Add($_) | Out-Null }
    if (Test-Path $dnsFile) {
        try {
            $entries = (Get-Content $dnsFile -Raw | ConvertFrom-Json).domains.PSObject.Properties | ForEach-Object { $_.Value }
            if ($script:SelectedDomain -ne "All Domains") { $entries = $entries | Where-Object { $_.domain -eq $script:SelectedDomain } }
            foreach ($e in $entries) {
                $dr = $table.NewRow()
                foreach ($col in $table.Columns) { try { $dr[$col.ColumnName] = $e.($col.ColumnName) } catch {} }
                $table.Rows.Add($dr)
            }
        } catch {}
    }
    $dgDNS.ItemsSource = $table.DefaultView
    $txtDNSCount.Text = if ($table.Rows.Count -gt 0) { "$($table.Rows.Count) domains checked" } else { "No DNS data - enable check in Settings" }
}
function Invoke-SPFInspection {
    if ($script:SelectedDomain -eq "All Domains") { [System.Windows.MessageBox]::Show("Select a specific domain in the sidebar first.", "Domain Required", "OK", "Information") | Out-Null; return }
    if (-not (Test-Path $script:SPFScript)) { $txtLog.AppendText("[WARN] SPF inspector not found at $script:SPFScript`n"); return }
    $txtLog.AppendText("[INFO] Running SPF + DKIM inspection for $script:SelectedDomain...`n"); $txtLog.ScrollToEnd()
    try {
        $exe = if (Get-Command pwsh -EA SilentlyContinue) { "pwsh" } else { "powershell" }
        $tmp = [System.IO.Path]::GetTempPath() + "dmarcmonitor_spf_inspect.html"
        $proc = Start-Process -FilePath $exe -ArgumentList @("-ExecutionPolicy","Bypass","-NonInteractive","-File","`"$($script:SPFScript)`"","-Domain",$script:SelectedDomain,"-OutputPath","`"$tmp`"") -PassThru -WindowStyle Hidden
        $proc.WaitForExit(30000) | Out-Null
        if (Test-Path $tmp) { $wbSPF.Navigate("file:///$($tmp.Replace('\','/'))"); $txtLog.AppendText("[SUCCESS] SPF inspection complete.`n") }
        else { $txtLog.AppendText("[WARN] SPF inspection produced no output.`n") }
    } catch { $txtLog.AppendText("[WARN] SPF inspection: $_`n") }
}
function Test-ReportDestinationAuthorized {
    <#
        RFC 7489 s7.1: when a domain sends its DMARC reports to an address at a
        different organisational domain, that destination must publish
        <policy-domain>._report._dmarc.<destination> TXT "v=DMARC1"
        or conforming receivers will refuse to send the reports. The operator
        sees a working-looking record and no data, with nothing to explain why.
    #>
    param([string]$PolicyDomain, [string]$ExternalDomain)
    try {
        $probe = "$PolicyDomain._report._dmarc.$ExternalDomain"
        $ans = Resolve-DnsName -Name $probe -Type TXT -EA Stop
        return [bool](@($ans | Where-Object { $_.Strings -match 'v=DMARC1' }).Count -gt 0)
    } catch { return $false }
}

function Invoke-SilentFailureCheck {
    <#
        Runs the silent-failure analysis over whatever DNS the last health check
        recorded. Deliberately reads stored records rather than re-resolving:
        the point is to analyse exactly what was observed, and it stays usable
        when the dashboard has no outbound DNS.
    #>
    $cfg = Get-AllSettings
    if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) {
        [System.Windows.MessageBox]::Show("Set a working directory in Settings first.", "Not Configured", "OK", "Information") | Out-Null; return
    }
    if (-not (Test-Path $script:RemediationScript)) {
        [System.Windows.MessageBox]::Show("Invoke-DNSRemediation.ps1 not found at $script:RemediationScript", "Missing", "OK", "Warning") | Out-Null; return
    }
    $dnsFile = Join-Path $cfg.WorkingDir "State\dns-health.json"
    if (-not (Test-Path $dnsFile)) {
        [System.Windows.MessageBox]::Show("No DNS health data yet. Run a collection first.", "No Data", "OK", "Information") | Out-Null; return
    }

    $txtLog.AppendText("[INFO] Running silent-failure analysis...`n"); $txtLog.ScrollToEnd()
    try {
        . $script:RemediationScript

        $entries = @((Get-Content $dnsFile -Raw | ConvertFrom-Json).domains.PSObject.Properties | ForEach-Object { $_.Value })
        if ($script:SelectedDomain -ne "All Domains") { $entries = @($entries | Where-Object { $_.domain -eq $script:SelectedDomain }) }
        if ($entries.Count -eq 0) { $txtLog.AppendText("[WARN] No domains to analyse.`n"); return }

        $verifier = { param($pd, $ed) Test-ReportDestinationAuthorized -PolicyDomain $pd -ExternalDomain $ed }

        $results = foreach ($e in $entries) {
            # Records were only stored from this version onward. An older
            # dns-health.json has the analysis fields absent, which must not be
            # read as "the domain publishes nothing" - that would invent
            # critical findings for domains that are fine.
            $hasRecords = ($null -ne $e.PSObject.Properties['SPFRecords']) -or ($null -ne $e.PSObject.Properties['DMARCRecords'])
            if (-not $hasRecords) { continue }
            Test-AuthenticationSilentFailures -Domain $e.domain `
                -SpfRecords @($e.SPFRecords) -DmarcRecords @($e.DMARCRecords) `
                -ReportDomainVerifier $verifier
        }
        $results = @($results)

        if ($results.Count -eq 0) {
            $txtLog.AppendText("[WARN] Stored DNS data predates raw-record capture. Run a collection to refresh, then re-check.`n")
            [System.Windows.MessageBox]::Show("The stored DNS data was collected before raw records were captured.`n`nRun a collection to refresh it, then run this check again.", "Refresh Needed", "OK", "Information") | Out-Null
            return
        }

        $broken = @($results | Where-Object { $_.IsSilentlyBroken })
        $totalF = ($results | Measure-Object -Property TotalCount -Sum).Sum
        if ($null -eq $totalF) { $totalF = 0 }

        $sevColor = @{ critical='#F85149'; high='#DB6D28'; medium='#D29922'; low='#58A6FF'; info='#8B949E' }
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append(@"
<html><head><meta charset="utf-8"><style>
body{background:#0D1117;color:#C9D1D9;font-family:'Segoe UI',sans-serif;font-size:13px;margin:0;padding:16px}
h1{font-size:17px;margin:0 0 4px 0;color:#E6EDF3}
.sub{color:#8B949E;font-size:12px;margin-bottom:16px}
.dom{background:#161B22;border:1px solid #30363D;border-radius:6px;margin-bottom:12px}
.domh{padding:9px 13px;border-bottom:1px solid #30363D;font-weight:600;font-size:14px;display:flex;justify-content:space-between}
.ok{color:#3FB950}.bad{color:#F85149}
.f{padding:10px 13px;border-bottom:1px solid #21262D}
.f:last-child{border-bottom:none}
.badge{display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:700;letter-spacing:.5px;color:#0D1117;margin-right:8px}
.t{font-weight:600;color:#E6EDF3}
.d{color:#8B949E;margin-top:5px;line-height:1.55}
.ev{font-family:Consolas,monospace;font-size:11px;background:#0D1117;border:1px solid #30363D;border-radius:4px;padding:6px 8px;margin-top:6px;color:#79C0FF;word-break:break-all}
.rem{margin-top:6px;color:#3FB950}
.ref{color:#484F58;font-size:11px;margin-left:8px}
.clean{padding:11px 13px;color:#3FB950}
</style></head><body>
<h1>Silent Failure Analysis</h1>
<div class="sub">Records that are published, parse correctly, and do not take effect.
Analysed $($results.Count) domain(s) &mdash; $($broken.Count) silently broken, $totalF finding(s) total.</div>
"@)

        foreach ($r in ($results | Sort-Object -Property @{Expression={$_.CriticalCount};Descending=$true}, @{Expression={$_.TotalCount};Descending=$true}, Domain)) {
            $state = if ($r.IsSilentlyBroken) { "<span class='bad'>SILENTLY BROKEN</span>" }
                     elseif ($r.TotalCount -gt 0) { "<span style='color:#D29922'>$($r.TotalCount) finding(s)</span>" }
                     else { "<span class='ok'>clean</span>" }
            [void]$sb.Append("<div class='dom'><div class='domh'><span>$(HtmlEnc $r.Domain)</span>$state</div>")
            if ($r.TotalCount -eq 0) {
                [void]$sb.Append("<div class='clean'>No silent failures detected.</div>")
            } else {
                foreach ($f in $r.Findings) {
                    $c = $sevColor[$f.Severity]; if (-not $c) { $c = '#8B949E' }
                    [void]$sb.Append("<div class='f'><span class='badge' style='background:$c'>$(HtmlEnc $f.Severity.ToUpper())</span>")
                    [void]$sb.Append("<span class='t'>$(HtmlEnc $f.Title)</span><span class='ref'>$(HtmlEnc $f.Reference)</span>")
                    [void]$sb.Append("<div class='d'>$(HtmlEnc $f.Detail)</div>")
                    if ($f.Evidence)    { [void]$sb.Append("<div class='ev'>$(HtmlEnc $f.Evidence)</div>") }
                    if ($f.Remediation) { [void]$sb.Append("<div class='rem'>Fix: $(HtmlEnc $f.Remediation)</div>") }
                    [void]$sb.Append("</div>")
                }
            }
            [void]$sb.Append("</div>")
        }
        [void]$sb.Append("</body></html>")

        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "dmarcmonitor_silent_check.html"
        $sb.ToString() | Set-Content -Path $tmp -Encoding UTF8
        $wbSPF.Navigate("file:///$($tmp.Replace('\','/'))")

        if ($broken.Count -gt 0) {
            $txtStatus.Text = "$($broken.Count) domain(s) silently broken"
            $txtStatus.Foreground = [System.Windows.Media.Brushes]::Salmon
            $txtLog.AppendText("[WARN] Silent failures: $($broken.Count) domain(s) publish records that do not take effect.`n")
            foreach ($b in $broken) { $txtLog.AppendText("        $($b.Domain): $($b.Findings[0].Title)`n") }
        } else {
            $txtStatus.Text = "No silent failures"
            $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
            $txtLog.AppendText("[SUCCESS] No silently-broken domains. $totalF advisory finding(s).`n")
        }
        $txtLog.ScrollToEnd()
    } catch {
        $txtLog.AppendText("[WARN] Silent-failure analysis: $_`n"); $txtLog.ScrollToEnd()
    }
}

function Refresh-RUFData {
    $cfg = Get-AllSettings; if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return }
    $rptDir = Join-Path $cfg.WorkingDir "Reports"
    $table = New-Object System.Data.DataTable
    @('ArrivalDate','Domain','SourceIP','DKIMResult','SPFResult','HeaderFrom','ReturnPath','Subject','ParsedAt') | ForEach-Object { $table.Columns.Add($_) | Out-Null }
    $all = @()
    Get-ChildItem $rptDir -Filter "dmarc_forensic_*.csv" -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 7 |
        ForEach-Object { try { $all += Import-Csv $_.FullName } catch {} }
    if ($script:SelectedDomain -ne "All Domains") { $all = $all | Where-Object { $_.Domain -eq $script:SelectedDomain } }
    foreach ($r in $all) {
        $dr = $table.NewRow()
        foreach ($col in $table.Columns) { try { $dr[$col.ColumnName] = $r.($col.ColumnName) } catch {} }
        $table.Rows.Add($dr)
    }
    $dgRUF.ItemsSource = $table.DefaultView
    $txtRUFCount.Text = if ($table.Rows.Count -gt 0) { "$($table.Rows.Count) forensic records" } else { "No forensic reports - add ruf= to your DMARC record" }
}
function Refresh-TrendChart {
    $days = switch ($cmbTrendPeriod.SelectedIndex) { 0 { 7 } 1 { 14 } 2 { 30 } default { 7 } }
    try { $html = New-TrendChartHTML -DomainFilter $script:SelectedDomain -Days $days
        $tmp = [System.IO.Path]::GetTempPath() + "dmarcmonitor_trend.html"
        $html | Set-Content $tmp -Encoding UTF8
        $wbTrend.Navigate("file:///$($tmp.Replace('\','/'))") } catch { $txtLog.AppendText("[WARN] Trend: $_`n") }
}
function Refresh-GeoMap {
    try { $html = New-GeoMapHTML -DomainFilter $script:SelectedDomain
        $tmp = [System.IO.Path]::GetTempPath() + "dmarcmonitor_geomap.html"
        $html | Set-Content $tmp -Encoding UTF8
        $wbGeoMap.Navigate("file:///$($tmp.Replace('\','/'))") } catch { $txtLog.AppendText("[WARN] Geo map: $_`n") }
}
function Refresh-ProtocolStatus {
    $cfg = Get-AllSettings; if ([string]::IsNullOrWhiteSpace($cfg.WorkingDir)) { return }
    $stateDir = Join-Path $cfg.WorkingDir "State"
    $table = New-Object System.Data.DataTable
    @('Domain','DMARCPolicy','MTASTSMode','MTASTSStatus','BIMIStatus','BIMIHasVMC','DKIMDomains','DKIMChangeCount','LastChecked') | ForEach-Object { $table.Columns.Add($_) | Out-Null }
    $mtaState=$null; $bimiState=$null; $dkimState=$null; $progState=$null
    try { if (Test-Path (Join-Path $stateDir "mta-sts.json"))        { $mtaState  = Get-Content (Join-Path $stateDir "mta-sts.json") -Raw | ConvertFrom-Json } } catch {}
    try { if (Test-Path (Join-Path $stateDir "bimi.json"))           { $bimiState = Get-Content (Join-Path $stateDir "bimi.json") -Raw | ConvertFrom-Json } } catch {}
    try { if (Test-Path (Join-Path $stateDir "dkim-selectors.json")) { $dkimState = Get-Content (Join-Path $stateDir "dkim-selectors.json") -Raw | ConvertFrom-Json } } catch {}
    try { if (Test-Path (Join-Path $stateDir "progression.json"))    { $progState = Get-Content (Join-Path $stateDir "progression.json") -Raw | ConvertFrom-Json } } catch {}
    $allDomains = @()
    if ($mtaState  -and $mtaState.domains)  { $mtaState.domains.PSObject.Properties  | ForEach-Object { $allDomains += $_.Value.domain } }
    if ($bimiState -and $bimiState.domains) { $bimiState.domains.PSObject.Properties | ForEach-Object { $allDomains += $_.Value.domain } }
    if ($dkimState -and $dkimState.domains) { $dkimState.domains.PSObject.Properties | ForEach-Object { $allDomains += $_.Value.domain } }
    if ($progState -and $progState.domains) { $progState.domains.PSObject.Properties | ForEach-Object { $allDomains += $_.Value.domain } }
    $allDomains = $allDomains | Sort-Object -Unique
    if ($script:SelectedDomain -ne "All Domains") { $allDomains = $allDomains | Where-Object { $_ -eq $script:SelectedDomain } }
    foreach ($domain in $allDomains) {
        $sk = $domain -replace '[^a-zA-Z0-9_]','_'
        $dr = $table.NewRow()
        $dr['Domain'] = $domain
        $dr['DMARCPolicy']     = if ($progState -and $progState.domains.$sk) { $progState.domains.$sk.currentPolicy } else { 'unknown' }
        $dr['MTASTSMode']      = if ($mtaState  -and $mtaState.domains.$sk)  { $mtaState.domains.$sk.PolicyMode } else { 'not-checked' }
        $dr['MTASTSStatus']    = if ($mtaState  -and $mtaState.domains.$sk)  { $mtaState.domains.$sk.Status } else { 'not-checked' }
        $dr['BIMIStatus']      = if ($bimiState -and $bimiState.domains.$sk) { $bimiState.domains.$sk.Status } else { 'not-checked' }
        $dr['BIMIHasVMC']      = if ($bimiState -and $bimiState.domains.$sk) { if ($bimiState.domains.$sk.HasVMC) { "Yes" } else { "No" } } else { '' }
        $dr['DKIMDomains']     = if ($dkimState -and $dkimState.domains.$sk) { $dkimState.domains.$sk.dkimDomains } else { '' }
        $dr['DKIMChangeCount'] = if ($dkimState -and $dkimState.domains.$sk) { $dkimState.domains.$sk.changeCount } else { 0 }
        $dr['LastChecked']     = if ($mtaState  -and $mtaState.domains.$sk)  { $mtaState.domains.$sk.LastChecked } else { '' }
        $table.Rows.Add($dr)
    }
    $dgProtocol.ItemsSource = $table.DefaultView; $txtProtocolCount.Text = "$($table.Rows.Count) domains"
}
function Refresh-AllData {
    Update-Sidebar -Filter $txtDomainSearch.Text.Trim()
    $cfg = Get-AllSettings
    if ($cfg.MailboxAddress) { $txtMailboxLabel.Text = $cfg.MailboxAddress }
    # Index map after adding Senders (3) + DNS Drift (5):
    #   0 Overview  1 DMARC  2 TLS  3 Senders  4 Sources  5 DNS Drift
    #   6 DNS Health  7 Forensic  8 Trends  9 Protocol
    switch ($tabMain.SelectedIndex) {
        0 { Refresh-Overview }
        1 { Refresh-DMARCData }
        2 { Refresh-TLSData }
        3 { Refresh-Senders }
        4 { Refresh-Sources }
        5 { Refresh-Drift }
        6 { Refresh-DNSHealth }
        7 { Refresh-RUFData }
        8 { Refresh-TrendChart; Refresh-GeoMap }
        9 { Refresh-ProtocolStatus }
    }
}

# Called after a Run Now completes: refresh every tab so charts/data are ready
# the moment the user clicks any tab, not only the one currently in front.
function Refresh-AllTabs {
    Update-Sidebar -Filter $txtDomainSearch.Text.Trim()
    $cfg = Get-AllSettings
    if ($cfg.MailboxAddress) { $txtMailboxLabel.Text = $cfg.MailboxAddress }
    try { Refresh-Overview }       catch { $txtLog.AppendText("[WARN] Overview refresh: $_`n") }
    try { Refresh-DMARCData }      catch { $txtLog.AppendText("[WARN] DMARC refresh: $_`n") }
    try { Refresh-TLSData }        catch { $txtLog.AppendText("[WARN] TLS refresh: $_`n") }
    try { Refresh-Senders }        catch { $txtLog.AppendText("[WARN] Senders refresh: $_`n") }
    try { Refresh-Sources }        catch { $txtLog.AppendText("[WARN] Sources refresh: $_`n") }
    try { Refresh-Drift }          catch { $txtLog.AppendText("[WARN] Drift refresh: $_`n") }
    try { Refresh-DNSHealth }      catch { $txtLog.AppendText("[WARN] DNS refresh: $_`n") }
    try { Refresh-RUFData }        catch { $txtLog.AppendText("[WARN] RUF refresh: $_`n") }
    try { Refresh-TrendChart }     catch { $txtLog.AppendText("[WARN] Trend refresh: $_`n") }
    try { Refresh-GeoMap }         catch { $txtLog.AppendText("[WARN] Geo refresh: $_`n") }
    try { Refresh-ProtocolStatus } catch { $txtLog.AppendText("[WARN] Protocol refresh: $_`n") }
}
#endregion

#region Settings dialog
function Show-Settings {
    $cfg = Get-AllSettings
    [xml]$sx = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Settings" Height="780" Width="640" Background="#161B22" WindowStartupLocation="CenterOwner" ResizeMode="NoResize" FontFamily="Segoe UI">
<Grid Margin="24">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Grid.Row="0" Text="Settings" FontSize="18" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,16"/>
    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto"><StackPanel>
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4">Tenant ID (DPAPI)</TextBlock>
        <TextBox x:Name="fTenantId" Margin="0,0,0,10" Background="#0D1117" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/>
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4">Client ID (DPAPI)</TextBlock>
        <TextBox x:Name="fClientId" Margin="0,0,0,10" Background="#0D1117" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/>
        <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4">Mailbox Address (DPAPI)</TextBlock>
        <TextBox x:Name="fMailbox" Margin="0,0,0,10" Background="#0D1117" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/>
        <TextBlock Text="Working Directory" Foreground="#6E7681" FontSize="11" Margin="0,0,0,4"/>
        <Grid Margin="0,0,0,10"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <TextBox x:Name="fWorkingDir" Grid.Column="0" Background="#0D1117" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/>
            <Button x:Name="btnBrowseDir" Grid.Column="1" Content="Browse" Margin="6,0,0,0" Padding="12,6" FontSize="12" Cursor="Hand" Background="#21262D" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1"/>
        </Grid>
        <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="14,10" Margin="0,0,0,10">
            <StackPanel><TextBlock Text="Certificate" Foreground="#E6EDF3" FontWeight="SemiBold" FontSize="12" Margin="0,0,0,8"/>
                <ComboBox x:Name="fCertStore" Width="200" HorizontalAlignment="Left" Margin="0,0,0,8"><ComboBoxItem Content="LocalMachine" IsSelected="True"/><ComboBoxItem Content="CurrentUser"/></ComboBox>
                <TextBox x:Name="fCertThumbprint" Background="#161B22" Foreground="#7EE787" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="11" FontFamily="Cascadia Code, Consolas, Courier New" CaretBrush="#7EE787" Margin="0,0,0,8"/>
                <Button x:Name="btnGenCert" Content="Generate Certificate + Export .cer" Padding="12,7" FontSize="12" Cursor="Hand" Background="#1F6FEB" Foreground="White" BorderThickness="0" HorizontalAlignment="Left"/>
                <TextBlock x:Name="lblCertStatus" Foreground="#6E7681" FontSize="11" TextWrapping="Wrap" Margin="0,8,0,0"/>
            </StackPanel>
        </Border>
        <Grid Margin="0,0,0,10"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0" Margin="0,0,8,0"><TextBlock Text="Retention Days" Foreground="#6E7681" FontSize="11" Margin="0,0,0,4"/><TextBox x:Name="fRetention" Background="#0D1117" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/></StackPanel>
            <StackPanel Grid.Column="1"><TextBlock Text="Source Folder" Foreground="#6E7681" FontSize="11" Margin="0,0,0,4"/><TextBox x:Name="fSourceFolder" Background="#0D1117" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/></StackPanel>
        </Grid>
        <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="14,10" Margin="0,0,0,10">
            <StackPanel><TextBlock Text="Geolocation + Alerts" Foreground="#E6EDF3" FontWeight="SemiBold" FontSize="12" Margin="0,0,0,8"/>
                <CheckBox x:Name="fEnableGeo" Content="Enable IP geolocation (ipinfo.io)" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,6"/>
                <TextBox x:Name="fGeoToken" Background="#161B22" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5" Margin="0,0,0,8"/>
                <CheckBox x:Name="fEnableAlerts" Content="Enable failure rate alerts" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,6"/>
                <Grid Margin="0,0,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <TextBox x:Name="fAlertThreshold" Grid.Column="0" Background="#161B22" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5" Margin="0,0,8,0"/>
                    <TextBox x:Name="fAlertEmail" Grid.Column="1" Background="#161B22" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/>
                </Grid>
                <TextBlock Foreground="#6E7681" FontSize="11" Margin="0,0,0,4">Teams Webhook URL (DPAPI)</TextBlock>
                <TextBox x:Name="fTeamsWebhook" Background="#161B22" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/>
            </StackPanel>
        </Border>
        <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="14,10" Margin="0,0,0,10">
            <StackPanel><TextBlock Text="Advanced Monitoring" Foreground="#E6EDF3" FontWeight="SemiBold" FontSize="12" Margin="0,0,0,8"/>
                <CheckBox x:Name="fEnableNewSender" Content="New sender alerts" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,4"/>
                <CheckBox x:Name="fEnableVolume" Content="Volume anomaly alerts" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,4"/>
                <TextBox x:Name="fVolumeMultiplier" Background="#161B22" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,4" FontSize="12" CaretBrush="#CDD9E5" Width="120" HorizontalAlignment="Left" Margin="0,0,0,8"/>
                <CheckBox x:Name="fEnableDNSHealth" Content="DNS health checks (SPF depth, DMARC audit)" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,4"/>
                <CheckBox x:Name="fEnableCousin" Content="Cousin domain detection (Levenshtein 2)" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,4"/>
                <CheckBox x:Name="fEnableCoverage" Content="Track reporting org coverage" Foreground="#CDD9E5" FontSize="12"/>
            </StackPanel>
        </Border>
        <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="14,10" Margin="0,0,0,10">
            <StackPanel><TextBlock Text="Protocol Monitoring" Foreground="#E6EDF3" FontWeight="SemiBold" FontSize="12" Margin="0,0,0,8"/>
                <CheckBox x:Name="fEnableMTASTS" Content="MTA-STS policy monitoring" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,4"/>
                <CheckBox x:Name="fEnableBIMI" Content="BIMI record validation" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,4"/>
                <CheckBox x:Name="fEnableDKIM" Content="DKIM signing domain tracking" Foreground="#CDD9E5" FontSize="12"/>
            </StackPanel>
        </Border>
        <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="14,10">
            <StackPanel><TextBlock Text="Daily Digest" Foreground="#E6EDF3" FontWeight="SemiBold" FontSize="12" Margin="0,0,0,8"/>
                <CheckBox x:Name="fEnableDigest" Content="Send daily HTML digest email" Foreground="#CDD9E5" FontSize="12" Margin="0,0,0,6"/>
                <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="100"/></Grid.ColumnDefinitions>
                    <TextBox x:Name="fDigestEmail" Grid.Column="0" Background="#161B22" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5" Margin="0,0,8,0"/>
                    <TextBox x:Name="fDigestHour" Grid.Column="1" Background="#161B22" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12" CaretBrush="#CDD9E5"/>
                </Grid>
            </StackPanel>
        </Border>
    </StackPanel></ScrollViewer>
    <TextBlock x:Name="lblValidation" Grid.Row="2" Foreground="#F85149" FontSize="11" Margin="0,10,0,0" TextWrapping="Wrap"/>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
        <Button x:Name="btnCancel" Content="Cancel" Margin="0,0,10,0" Padding="16,8" FontSize="12" Cursor="Hand" Background="#21262D" Foreground="#CDD9E5" BorderBrush="#30363D" BorderThickness="1"/>
        <Button x:Name="btnSave" Content="Save Settings" Padding="16,8" FontSize="12" Cursor="Hand" Background="#1F6FEB" Foreground="White" BorderThickness="0"/>
    </StackPanel>
</Grid></Window>
'@
    $sw = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $sx)); $sw.Owner = $window

    $sw.FindName("fTenantId").Text       = if ($cfg.TenantId)       { $cfg.TenantId }       else { "" }
    $sw.FindName("fClientId").Text       = if ($cfg.ClientId)       { $cfg.ClientId }       else { "" }
    $sw.FindName("fMailbox").Text        = if ($cfg.MailboxAddress) { $cfg.MailboxAddress } else { "" }
    $sw.FindName("fWorkingDir").Text     = if ($cfg.WorkingDir)     { $cfg.WorkingDir }     else { "" }
    $sw.FindName("fCertThumbprint").Text = if ($cfg.CertThumbprint) { $cfg.CertThumbprint } else { "" }
    $sw.FindName("fRetention").Text      = if ($cfg.RetentionDays)  { $cfg.RetentionDays }  else { "7" }
    $sw.FindName("fSourceFolder").Text   = if ($cfg.SourceFolder)   { $cfg.SourceFolder }   else { "Inbox" }
    if ($cfg.CertStore) { foreach ($i in $sw.FindName("fCertStore").Items) { if ($i.Content -eq $cfg.CertStore) { $sw.FindName("fCertStore").SelectedItem = $i; break } } }

    $sw.FindName("fEnableGeo").IsChecked       = ($cfg.EnableGeoLookup             -eq 1)
    $sw.FindName("fGeoToken").Text             = if ($cfg.GeoAPIToken)             { $cfg.GeoAPIToken }             else { "" }
    $sw.FindName("fEnableAlerts").IsChecked    = ($cfg.EnableAlerts                -eq 1)
    $sw.FindName("fAlertThreshold").Text       = if ($cfg.AlertThresholdPct)       { $cfg.AlertThresholdPct }       else { "10" }
    $sw.FindName("fAlertEmail").Text           = if ($cfg.AlertEmailTo)            { $cfg.AlertEmailTo }            else { "" }
    $sw.FindName("fTeamsWebhook").Text         = if ($cfg.TeamsWebhookUrl)         { $cfg.TeamsWebhookUrl }         else { "" }
    $sw.FindName("fEnableNewSender").IsChecked = ($cfg.EnableNewSenderAlerts       -eq 1)
    $sw.FindName("fEnableVolume").IsChecked    = ($cfg.EnableVolumeAnomalyAlerts   -eq 1)
    $sw.FindName("fVolumeMultiplier").Text     = if ($cfg.VolumeMultiplier)        { $cfg.VolumeMultiplier }        else { "3.0" }
    $sw.FindName("fEnableDNSHealth").IsChecked = ($cfg.EnableDNSHealthCheck        -eq 1)
    $sw.FindName("fEnableCousin").IsChecked    = ($cfg.EnableCousinDomainDetection -eq 1)
    $sw.FindName("fEnableCoverage").IsChecked  = ($cfg.EnableReportingCoverage     -eq 1)
    $sw.FindName("fEnableMTASTS").IsChecked    = ($cfg.EnableMTASTSCheck           -eq 1)
    $sw.FindName("fEnableBIMI").IsChecked      = ($cfg.EnableBIMI                  -eq 1)
    $sw.FindName("fEnableDKIM").IsChecked      = ($cfg.EnableDKIMTracking          -eq 1)
    $sw.FindName("fEnableDigest").IsChecked    = ($cfg.EnableDailyDigest           -eq 1)
    $sw.FindName("fDigestEmail").Text          = if ($cfg.DigestEmailTo)           { $cfg.DigestEmailTo }           else { "" }
    $sw.FindName("fDigestHour").Text           = if ($cfg.DigestHour)              { $cfg.DigestHour }              else { "7" }

    $sw.FindName("btnBrowseDir").Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.SelectedPath = $sw.FindName("fWorkingDir").Text
        if ($dlg.ShowDialog() -eq "OK") { $sw.FindName("fWorkingDir").Text = $dlg.SelectedPath }
    })
    $sw.FindName("btnGenCert").Add_Click({
        $store = ($sw.FindName("fCertStore").SelectedItem).Content
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Title = "Save .cer (upload to Entra)"; $dlg.Filter = "Certificate (*.cer)|*.cer"
        $dlg.FileName = "DMARCMonitor-$($env:COMPUTERNAME).cer"
        $dlg.InitialDirectory = [Environment]::GetFolderPath("Desktop")
        if (-not $dlg.ShowDialog()) { return }
        try {
            $cert = New-SelfSignedCertificate -Subject "CN=DMARCMonitor-$($env:COMPUTERNAME)" -CertStoreLocation "Cert:\$store\My" -KeyExportPolicy "NonExportable" -KeySpec "Signature" -KeyLength 2048 -HashAlgorithm "SHA512" -NotAfter (Get-Date).AddYears(2) -KeyUsage "DigitalSignature" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") -EA Stop
            Export-Certificate -Cert $cert -FilePath $dlg.FileName -Type CERT | Out-Null
            $sw.FindName("fCertThumbprint").Text = $cert.Thumbprint
            $sw.FindName("lblCertStatus").Foreground = [System.Windows.Media.Brushes]::LightGreen
            $sw.FindName("lblCertStatus").Text = "Cert created (SHA-512, RSA-2048, NonExportable). .cer saved to: $($dlg.FileName). Upload to Entra > App registrations > Certificates and secrets."
        } catch {
            $sw.FindName("lblCertStatus").Foreground = [System.Windows.Media.Brushes]::Tomato
            $sw.FindName("lblCertStatus").Text = "Failed: $_"
        }
    })
    $sw.FindName("btnCancel").Add_Click({ $sw.Close() })
    $sw.FindName("btnSave").Add_Click({
        $lbl = $sw.FindName("lblValidation"); $errors = @()
        $tid = $sw.FindName("fTenantId").Text.Trim(); $cid = $sw.FindName("fClientId").Text.Trim()
        $mb = $sw.FindName("fMailbox").Text.Trim(); $wd = $sw.FindName("fWorkingDir").Text.Trim()
        $thumb = $sw.FindName("fCertThumbprint").Text.Trim(); $store = ($sw.FindName("fCertStore").SelectedItem).Content
        $rd = $sw.FindName("fRetention").Text.Trim(); $src = $sw.FindName("fSourceFolder").Text.Trim()
        if ([string]::IsNullOrWhiteSpace($tid))   { $errors += "Tenant ID required" }
        if ([string]::IsNullOrWhiteSpace($cid))   { $errors += "Client ID required" }
        if ([string]::IsNullOrWhiteSpace($mb))    { $errors += "Mailbox required" }
        if ([string]::IsNullOrWhiteSpace($wd))    { $errors += "Working dir required" }
        if ([string]::IsNullOrWhiteSpace($thumb)) { $errors += "Cert thumbprint required - use Generate Certificate" }
        if ([string]::IsNullOrWhiteSpace($src))   { $errors += "Source folder required" }
        $rdInt = 0; if (-not [int]::TryParse($rd, [ref]$rdInt) -or $rdInt -lt 1) { $errors += "Retention must be positive integer" }
        $atText = $sw.FindName("fAlertThreshold").Text.Trim(); $atInt = 10
        if ($atText -and -not [int]::TryParse($atText, [ref]$atInt)) { $errors += "Alert threshold must be a whole number (e.g. 10)" }
        if ($atInt -lt 0 -or $atInt -gt 100) { $errors += "Alert threshold must be 0-100" }
        $dhText = $sw.FindName("fDigestHour").Text.Trim(); $dhInt = 7
        if ($dhText -and -not [int]::TryParse($dhText, [ref]$dhInt)) { $errors += "Digest hour must be a whole number 0-23" }
        if ($dhInt -lt 0 -or $dhInt -gt 23) { $errors += "Digest hour must be 0-23" }
        if ($thumb -and -not (Test-Path "Cert:\$store\My\$thumb")) { $errors += "Cert thumbprint not found in $store\My" }
        if ($errors.Count -gt 0) { $lbl.Text = $errors -join "`n"; return }

        Set-RegEncrypted "TenantId"       $tid
        Set-RegEncrypted "ClientId"       $cid
        Set-RegEncrypted "MailboxAddress" $mb
        Set-RegPlain     "CertThumbprint" $thumb
        Set-RegPlain     "CertStore"      $store
        Set-RegPlain     "WorkingDir"     $wd
        Set-RegPlain     "RetentionDays"  $rdInt
        Set-RegPlain     "SourceFolder"   $src
        Set-RegPlain     "EnableGeoLookup"             $([int]($sw.FindName("fEnableGeo").IsChecked -eq $true))
        Set-RegPlain     "GeoAPIToken"                 $sw.FindName("fGeoToken").Text.Trim()
        Set-RegPlain     "EnableAlerts"                $([int]($sw.FindName("fEnableAlerts").IsChecked -eq $true))
        Set-RegPlain     "AlertThresholdPct"           $atInt
        Set-RegPlain     "AlertEmailTo"                $sw.FindName("fAlertEmail").Text.Trim()
        # Save webhook on non-empty; remove from registry when cleared so we
        # don't keep sending alerts to a stale channel.
        $webhookText = $sw.FindName("fTeamsWebhook").Text.Trim()
        if ($webhookText) { Set-RegEncrypted "TeamsWebhookUrl" $webhookText }
        else { Remove-ItemProperty -Path $script:RegPath -Name "TeamsWebhookUrl" -EA SilentlyContinue }
        Set-RegPlain     "EnableNewSenderAlerts"       $([int]($sw.FindName("fEnableNewSender").IsChecked -eq $true))
        Set-RegPlain     "EnableVolumeAnomalyAlerts"   $([int]($sw.FindName("fEnableVolume").IsChecked -eq $true))
        Set-RegPlain     "VolumeMultiplier"            $sw.FindName("fVolumeMultiplier").Text.Trim()
        Set-RegPlain     "EnableDNSHealthCheck"        $([int]($sw.FindName("fEnableDNSHealth").IsChecked -eq $true))
        Set-RegPlain     "EnableCousinDomainDetection" $([int]($sw.FindName("fEnableCousin").IsChecked -eq $true))
        Set-RegPlain     "EnableReportingCoverage"     $([int]($sw.FindName("fEnableCoverage").IsChecked -eq $true))
        Set-RegPlain     "EnableMTASTSCheck"           $([int]($sw.FindName("fEnableMTASTS").IsChecked -eq $true))
        Set-RegPlain     "EnableBIMI"                  $([int]($sw.FindName("fEnableBIMI").IsChecked -eq $true))
        Set-RegPlain     "EnableDKIMTracking"          $([int]($sw.FindName("fEnableDKIM").IsChecked -eq $true))
        Set-RegPlain     "EnableDailyDigest"           $([int]($sw.FindName("fEnableDigest").IsChecked -eq $true))
        Set-RegPlain     "DigestEmailTo"               $sw.FindName("fDigestEmail").Text.Trim()
        Set-RegPlain     "DigestHour"                  $dhInt

        $sw.Close(); Refresh-AllData
        $txtStatus.Text = "Settings saved"; $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
        $btnRun.IsEnabled = Test-SettingsComplete
        # Re-evaluate cert banner so a freshly regenerated cert clears it
        try { Test-CertExpiryUI } catch {}
    })
    $sw.ShowDialog() | Out-Null
}
#endregion

#region Engine runner + Module installer
$script:sync = [hashtable]::Synchronized(@{ IsRunning=$false; LogQueue=[System.Collections.Concurrent.ConcurrentQueue[string]]::new(); Done=$false; ExitCode=-1 })

function Start-EngineRun {
    if ($script:sync.IsRunning) { [System.Windows.MessageBox]::Show("Run already in progress.", "Busy", "OK", "Information") | Out-Null; return }
    if (-not (Test-SettingsComplete)) { Show-Settings; return }
    if (-not (Test-Path $script:EngineScript)) { [System.Windows.MessageBox]::Show("Engine script not found:`n$($script:EngineScript)", "Engine Missing", "OK", "Error") | Out-Null; return }

    $cfg = Get-AllSettings
    $script:sync.IsRunning = $true; $script:sync.Done = $false; $script:sync.ExitCode = -1
    # ConcurrentQueue doesn't have Clear() on PS5.1; drain it instead
    $_drain = ''
    while ($script:sync.LogQueue.TryDequeue([ref]$_drain)) {}
    $btnRun.IsEnabled = $false; $txtRunStatus.Text = "Running..."
    $txtStatus.Text = "Ingesting reports..."; $txtStatus.Foreground = [System.Windows.Media.Brushes]::Orange

    $engineP = $script:EngineScript
    $params = @{
        TenantId=$cfg.TenantId; ClientId=$cfg.ClientId; MailboxAddress=$cfg.MailboxAddress
        CertThumbprint=$cfg.CertThumbprint; CertStore=$cfg.CertStore
        WorkingDir=$cfg.WorkingDir; RetentionDays=[int]$cfg.RetentionDays; SourceFolder=$cfg.SourceFolder
        EnableGeoLookup=($cfg.EnableGeoLookup -eq 1); GeoAPIToken=if($cfg.GeoAPIToken){$cfg.GeoAPIToken}else{""}
        EnableAlerts=($cfg.EnableAlerts -eq 1); AlertThresholdPct=if($cfg.AlertThresholdPct){[int]$cfg.AlertThresholdPct}else{10}
        AlertEmailTo=if($cfg.AlertEmailTo){$cfg.AlertEmailTo}else{""}; TeamsWebhookUrl=if($cfg.TeamsWebhookUrl){$cfg.TeamsWebhookUrl}else{""}
        EnableNewSenderAlerts=($cfg.EnableNewSenderAlerts -eq 1); EnableVolumeAnomalyAlerts=($cfg.EnableVolumeAnomalyAlerts -eq 1)
        VolumeAnomalyMultiplier=if($cfg.VolumeMultiplier){[double]$cfg.VolumeMultiplier}else{3.0}
        EnableDNSHealthCheck=($cfg.EnableDNSHealthCheck -eq 1); EnableCousinDomainDetection=($cfg.EnableCousinDomainDetection -eq 1)
        EnableReportingCoverage=($cfg.EnableReportingCoverage -eq 1)
        EnableDailyDigest=($cfg.EnableDailyDigest -eq 1); DigestEmailTo=if($cfg.DigestEmailTo){$cfg.DigestEmailTo}else{""}
        DigestHour=if($cfg.DigestHour){[int]$cfg.DigestHour}else{7}
        EnableMTASTSCheck=($cfg.EnableMTASTSCheck -eq 1); EnableBIMI=($cfg.EnableBIMI -eq 1); EnableDKIMTracking=($cfg.EnableDKIMTracking -eq 1)
    }

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = [System.Threading.ApartmentState]::MTA
    $rs.ThreadOptions  = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('sync', $script:sync)
    $rs.SessionStateProxy.SetVariable('enginePath', $engineP)
    $rs.SessionStateProxy.SetVariable('engParams', $params)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    $ps.AddScript({
        try {
            # Stream the engine's output line-by-line through the pipeline so the
            # UI log panel shows progress live, instead of dumping everything
            # only after the engine has finished.
            & $enginePath @engParams 2>&1 | ForEach-Object { $sync.LogQueue.Enqueue($_.ToString()) }
            $sync.ExitCode = if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 }
        } catch { $sync.LogQueue.Enqueue("[ERROR] $_"); $sync.ExitCode = 99 }
        finally { $sync.IsRunning = $false; $sync.Done = $true }
    }) | Out-Null
    # Capture the async handle and PS instance so the timer can dispose them
    $script:engineAsync = $ps.BeginInvoke()
    $script:enginePS    = $ps
    $script:engineRS    = $rs

    $timer = New-Object System.Windows.Threading.DispatcherTimer; $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $script:engineTimer = $timer
    $timer.Add_Tick({
        try {
            $line = ''
            while ($script:sync.LogQueue.TryDequeue([ref]$line)) {
                $txtLog.AppendText("$line`n"); $txtLog.ScrollToEnd()
            }
            if ($script:sync.Done) {
                $timer.Stop(); $code = $script:sync.ExitCode
                switch ($code) {
                    0       { $txtStatus.Text = "Completed"; $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen }
                    4       { $txtStatus.Text = "No new reports"; $txtStatus.Foreground = [System.Windows.Media.Brushes]::Orange }
                    default { $txtStatus.Text = "Error (exit $code)"; $txtStatus.Foreground = [System.Windows.Media.Brushes]::Tomato }
                }
                $txtLastRun.Text = "Last run: $(Get-Date -Format 'HH:mm:ss') | Exit: $code"
                $txtRunStatus.Text = "Exit: $code"; $btnRun.IsEnabled = $true
                # Drain any final log lines that arrived between the loop and Done flip
                while ($script:sync.LogQueue.TryDequeue([ref]$line)) {
                    $txtLog.AppendText("$line`n"); $txtLog.ScrollToEnd()
                }
                # Dispose the runspace + PowerShell instance to avoid leaks per Run
                try { if ($script:enginePS -and $script:engineAsync) { $script:enginePS.EndInvoke($script:engineAsync) | Out-Null } } catch {}
                try { if ($script:enginePS) { $script:enginePS.Dispose() } } catch {}
                try { if ($script:engineRS) { $script:engineRS.Close(); $script:engineRS.Dispose() } } catch {}
                $script:enginePS = $null; $script:engineRS = $null; $script:engineAsync = $null
                Refresh-AllTabs
            }
        } catch {
            # Don't propagate dispatcher-tick exceptions (e.g. controls disposed on shutdown)
            try { $timer.Stop() } catch {}
        }
    })
    $timer.Start()
}

function Start-ModuleInstall {
    $btnInstallModule.IsEnabled = $false; $txtLog.AppendText("[INFO] Installing Microsoft.Graph.Authentication...`n")
    $script:sync.Done = $false
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
    $rs.SessionStateProxy.SetVariable('sync', $script:sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    $ps.AddScript({
        try { Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -EA Stop; $sync.LogQueue.Enqueue("[SUCCESS] Module installed.") }
        catch { $sync.LogQueue.Enqueue("[ERROR] Install failed: $_") }
        $sync.Done = $true
    }) | Out-Null
    $script:moduleAsync = $ps.BeginInvoke()
    $script:modulePS = $ps; $script:moduleRS = $rs
    $t = New-Object System.Windows.Threading.DispatcherTimer; $t.Interval = [TimeSpan]::FromMilliseconds(300)
    $t.Add_Tick({
        try {
            $line = ''
            while ($script:sync.LogQueue.TryDequeue([ref]$line)) { $txtLog.AppendText("$line`n") }
            if ($script:sync.Done) {
                $t.Stop(); $script:sync.Done = $false
                while ($script:sync.LogQueue.TryDequeue([ref]$line)) { $txtLog.AppendText("$line`n") }
                if (Test-GraphModule) { $bannerModule.Visibility = [System.Windows.Visibility]::Collapsed; $btnRun.IsEnabled = Test-SettingsComplete }
                $btnInstallModule.IsEnabled = $true
                try { if ($script:modulePS -and $script:moduleAsync) { $script:modulePS.EndInvoke($script:moduleAsync) | Out-Null } } catch {}
                try { if ($script:modulePS) { $script:modulePS.Dispose() } } catch {}
                try { if ($script:moduleRS) { $script:moduleRS.Close(); $script:moduleRS.Dispose() } } catch {}
                $script:modulePS = $null; $script:moduleRS = $null; $script:moduleAsync = $null
            }
        } catch { try { $t.Stop() } catch {} }
    })
    $t.Start()
}
#endregion

#region Schedule + cert expiry + export + report
function Show-ScheduleDialog {
    if (-not (Test-SettingsComplete)) { Show-Settings; return }
    if (-not (Test-Path $script:EngineScript)) { return }
    $existing = Get-ScheduledTask -TaskName "DMARC Monitor" -EA SilentlyContinue
    $msg = "Create scheduled task running every 30 minutes?`n`nTask: DMARC Monitor`nInterval: 30 minutes`nRuns as: $($env:USERDOMAIN)\$($env:USERNAME)$(if ($existing) { "`n`nNote: Existing task will be replaced." })"
    if ([System.Windows.MessageBox]::Show($msg, "Create Scheduled Task", "YesNo", "Question") -ne "Yes") { return }
    try {
        $exe = if (Get-Command pwsh -EA SilentlyContinue) { (Get-Command pwsh).Source } else { "powershell.exe" }
        $action = New-ScheduledTaskAction -Execute $exe -Argument "-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$($script:EngineScript)`""
        $start = (Get-Date).AddMinutes(2)
        $trigger = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration ([System.TimeSpan]::MaxValue)
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RunOnlyIfNetworkAvailable -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 25) -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 2
        Register-ScheduledTask -TaskName "DMARC Monitor" -TaskPath "\DMARCMonitor\" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
        $txtStatus.Text = "Scheduled task created - every 30 min"; $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
        $txtLog.AppendText("[SUCCESS] Scheduled task created. First run in ~2 minutes.`n")
    } catch { [System.Windows.MessageBox]::Show("Failed: $_`n`nTry running as administrator.", "Task Failed", "OK", "Error") | Out-Null }
}

function Test-CertExpiryUI {
    # Reset state every call so a freshly regenerated cert clears the banner
    # and re-enables Run without needing to relaunch the dashboard.
    $bannerCert.Visibility = [System.Windows.Visibility]::Collapsed
    if (Test-SettingsComplete -and (Test-GraphModule)) { $btnRun.IsEnabled = $true }

    $cfg = Get-AllSettings
    if ([string]::IsNullOrWhiteSpace($cfg.CertThumbprint)) { return }
    try {
        $path = "Cert:\$($cfg.CertStore)\My\$($cfg.CertThumbprint)"
        if (-not (Test-Path $path)) { return }
        $cert = Get-Item $path; $days = ($cert.NotAfter - (Get-Date)).Days
        if ($days -le 0) {
            $bannerCert.Visibility = [System.Windows.Visibility]::Visible
            $txtCertBanner.Text = "Certificate EXPIRED on $($cert.NotAfter.ToString('yyyy-MM-dd')). Re-generate in Settings."
            $btnRun.IsEnabled = $false
        } elseif ($days -le 60) {
            $bannerCert.Visibility = [System.Windows.Visibility]::Visible
            $txtCertBanner.Text = "Certificate expires in $days days. Regenerate via Settings > Generate Certificate."
        }
    } catch {}
}

function Export-CurrentView {
    $view = $dgDMARC.ItemsSource
    if (-not $view -or $view.Count -eq 0) { [System.Windows.MessageBox]::Show("No data.", "Export", "OK", "Information") | Out-Null; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = "CSV (*.csv)|*.csv"; $dlg.FileName = "dmarc_export_$(Get-Date -Format 'yyyy-MM-dd_HHmm').csv"
    if ($dlg.ShowDialog()) {
        $view | ForEach-Object { $_ } | Export-Csv $dlg.FileName -NoTypeInformation -Encoding UTF8
        $txtStatus.Text = "Exported"; $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
    }
}

function Start-HTMLReport {
    if (-not (Test-SettingsComplete)) { return }
    if (-not (Test-Path $script:ReportScript)) {
        [System.Windows.MessageBox]::Show("Invoke-HTMLReportGenerator.ps1 not in $script:ScriptDir", "Missing", "OK", "Warning") | Out-Null; return
    }
    $cfg = Get-AllSettings
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = "HTML (*.html)|*.html"; $dlg.FileName = "DMARC_Report_$(Get-Date -Format 'yyyy-MM-dd').html"
    $dlg.InitialDirectory = Join-Path $cfg.WorkingDir "Reports"
    if (-not $dlg.ShowDialog()) { return }
    $txtLog.AppendText("[INFO] Generating HTML report...`n")
    $exe = if (Get-Command pwsh -EA SilentlyContinue) { "pwsh" } else { "powershell" }
    $domArgs = if ($script:SelectedDomain -ne "All Domains") { @("-FilterDomain",$script:SelectedDomain) } else { @() }
    $argsList = @("-ExecutionPolicy","Bypass","-NonInteractive","-File","`"$($script:ReportScript)`"","-WorkingDir","`"$($cfg.WorkingDir)`"","-OutputPath","`"$($dlg.FileName)`"","-Open") + $domArgs
    $proc = Start-Process -FilePath $exe -ArgumentList $argsList -PassThru -WindowStyle Hidden
    $proc.WaitForExit(30000) | Out-Null
    if (Test-Path $dlg.FileName) { $txtLog.AppendText("[SUCCESS] Report: $($dlg.FileName)`n"); $txtStatus.Text = "Report generated"; $txtStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen }
}
#endregion

#region Event handlers
$btnRun.Add_Click({ Start-EngineRun })
$btnRefresh.Add_Click({ Refresh-AllData })
$btnSettings.Add_Click({ Show-Settings })
$btnSchedule.Add_Click({ Show-ScheduleDialog })
$btnExport.Add_Click({ Export-CurrentView })
$btnGenReport.Add_Click({ Start-HTMLReport })
$btnClearLog.Add_Click({ $txtLog.Clear() })
$btnInstallModule.Add_Click({ Start-ModuleInstall })
$btnDMARCFilter.Add_Click({ Refresh-DMARCData })
$btnDMARCReset.Add_Click({ $cmbDMARCResult.SelectedIndex=0; $cmbFailReason.SelectedIndex=0; $txtDMARCIP.Text=""; Refresh-DMARCData })
$txtDMARCIP.Add_KeyDown({ if ($_.Key -eq [System.Windows.Input.Key]::Return) { Refresh-DMARCData } })
$btnTLSFilter.Add_Click({ Refresh-TLSData })
$btnTLSReset.Add_Click({ $cmbTLSResult.SelectedIndex=0; Refresh-TLSData })
# Drill-through: clicking a service card on the Senders page navigates to a
# pseudo-URL like "dmarc:drill?service=SendGrid". Intercept Navigating,
# cancel the actual nav, set $script:DrillService, switch to Sources tab.
$wbSenders.Add_Navigating({
    param($s, $e)
    $u = [string]$e.Uri
    if ($u -and $u.StartsWith('dmarc:drill')) {
        $e.Cancel = $true
        try {
            $q = $u.Substring($u.IndexOf('?') + 1)
            $svc = $null
            foreach ($pair in $q.Split('&')) {
                $kv = $pair.Split('=',2)
                if ($kv.Length -eq 2 -and $kv[0] -eq 'service') { $svc = [uri]::UnescapeDataString($kv[1]) }
            }
            if ($svc) {
                $script:DrillService = $svc
                # Switch to Sources tab (index 4 after Senders was inserted at 3)
                $tabMain.SelectedIndex = 4
                Refresh-Sources
            }
        } catch { $txtLog.AppendText("[WARN] Drill nav: $_`n") }
    }
})
$btnAuthorize.Add_Click({ Show-AuthorizationWizard })
$btnRefreshDrift.Add_Click({ Refresh-Drift })
$cmbDriftType.Add_SelectionChanged({ Refresh-Drift })
$cmbSrcService.Add_SelectionChanged({
    # Manual service-dropdown change clears the drill-from-card state
    $sel = if ($cmbSrcService.SelectedItem) { ($cmbSrcService.SelectedItem).Content } else { 'All Services' }
    if ($sel -ne $script:DrillService) { $script:DrillService = $null }
    Refresh-Sources
})
$btnApprove.Add_Click({ Set-SourceApproval -Approved $true })
$btnUnapprove.Add_Click({ Set-SourceApproval -Approved $false })
$btnRefreshSources.Add_Click({ Refresh-Sources })
$cmbSrcStatus.Add_SelectionChanged({ Refresh-Sources })
$btnRefreshDNS.Add_Click({ Refresh-DNSHealth })
$btnInspectSPF.Add_Click({ Invoke-SPFInspection })
$btnSilentCheck.Add_Click({ Invoke-SilentFailureCheck })
$btnRefreshRUF.Add_Click({ Refresh-RUFData })
$btnRefreshTrend.Add_Click({ Refresh-TrendChart })
$cmbTrendPeriod.Add_SelectionChanged({ Refresh-TrendChart })
$btnRefreshProtocol.Add_Click({ Refresh-ProtocolStatus })
$txtDomainSearch.Add_TextChanged({ Update-Sidebar -Filter $txtDomainSearch.Text.Trim() })

$lbDomains.Add_SelectionChanged({
    if ($lbDomains.SelectedItem) {
        $script:SelectedDomain = $lbDomains.SelectedItem.DomainName
        Refresh-AllData
    }
})

$tabMain.Add_SelectionChanged({
    # Index map after adding Senders (3) + DNS Drift (5):
    #   0 Overview  1 DMARC  2 TLS  3 Senders  4 Sources  5 DNS Drift
    #   6 DNS Health  7 Forensic  8 Trends  9 Protocol
    switch ($tabMain.SelectedIndex) {
        0 { Refresh-Overview }
        1 { Refresh-DMARCData }
        2 { Refresh-TLSData }
        3 { Refresh-Senders }
        4 { Refresh-Sources }
        5 { Refresh-Drift }
        6 { Refresh-DNSHealth }
        7 { Refresh-RUFData }
        8 { Refresh-TrendChart; Refresh-GeoMap }
        9 { Refresh-ProtocolStatus }
    }
})

$window.Add_Loaded({
    if (-not (Test-GraphModule)) {
        $bannerModule.Visibility = [System.Windows.Visibility]::Visible
        $btnRun.IsEnabled = $false
        $txtLog.AppendText("[WARN] Microsoft.Graph.Authentication not installed.`n")
    } else { $btnRun.IsEnabled = Test-SettingsComplete }
    Test-CertExpiryUI
    Update-Sidebar
    if (-not (Test-SettingsComplete)) {
        $txtStatus.Text = "Setup required - open Settings"
        $txtStatus.Foreground = [System.Windows.Media.Brushes]::Orange
        $window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{ Show-Settings }) | Out-Null
    } else {
        if ($lbDomains.Items.Count -gt 0) { $lbDomains.SelectedIndex = 0 }
    }
})
#endregion

$window.ShowDialog() | Out-Null
