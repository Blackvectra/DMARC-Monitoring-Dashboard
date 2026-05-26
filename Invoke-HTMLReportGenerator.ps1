#Requires -Version 5.1
<#
.SYNOPSIS
    Generate a self-contained DMARC HTML report and (optionally) open it in the
    default browser. Used by the Start-DMARCDashboard "Report" toolbar button
    and also runnable headless.

.DESCRIPTION
    Reads the parsed CSVs under <WorkingDir>\Reports and the State JSON files,
    produces one standalone HTML file with KPI cards, a Chart.js line chart of
    pass rate over time, top-senders table, country breakdown, and a recent
    records grid. Opens in Edge/Chrome/Firefox so the user gets a modern JS
    engine instead of the WPF IE-based WebBrowser control.

.PARAMETER WorkingDir
    Root directory the engine writes to (contains Reports\, State\, Logs\).

.PARAMETER OutputPath
    Destination .html file path.

.PARAMETER FilterDomain
    Optional. Limit the report to a single domain.

.PARAMETER Days
    Look-back window for aggregate data. Default 14.

.PARAMETER Open
    If set, opens the generated file with the default browser.
#>
param(
    [Parameter(Mandatory)][string]$WorkingDir,
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$FilterDomain,
    [int]$Days = 14,
    [switch]$Open
)

$ErrorActionPreference = 'Continue'

function Get-Json {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try { return Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
}

function HtmlEncode {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return '' }
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

# JSON-string escape for values embedded inside a <script> tag. HtmlEncode
# is wrong there: browsers don't decode entities in script context, and a
# raw quote breaks the JSON. Also neutralizes "</" so a value can never
# end the enclosing <script>.
function JsonEscape {
    param([string]$s)
    if ($null -eq $s) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $s.ToCharArray()) {
        switch ([int]$c) {
            8  { [void]$sb.Append('\b') }
            9  { [void]$sb.Append('\t') }
            10 { [void]$sb.Append('\n') }
            12 { [void]$sb.Append('\f') }
            13 { [void]$sb.Append('\r') }
            34 { [void]$sb.Append('\"') }
            47 { [void]$sb.Append('\/') } # forward slash escaped so "</script>" is harmless
            92 { [void]$sb.Append('\\') }
            default {
                if ([int]$c -lt 32 -or [int]$c -eq 0x2028 -or [int]$c -eq 0x2029) {
                    [void]$sb.AppendFormat('\u{0:x4}', [int]$c)
                } else {
                    [void]$sb.Append($c)
                }
            }
        }
    }
    return $sb.ToString()
}

function Get-SafeKey { param([string]$Domain) return ($Domain -replace '[^a-zA-Z0-9_]','_') }

$reportDir = Join-Path $WorkingDir 'Reports'
$stateDir  = Join-Path $WorkingDir 'State'

if (-not (Test-Path $reportDir)) {
    "ERROR: Reports directory not found at $reportDir" | Write-Error
    exit 1
}

$cutoff = (Get-Date).AddDays(-$Days)
$records = @()
Get-ChildItem $reportDir -Filter 'dmarc_aggregate_*.csv' -EA SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $cutoff } |
    Sort-Object Name |
    ForEach-Object { try { $records += Import-Csv $_.FullName } catch {} }

if ($FilterDomain) { $records = $records | Where-Object { $_.Domain -eq $FilterDomain } }

$prog  = Get-Json (Join-Path $stateDir 'progression.json')
$mta   = Get-Json (Join-Path $stateDir 'mta-sts.json')
$bimi  = Get-Json (Join-Path $stateDir 'bimi.json')
$dkim  = Get-Json (Join-Path $stateDir 'dkim-selectors.json')
$src   = Get-Json (Join-Path $stateDir 'source-inventory.json')

$domains = @()
if ($FilterDomain) {
    $domains = @($FilterDomain)
} else {
    $set = @{}
    if ($records) { $records | Select-Object -ExpandProperty Domain -Unique | ForEach-Object { if ($_) { $set[$_] = $true } } }
    if ($prog -and $prog.domains) { $prog.domains.PSObject.Properties | ForEach-Object { if ($_.Value.domain) { $set[$_.Value.domain] = $true } } }
    $domains = @($set.Keys | Sort-Object)
}

# Aggregate stats
$totalPass = ($records | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
$totalFail = ($records | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
$totalPass = if ($null -eq $totalPass) { 0 } else { [int]$totalPass }
$totalFail = if ($null -eq $totalFail) { 0 } else { [int]$totalFail }
$totalMsgs = $totalPass + $totalFail
$passRate  = if ($totalMsgs -gt 0) { [math]::Round(($totalPass / $totalMsgs) * 100, 1) } else { 0 }

# Trend dataset per domain
$dates = @($records | Select-Object -ExpandProperty ReportDate -Unique | Sort-Object)
$colors = @('#3FB950','#79C0FF','#D29922','#F85149','#BC8CFF','#FFA657','#56D364','#FF7B72','#58A6FF','#E6EDF3')
$datasets = @()
$ci = 0
foreach ($dom in $domains) {
    $color = $colors[$ci % $colors.Count]; $ci++
    $points = foreach ($d in $dates) {
        $rows = $records | Where-Object { $_.Domain -eq $dom -and $_.ReportDate -eq $d }
        $p = ($rows | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
        $f = ($rows | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
        $t = [int]$p + [int]$f
        if ($t -gt 0) { [math]::Round(($p / $t) * 100, 1) } else { $null }
    }
    $pointsJson = ($points | ForEach-Object { if ($null -eq $_) { 'null' } else { $_ } }) -join ','
    $domJson = JsonEscape $dom
    $datasets += "{`"label`":`"$domJson`",`"data`":[$pointsJson],`"borderColor`":`"$color`",`"backgroundColor`":`"${color}33`",`"tension`":0.3,`"fill`":false,`"pointRadius`":4,`"spanGaps`":true}"
}
$labelsJson   = ($dates | ForEach-Object { "`"$(JsonEscape $_)`"" }) -join ','
$datasetsJson = $datasets -join ','

# Per-domain summary cards
$domainCards = ''
foreach ($dom in $domains) {
    $domRows = $records | Where-Object { $_.Domain -eq $dom }
    $dp = ($domRows | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
    $df = ($domRows | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
    $dp = if ($null -eq $dp) { 0 } else { [int]$dp }
    $df = if ($null -eq $df) { 0 } else { [int]$df }
    $dt = $dp + $df
    $dr = if ($dt -gt 0) { [math]::Round(($dp / $dt) * 100, 1) } else { 0 }

    $safeKey = Get-SafeKey -Domain $dom
    $policy  = if ($prog -and $prog.domains.$safeKey) { $prog.domains.$safeKey.currentPolicy } elseif ($domRows -and $domRows[0].Policy) { $domRows[0].Policy } else { 'unknown' }
    $mtaMode = if ($mta  -and $mta.domains.$safeKey)  { $mta.domains.$safeKey.PolicyMode } else { '-' }
    $bimiSt  = if ($bimi -and $bimi.domains.$safeKey) { $bimi.domains.$safeKey.Status }    else { '-' }
    $dkimDom = if ($dkim -and $dkim.domains.$safeKey) { $dkim.domains.$safeKey.dkimDomains } else { '' }

    $pColor = switch ($policy) { 'reject' { '#3FB950' } 'quarantine' { '#D29922' } default { '#F85149' } }
    $rColor = if ($dr -ge 95) { '#3FB950' } elseif ($dr -ge 80) { '#D29922' } else { '#F85149' }

    $domainCards += @"
<div class="card">
  <div class="card-head"><span class="dom">$(HtmlEncode $dom)</span><span class="pill" style="background:$pColor">p=$(HtmlEncode $policy)</span></div>
  <div class="kpis">
    <div class="kpi"><div class="kpi-v" style="color:$rColor">$dr%</div><div class="kpi-l">pass rate</div></div>
    <div class="kpi"><div class="kpi-v">$dt</div><div class="kpi-l">messages</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#3FB950">$dp</div><div class="kpi-l">pass</div></div>
    <div class="kpi"><div class="kpi-v" style="color:#F85149">$df</div><div class="kpi-l">fail</div></div>
  </div>
  <div class="meta"><span>MTA-STS: <b>$(HtmlEncode $mtaMode)</b></span><span>BIMI: <b>$(HtmlEncode $bimiSt)</b></span><span>DKIM: <b>$(HtmlEncode $dkimDom)</b></span></div>
</div>
"@
}

# Top senders
$senderRowsHtml = ''
$topSenders = $records | Group-Object SourceIP | ForEach-Object {
    $msgs = ($_.Group | Measure-Object MessageCount -Sum).Sum
    $pass = ($_.Group | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
    [PSCustomObject]@{
        IP      = $_.Name
        Msgs    = [int]$msgs
        Pass    = [int]$pass
        Rate    = if ([int]$msgs -gt 0) { [math]::Round(([int]$pass / [int]$msgs) * 100, 1) } else { 0 }
        Country = ($_.Group | Select-Object -ExpandProperty GeoCountry -Unique | Where-Object { $_ } | Select-Object -First 1)
        Org     = ($_.Group | Select-Object -ExpandProperty GeoOrg     -Unique | Where-Object { $_ } | Select-Object -First 1)
        Sender  = ($_.Group | Select-Object -ExpandProperty SenderClass -Unique | Where-Object { $_ } | Select-Object -First 1)
        Domain  = ($_.Group | Select-Object -ExpandProperty Domain     -Unique | Where-Object { $_ } | Select-Object -First 1)
    }
} | Sort-Object Msgs -Descending | Select-Object -First 25
foreach ($s in $topSenders) {
    $rc = if ($s.Rate -ge 95) { '#3FB950' } elseif ($s.Rate -ge 80) { '#D29922' } else { '#F85149' }
    $senderRowsHtml += "<tr><td class='mono'>$(HtmlEncode $s.IP)</td><td>$(HtmlEncode $s.Country)</td><td>$(HtmlEncode $s.Org)</td><td>$(HtmlEncode $s.Sender)</td><td>$(HtmlEncode $s.Domain)</td><td class='num'>$($s.Msgs)</td><td class='num' style='color:$rc'>$($s.Rate)%</td></tr>"
}
if (-not $senderRowsHtml) { $senderRowsHtml = "<tr><td colspan='7' class='empty'>No sender records in the last $Days days.</td></tr>" }

# Country breakdown
$countryRowsHtml = ''
$countryGroups = $records | Where-Object { $_.GeoCountry } | Group-Object GeoCountry | ForEach-Object {
    $msgs = ($_.Group | Measure-Object MessageCount -Sum).Sum
    $pass = ($_.Group | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
    [PSCustomObject]@{
        Country = $_.Name
        Msgs    = [int]$msgs
        Pass    = [int]$pass
        Rate    = if ([int]$msgs -gt 0) { [math]::Round(([int]$pass / [int]$msgs) * 100, 1) } else { 0 }
    }
} | Sort-Object Msgs -Descending
$maxCountryMsgs = ($countryGroups | Measure-Object Msgs -Maximum).Maximum
if (-not $maxCountryMsgs -or $maxCountryMsgs -lt 1) { $maxCountryMsgs = 1 }
foreach ($c in $countryGroups) {
    $rc = if ($c.Rate -ge 95) { '#3FB950' } elseif ($c.Rate -ge 80) { '#D29922' } else { '#F85149' }
    $barW = [math]::Round(($c.Msgs / $maxCountryMsgs) * 100, 1)
    $countryRowsHtml += "<tr><td class='mono'><b>$(HtmlEncode $c.Country)</b></td><td class='num'>$($c.Msgs)</td><td><div class='bar-wrap'><div class='bar' style='width:$barW%;background:$rc'></div></div></td><td class='num' style='color:$rc'>$($c.Rate)%</td></tr>"
}
if (-not $countryRowsHtml) { $countryRowsHtml = "<tr><td colspan='4' class='empty'>No geolocated sources. Enable IP geolocation in Settings.</td></tr>" }

# Recent records (most recent 100)
$recentRowsHtml = ''
$recent = $records | Sort-Object ParsedAt -Descending | Select-Object -First 100
foreach ($r in $recent) {
    $rc = if ($r.DMARCResult -eq 'pass') { '#3FB950' } else { '#F85149' }
    $recentRowsHtml += "<tr><td>$(HtmlEncode $r.ReportDate)</td><td>$(HtmlEncode $r.Domain)</td><td class='mono'>$(HtmlEncode $r.SourceIP)</td><td>$(HtmlEncode $r.OrgName)</td><td class='num'>$($r.MessageCount)</td><td style='color:$rc;font-weight:600'>$(HtmlEncode $r.DMARCResult)</td><td>$(HtmlEncode $r.FailReason)</td><td>$(HtmlEncode $r.OverrideReason)</td></tr>"
}
if (-not $recentRowsHtml) { $recentRowsHtml = "<tr><td colspan='8' class='empty'>No DMARC records yet. Run the engine after configuring.</td></tr>" }

$title       = if ($FilterDomain) { "DMARC Report: $FilterDomain" } else { "DMARC Portfolio Report" }
$titleSafe   = HtmlEncode $title
$generated   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$overallColor= if ($passRate -ge 95) { '#3FB950' } elseif ($passRate -ge 80) { '#D29922' } else { '#F85149' }
$hasChart    = ($dates.Count -gt 0 -and $datasets.Count -gt 0)

$chartBlock = if ($hasChart) { @"
<section class="panel">
  <h2>Pass Rate Trend (Last $Days Days)</h2>
  <canvas id="trendChart" style="max-height:420px"></canvas>
</section>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>
(function(){
  if (typeof Chart === 'undefined') {
    document.getElementById('trendChart').outerHTML = '<div class="empty">Chart.js failed to load. Check your internet connection and reload this report.</div>';
    return;
  }
  Chart.defaults.color = '#6E7681';
  Chart.defaults.borderColor = '#21262D';
  new Chart(document.getElementById('trendChart'), {
    type: 'line',
    data: { labels: [$labelsJson], datasets: [$datasetsJson] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'bottom', labels: { color: '#CDD9E5', padding: 14, font: { family: 'Segoe UI, Arial', size: 12 } } },
        tooltip: { backgroundColor: '#161B22', borderColor: '#30363D', borderWidth: 1, titleColor: '#E6EDF3', bodyColor: '#CDD9E5' }
      },
      scales: {
        x: { ticks: { color: '#6E7681' }, grid: { color: '#21262D' } },
        y: { min: 0, max: 100, ticks: { color: '#6E7681', callback: function(v){return v+'%';} }, grid: { color: '#21262D' }, title: { display: true, text: 'Pass Rate (%)', color: '#6E7681' } }
      }
    }
  });
})();
</script>
"@ } else { '<section class="panel"><h2>Pass Rate Trend</h2><div class="empty">No aggregate data in the last ' + $Days + ' days.</div></section>' }

$html = @"
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>$titleSafe</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0D1117;color:#E6EDF3;font-family:'Segoe UI',Arial,sans-serif;padding:24px;line-height:1.45}
h1{font-size:24px;margin-bottom:4px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:0.06em;color:#6E7681;margin-bottom:14px;font-weight:600}
.sub{color:#6E7681;font-size:12px;margin-bottom:24px}
.hero{display:flex;gap:14px;margin-bottom:24px;flex-wrap:wrap}
.hero .kpi{background:#161B22;border:1px solid #30363D;border-radius:8px;padding:18px 22px;min-width:160px}
.hero .kpi-v{font-size:36px;font-weight:800;line-height:1}
.hero .kpi-l{font-size:11px;color:#6E7681;margin-top:6px;text-transform:uppercase;letter-spacing:0.05em}
.panel{background:#161B22;border:1px solid #30363D;border-radius:8px;padding:20px;margin-bottom:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px;margin-bottom:24px}
.card{background:#161B22;border:1px solid #30363D;border-radius:8px;padding:16px}
.card-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.dom{font-weight:700;color:#E6EDF3;font-size:14px;word-break:break-all}
.pill{color:#0D1117;padding:3px 10px;border-radius:11px;font-size:11px;font-weight:700;letter-spacing:0.04em}
.card .kpis{display:flex;gap:10px;margin-bottom:10px}
.card .kpi{background:#0D1117;border:1px solid #21262D;border-radius:6px;padding:10px;flex:1;text-align:center}
.card .kpi-v{font-size:18px;font-weight:700}
.card .kpi-l{font-size:10px;color:#6E7681;margin-top:3px;text-transform:uppercase}
.meta{display:flex;gap:14px;font-size:11px;color:#6E7681;flex-wrap:wrap;border-top:1px solid #21262D;padding-top:10px}
.meta b{color:#CDD9E5;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:9px 12px;background:#0D1117;color:#6E7681;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid #30363D;font-weight:600}
td{padding:8px 12px;border-bottom:1px solid #21262D;color:#CDD9E5}
tr:hover td{background:#1C2128}
.mono{font-family:'Cascadia Code',Consolas,Menlo,monospace;font-size:11px}
.num{text-align:right;font-variant-numeric:tabular-nums}
.empty{padding:20px;color:#6E7681;text-align:center;font-style:italic}
.bar-wrap{background:#21262D;height:8px;border-radius:4px;width:180px}
.bar{height:100%;border-radius:4px}
.footer{margin-top:32px;padding-top:14px;border-top:1px solid #21262D;font-size:11px;color:#6E7681;text-align:center}
</style>
</head><body>
<h1>$titleSafe</h1>
<div class="sub">Generated $generated &middot; Window: last $Days days &middot; $($domains.Count) domain(s)</div>

<div class="hero">
  <div class="kpi"><div class="kpi-v" style="color:$overallColor">$passRate%</div><div class="kpi-l">Overall Pass Rate</div></div>
  <div class="kpi"><div class="kpi-v">$totalMsgs</div><div class="kpi-l">Total Messages</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#3FB950">$totalPass</div><div class="kpi-l">Passed</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#F85149">$totalFail</div><div class="kpi-l">Failed</div></div>
</div>

<h2>Per-domain summary</h2>
<div class="cards">$domainCards</div>

$chartBlock

<section class="panel">
  <h2>Top Sending Sources</h2>
  <table><thead><tr><th>Source IP</th><th>Country</th><th>Organization</th><th>Class</th><th>Domain</th><th class="num">Messages</th><th class="num">Pass Rate</th></tr></thead><tbody>$senderRowsHtml</tbody></table>
</section>

<section class="panel">
  <h2>Country Breakdown</h2>
  <table><thead><tr><th>Country</th><th class="num">Messages</th><th>Volume</th><th class="num">Pass Rate</th></tr></thead><tbody>$countryRowsHtml</tbody></table>
</section>

<section class="panel">
  <h2>Recent Records (last 100)</h2>
  <table><thead><tr><th>Date</th><th>Domain</th><th>Source IP</th><th>Reporter</th><th class="num">Msgs</th><th>Result</th><th>Fail Reason</th><th>Override</th></tr></thead><tbody>$recentRowsHtml</tbody></table>
</section>

<div class="footer">DMARC Monitor &middot; self-hosted &middot; Report generated by Invoke-HTMLReportGenerator.ps1</div>
</body></html>
"@

# Write file (UTF-8 without BOM is best for browsers; Set-Content -Encoding UTF8 in PS5.1 adds BOM,
# so write via .NET to be safe)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$dir = Split-Path $OutputPath -Parent
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
[System.IO.File]::WriteAllText($OutputPath, $html, $utf8NoBom)

Write-Host "Report written: $OutputPath"

if ($Open) {
    try { Start-Process $OutputPath } catch { Write-Host "Could not auto-open report: $_" }
}
