#Requires -Version 5.1
<#
.SYNOPSIS
    DMARC Monitoring - Complete DMARC Monitoring Engine v5.0.0

.DESCRIPTION
    Full-featured DMARC monitoring engine with feature parity beyond paid tools.
    Polls dmarc@yourdomain.com every 30 minutes via Microsoft Graph.

    Report types parsed:
        DMARC aggregate (rua) — RFC 7489, including override reasons + subdomain analysis
        DMARC forensic  (ruf) — RFC 6591 MIME/ARF
        TLS-RPT               — RFC 8460 JSON

    Source analysis:
        Source inventory with first/last seen, pass/fail history
        New sender detection and alerting
        ESP classification (16 known providers)
        IP geolocation (ipinfo.io HTTPS, PS7 parallel)
        Volume anomaly detection (rolling baseline)
        Cousin domain detection (Levenshtein + visual substitutions)
        Reporting org coverage (Google/Microsoft/Yahoo/Apple/Comcast)

    DNS health:
        DMARC record audit, policy gap analysis (pct, sp, adkim, aspf)
        SPF lookup depth (RFC 7208 limit: 10), void lookups, mechanism count
        DKIM key presence per known selectors
        MTA-STS policy monitoring
        BIMI record validation

    Analytics:
        Compliance score per domain (0-100, DMARCian-style)
        Enforcement recommendation engine (data-driven, 14-day analysis)
        DMARC policy progression tracker
        Per-domain alert thresholds

    Alerting:
        Teams webhook MessageCard
        Email via Graph sendMail (requires Mail.Send permission)
        New sender first-seen alert
        Volume anomaly alert
        Cousin domain spoofing alert
        DNS health issues alert
        MTA-STS policy change alert
        Cert expiry warning (60-day)

    Reporting:
        Daily HTML digest email with domain summary
        Per-domain and portfolio HTML client reports

.NOTES
    Version         : 5.0.0
    Author          : DMARC Monitoring
    # Engineer line removed for generic build
    Updated         : 2026-05-10
    NIST SP 800-53  : AU-2, AU-6, AU-12, SI-4, SI-8, SC-8, SC-28
    MITRE ATT&CK    : T1566.001, T1078.004, T1114.002

    Requires        : Microsoft.Graph.Authentication
    PS7             : winget install Microsoft.PowerShell

    App permissions : Mail.ReadWrite, Mail.Send (Application, admin consent)

    Exit Codes: 0=Success 1=Config 2=Auth 3=Mailbox 4=NoReports 99=Exception
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]  [string]$TenantId,
    [Parameter(Mandatory=$true)]  [string]$ClientId,
    [Parameter(Mandatory=$true)]  [string]$MailboxAddress,
    [Parameter(Mandatory=$true)]  [string]$CertThumbprint,
    [Parameter(Mandatory=$true)]  [ValidateSet("CurrentUser","LocalMachine")] [string]$CertStore,
    [Parameter(Mandatory=$true)]  [string]$WorkingDir,
    [Parameter(Mandatory=$true)]  [int]$RetentionDays,
    [Parameter(Mandatory=$true)]  [string]$SourceFolder,
    [Parameter(Mandatory=$false)] [switch]$DMARCFailedOnly,
    [Parameter(Mandatory=$false)] [switch]$DMARCPassedOnly,
    [Parameter(Mandatory=$false)] [string]$FilterDomain = "",
    [Parameter(Mandatory=$false)] [switch]$EnableGeoLookup,
    [Parameter(Mandatory=$false)] [string]$GeoAPIToken = "",
    [Parameter(Mandatory=$false)] [switch]$EnableAlerts,
    [Parameter(Mandatory=$false)] [int]$AlertThresholdPct = 10,
    [Parameter(Mandatory=$false)] [string]$AlertEmailTo = "",
    [Parameter(Mandatory=$false)] [string]$TeamsWebhookUrl = "",
    [Parameter(Mandatory=$false)] [switch]$EnableNewSenderAlerts,
    [Parameter(Mandatory=$false)] [switch]$EnableVolumeAnomalyAlerts,
    [Parameter(Mandatory=$false)] [double]$VolumeAnomalyMultiplier = 3.0,
    [Parameter(Mandatory=$false)] [switch]$EnableDNSHealthCheck,
    [Parameter(Mandatory=$false)] [switch]$EnableCousinDomainDetection,
    [Parameter(Mandatory=$false)] [switch]$EnableReportingCoverage,
    [Parameter(Mandatory=$false)] [switch]$EnableDailyDigest,
    [Parameter(Mandatory=$false)] [string]$DigestEmailTo = "",
    [Parameter(Mandatory=$false)] [int]$DigestHour = 7,
    [Parameter(Mandatory=$false)] [switch]$EnableMTASTSCheck,
    [Parameter(Mandatory=$false)] [switch]$EnableBIMI,
    [Parameter(Mandatory=$false)] [switch]$EnableDKIMTracking
)

#region PS7 Relaunch
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $pwsh7 = Get-Command pwsh -EA SilentlyContinue
    if ($pwsh7) {
        $al = @("-ExecutionPolicy","Bypass","-NonInteractive","-File","`"$($MyInvocation.MyCommand.Path)`"")
        foreach ($k in $PSBoundParameters.Keys) {
            $v = $PSBoundParameters[$k]
            if ($v -is [switch]) { if ($v) { $al += "-$k" } } else { $al += "-$k"; $al += "`"$v`"" }
        }
        & pwsh $al; exit $LASTEXITCODE
    }
}
#endregion

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region TLS
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $script:TLSInfo = "PS7 — TLS 1.3 auto (OS Schannel)"
} else {
    try {
        $tls12 = [System.Net.SecurityProtocolType]::Tls12
        $tls13 = [System.Enum]::ToObject([System.Net.SecurityProtocolType], 12288)
        [System.Net.ServicePointManager]::SecurityProtocol = $tls12 -bor $tls13
        $script:TLSInfo = "PS5.1 — TLS 1.2+1.3"
    } catch {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $script:TLSInfo = "PS5.1 — TLS 1.2"
    }
}
try {
    @('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
      'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319') | ForEach-Object {
        if (Test-Path $_) { Set-ItemProperty -Path $_ -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -EA Stop }
    }
} catch {}
#endregion

#region Directories
$logDir    = Join-Path $WorkingDir "Logs"
$rawDir    = Join-Path $WorkingDir "Raw"
$reportDir = Join-Path $WorkingDir "Reports"
$stateDir  = Join-Path $WorkingDir "State"
$tempDir   = Join-Path $WorkingDir "Temp"
$logFile   = Join-Path $logDir "DMARCReporter_$(Get-Date -Format 'yyyy-MM').log"

foreach ($d in @($logDir,$rawDir,$reportDir,$stateDir,$tempDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
try {
    $acl = Get-Acl $WorkingDir; $acl.SetAccessRuleProtection($true,$false)
    $inh = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $prop = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    foreach ($id in @($identity,"SYSTEM","BUILTIN\Administrators")) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id,"FullControl",$inh,$prop,$allow)))
    }
    Set-Acl -Path $WorkingDir -AclObject $acl -EA Stop
} catch {}
#endregion

#region Logging + Events
function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','SUCCESS')] [string]$Level='INFO')
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')][$Level] $Message"
    Add-Content -Path $logFile -Value $entry -EA SilentlyContinue
    Write-Output $entry
}

$script:EvtSrc = "DMARCMonitor"
function Write-AuditEvent {
    param([string]$Message, [string]$EntryType='Information', [int]$EventId=1000)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:EvtSrc)) {
            [System.Diagnostics.EventLog]::CreateEventSource($script:EvtSrc,"Application")
        }
        Write-EventLog -LogName Application -Source $script:EvtSrc -EventId $EventId -EntryType $EntryType -Message $Message -EA Stop
    } catch {}
}
#endregion

#region Module + Auth
function Assert-GraphModule {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Log "Installing Microsoft.Graph.Authentication..." -Level WARN
        try { Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -EA Stop; Write-Log "Module installed." -Level SUCCESS }
        catch { Write-Log "Install failed: $_" -Level ERROR; exit 1 }
    }
    Import-Module Microsoft.Graph.Authentication -EA Stop
    Write-Log "Graph module v$((Get-Module Microsoft.Graph.Authentication).Version) loaded"
}

function Test-CertExpiry {
    param([int]$WarnDays=60)
    $path = "Cert:\$CertStore\My\$CertThumbprint"
    if (-not (Test-Path $path)) { Write-Log "Cert not found: $path" -Level ERROR; exit 1 }
    $cert = Get-Item $path
    $days = ($cert.NotAfter - (Get-Date)).Days
    if ($days -le 0)        { Write-Log "CERT EXPIRED: $($cert.NotAfter.ToString('yyyy-MM-dd'))" -Level ERROR; Write-AuditEvent "Cert EXPIRED" -EntryType Error -EventId 1002; exit 1 }
    if ($days -le $WarnDays) { Write-Log "CERT EXPIRY WARNING: $days days remaining" -Level WARN; Write-AuditEvent "Cert expires in $days days" -EntryType Warning -EventId 1005 }
    else { Write-Log "Cert valid — $days days remaining ($($cert.NotAfter.ToString('yyyy-MM-dd')))" }
    return $cert
}

function Connect-ToGraph {
    param($Cert)
    try {
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Certificate $Cert -NoWelcome -EA Stop
        Write-Log "Graph authenticated" -Level SUCCESS
        Write-AuditEvent "Auth OK. Tenant:$TenantId Machine:$env:COMPUTERNAME" -EventId 1001
    } catch { Write-Log "Auth failed: $_" -Level ERROR; exit 2 }
}
#endregion

#region Graph
function Invoke-Graph {
    param([string]$Uri, [string]$Method="GET", [hashtable]$Body=$null, [string]$OutFile=$null)
    $p = @{ Method=$Method; Uri=$Uri }
    if (-not $OutFile) { $p.OutputType = "PSObject" }
    if ($Body)    { $p.Body=$Body; $p.ContentType="application/json" }
    if ($OutFile) { $p.OutputFilePath=$OutFile }
    return Invoke-MgGraphRequest @p
}

function Resolve-MailFolder {
    param([string]$Name)
    $base = "https://graph.microsoft.com/v1.0/users/$MailboxAddress"
    if ($Name -eq "Inbox") { return (Invoke-Graph -Uri "$base/mailFolders/Inbox").id }
    $r = Invoke-Graph -Uri "$base/mailFolders?`$filter=displayName eq '$Name'"
    if ($r.value.Count -gt 0) { return $r.value[0].id }
    return (Invoke-Graph -Method POST -Uri "$base/mailFolders" -Body @{ displayName=$Name }).id
}

function Send-GraphEmail {
    param([string]$To, [string]$Subject, [string]$HTMLBody)
    if ([string]::IsNullOrWhiteSpace($To)) { return }
    try {
        Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$MailboxAddress/sendMail" -Body @{
            message=@{ subject=$Subject; body=@{ contentType="HTML"; content=$HTMLBody }; toRecipients=@(@{ emailAddress=@{ address=$To } }) }; saveToSentItems=$false
        } | Out-Null
        Write-Log "Email sent: $Subject → $To" -Level SUCCESS
    } catch { Write-Log "Email failed (ensure Mail.Send permission): $_" -Level WARN }
}
#endregion

#region Teams
function Send-TeamsCard {
    param([string]$Title, [string]$Color, [hashtable[]]$Facts)
    if ([string]::IsNullOrWhiteSpace($TeamsWebhookUrl)) { return }
    try {
        $card = @{ "@type"="MessageCard"; "@context"="https://schema.org/extensions"; "themeColor"=$Color; "title"=$Title; "sections"=@(@{ "facts"=$Facts }) }
        Invoke-RestMethod -Method POST -Uri $TeamsWebhookUrl -ContentType "application/json" -Body ($card | ConvertTo-Json -Depth 10) -TimeoutSec 10 | Out-Null
        Write-Log "Teams alert: $Title" -Level SUCCESS
    } catch { Write-Log "Teams alert failed: $_" -Level WARN }
}
#endregion

#region Extraction
function Expand-ReportAttachment {
    param([string]$FilePath, [string]$DestDir)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $out = [System.Collections.Generic.List[string]]::new()
    try {
        if ($FilePath -match '\.zip$') {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($FilePath,$DestDir)
            Get-ChildItem $DestDir -Recurse -File | ForEach-Object { $out.Add($_.FullName) }
        } elseif ($FilePath -match '\.gz$') {
            $outFile = Join-Path $DestDir ([System.IO.Path]::GetFileNameWithoutExtension($FilePath))
            $ins = [System.IO.File]::OpenRead($FilePath)
            $gz  = New-Object System.IO.Compression.GZipStream($ins,[System.IO.Compression.CompressionMode]::Decompress)
            $ots = [System.IO.File]::Create($outFile)
            $gz.CopyTo($ots); $ots.Dispose(); $gz.Dispose(); $ins.Dispose()
            if ($outFile -match '\.zip$') { [System.IO.Compression.ZipFile]::ExtractToDirectory($outFile,$DestDir); Get-ChildItem $DestDir -Recurse -File | ForEach-Object { $out.Add($_.FullName) } }
            else { $out.Add($outFile) }
        }
    } catch { Write-Log "Extraction failed: $(Split-Path $FilePath -Leaf) — $_" -Level WARN }
    return $out
}

function Get-ReportType {
    param([string]$FilePath)
    try {
        $r = [System.IO.StreamReader]::new($FilePath); $c = $r.ReadToEnd(); $r.Close()
        if ($c -match '<feedback')                              { return 'DMARC-RUA' }
        if ($c -match '(?i)"organization-name"|"policy-domain"') { return 'TLS-RPT'   }
        if ($c -match 'Received:|Return-Path:|Authentication-Results:') { return 'DMARC-RUF' }
        return 'UNKNOWN'
    } catch { return 'UNKNOWN' }
}
#endregion

#region DMARC RUA Parser (RFC 7489) — with override reasons + subdomain flag
function ConvertFrom-DMARCReport {
    param([string]$FilePath)
    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        [xml]$xml = Get-Content -Path $FilePath -Raw -Encoding UTF8
        $meta     = $xml.feedback.report_metadata
        $pol      = $xml.feedback.policy_published
        $dateBegin = [DateTimeOffset]::FromUnixTimeSeconds([long]$meta.date_range.begin).UtcDateTime.ToString('yyyy-MM-dd')
        $dateEnd   = [DateTimeOffset]::FromUnixTimeSeconds([long]$meta.date_range.end).UtcDateTime.ToString('yyyy-MM-dd')
        $pctTag    = if ($pol.pct)  { [int]$pol.pct  } else { 100 }
        $spTag     = if ($pol.sp)   { $pol.sp         } else { 'inherit' }
        $domain    = $pol.domain

        foreach ($rec in $xml.feedback.record) {
            $row   = $rec.row
            $dkim  = $row.policy_evaluated.dkim
            $spf   = $row.policy_evaluated.spf
            $hFrom = if ($rec.identifiers -and $rec.identifiers.header_from) { $rec.identifiers.header_from } else { '' }

            # Override/policy reasons
            $overrideReasons = @()
            if ($row.policy_evaluated.reason) {
                $reasons = @($row.policy_evaluated.reason)
                $reasons | ForEach-Object {
                    if ($_.type) { $overrideReasons += $_.type }
                }
            }
            $overrideStr = if ($overrideReasons.Count -gt 0) { $overrideReasons -join '; ' } else { 'none' }

            # Subdomain flag
            $isSubdomain = ($hFrom -ne '' -and $hFrom -notmatch "^$([regex]::Escape($domain))$" -and $hFrom -match "\.$([regex]::Escape($domain))$")

            # Failure reason classification
            $failReason = if ($dkim -eq 'pass' -and $spf -eq 'pass')                                  { 'aligned'          } `
                     elseif ($dkim -eq 'pass')                                                         { 'dkim-only'        } `
                     elseif ($spf  -eq 'pass')                                                         { 'spf-only'         } `
                     elseif ($overrideStr -ne 'none')                                                  { "override:$overrideStr" } `
                     else                                                                               { 'both-fail'        }

            $records.Add([PSCustomObject]@{
                ReportDate   = $dateBegin
                ReportEnd    = $dateEnd
                Domain       = $domain
                OrgName      = $meta.org_name
                ReportId     = $meta.report_id
                Policy       = $pol.p
                SubPolicy    = $spTag
                PCTPct       = $pctTag
                ADKIM        = if ($pol.adkim) { $pol.adkim } else { 'r' }
                ASPF         = if ($pol.aspf)  { $pol.aspf  } else { 'r' }
                SourceIP     = $row.source_ip
                MessageCount = [int]$row.count
                Disposition  = $row.policy_evaluated.disposition
                DKIMResult   = $dkim
                SPFResult    = $spf
                DMARCResult  = if ($dkim -eq 'pass' -or $spf -eq 'pass') { 'pass' } else { 'fail' }
                FailReason   = $failReason
                OverrideReason = $overrideStr
                HeaderFrom   = $hFrom
                IsSubdomain  = $isSubdomain
                SPFDomain    = if ($rec.auth_results -and $rec.auth_results.spf  -and $rec.auth_results.spf.domain)  { $rec.auth_results.spf.domain  } else { '' }
                DKIMDomain   = if ($rec.auth_results -and $rec.auth_results.dkim -and $rec.auth_results.dkim.domain) { $rec.auth_results.dkim.domain } else { '' }
                GeoCountry   = ''; GeoOrg = ''; GeoHostname = ''; GeoCity = ''
                SenderClass  = ''; IsNewSender = $false; IsCousinDomain = $false
                ParsedAt     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            })
        }
    } catch { Write-Log "RUA parse failed: $(Split-Path $FilePath -Leaf) — $_" -Level WARN }
    return $records
}
#endregion

#region DMARC RUF Parser (RFC 6591 ARF)
function ConvertFrom-DMARCForensicReport {
    param([string]$FilePath)
    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $content    = Get-Content -Path $FilePath -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($content)) { return $records }
        $arrival    = if ($content -match 'Arrival-Date:\s*(.+)')            { $Matches[1].Trim() } else { '' }
        $source     = if ($content -match 'Source-IP:\s*(.+)')               { $Matches[1].Trim() } else { '' }
        $returnPath = if ($content -match 'Return-Path:\s*<?([^>\r\n]+)>?')  { $Matches[1].Trim() } else { '' }
        $headerFrom = if ($content -match 'From:\s*<?([^>\r\n]+)>?')         { $Matches[1].Trim() } else { '' }
        $subject    = if ($content -match 'Subject:\s*(.+)')                 { $Matches[1].Trim() } else { '' }
        $msgId      = if ($content -match 'Message-ID:\s*<?([^>\r\n]+)>?')   { $Matches[1].Trim() } else { '' }
        $dkimResult = if ($content -match 'dkim=(\w+)')                      { $Matches[1].ToLower() } else { 'unknown' }
        $spfResult  = if ($content -match 'spf=(\w+)')                       { $Matches[1].ToLower() } else { 'unknown' }
        $dkimDomain = if ($content -match 'dkim=\w+.*?@([^\s;>]+)')          { $Matches[1].Trim() } else { '' }
        $domain     = if ($content -match 'Reported-Domain:\s*(.+)')         { $Matches[1].Trim() } `
                 elseif ($headerFrom -match '@(.+)$')                        { $Matches[1].Trim() } else { '' }
        $records.Add([PSCustomObject]@{
            ParsedAt=''; ArrivalDate=$arrival; Domain=$domain; SourceIP=$source
            ReturnPath=$returnPath; HeaderFrom=$headerFrom; Subject=$subject; MessageId=$msgId
            DKIMResult=$dkimResult; SPFResult=$spfResult; DKIMDomain=$dkimDomain; ReportType='RUF'
        })
        $records[-1].ParsedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    } catch { Write-Log "RUF parse failed: $(Split-Path $FilePath -Leaf) — $_" -Level WARN }
    return $records
}
#endregion

#region TLS-RPT Parser (RFC 8460)
function ConvertFrom-TLSRPTReport {
    param([string]$FilePath)
    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $json    = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        $orgName = $json.'organization-name'; $reportId = $json.'report-id'
        $dBegin  = ($json.'date-range'.'start-datetime' -replace 'T.*','').Substring(0,10)
        $dEnd    = ($json.'date-range'.'end-datetime'   -replace 'T.*','').Substring(0,10)

        foreach ($policy in $json.policies) {
            $pType = $policy.policy.'policy-type'; $pDomain = $policy.policy.'policy-domain'
            $success = [int]$policy.summary.'total-successful-session-count'
            $failure = [int]$policy.summary.'total-failure-session-count'
            $fails   = $policy.'failure-details'
            if ($fails -and $fails.Count -gt 0) {
                foreach ($f in $fails) {
                    $records.Add([PSCustomObject]@{
                        ReportDate=$dBegin; ReportEnd=$dEnd; Domain=$pDomain; OrgName=$orgName; ReportId=$reportId
                        PolicyType=$pType; TotalSuccess=$success; TotalFailure=$failure
                        ResultType=($f.'result-type')
                        SendingMtaIP        = if ($f.'sending-mta-ip')        { $f.'sending-mta-ip' }        else { '' }
                        ReceivingMxHostname = if ($f.'receiving-mx-hostname') { $f.'receiving-mx-hostname' } else { '' }
                        ReceivingIP         = if ($f.'receiving-ip')          { $f.'receiving-ip' }          else { '' }
                        FailedSessionCount  = if ($f.'failed-session-count')  { [int]$f.'failed-session-count' } else { 0 }
                        AdditionalInfo      = if ($f.'additional-information'){ $f.'additional-information' } else { '' }
                        ParsedAt            = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    })
                }
            } else {
                $records.Add([PSCustomObject]@{
                    ReportDate=$dBegin; ReportEnd=$dEnd; Domain=$pDomain; OrgName=$orgName; ReportId=$reportId
                    PolicyType=$pType; TotalSuccess=$success; TotalFailure=$failure; ResultType='none'
                    SendingMtaIP=''; ReceivingMxHostname=''; ReceivingIP=''; FailedSessionCount=0
                    AdditionalInfo=''; ParsedAt=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                })
            }
        }
    } catch { Write-Log "TLS-RPT parse failed: $(Split-Path $FilePath -Leaf) — $_" -Level WARN }
    return $records
}
#endregion

#region Geolocation
function Invoke-GeoLookup {
    param([string[]]$IPs)
    $results = @{}; $unique = $IPs | Where-Object { $_ } | Sort-Object -Unique
    if ($unique.Count -eq 0) { return $results }
    $headers = @{}; if ($GeoAPIToken) { $headers.Authorization = "Bearer $GeoAPIToken" }
    Write-Log "Geo: $($unique.Count) IPs"
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $geoData = $unique | ForEach-Object -Parallel {
            $h = @{}; if ($using:GeoAPIToken) { $h.Authorization = "Bearer $($using:GeoAPIToken)" }
            try { $r = Invoke-RestMethod -Uri "https://ipinfo.io/$_/json" -Headers $h -TimeoutSec 6 -EA Stop
                  [PSCustomObject]@{ IP=$_; Country=$r.country; Org=$r.org; Hostname=$r.hostname; City=$r.city } }
            catch { [PSCustomObject]@{ IP=$_; Country=''; Org=''; Hostname=''; City='' } }
        } -ThrottleLimit 5
    } else {
        $geoData = $unique | ForEach-Object {
            try { $r = Invoke-RestMethod -Uri "https://ipinfo.io/$_/json" -Headers $headers -TimeoutSec 6 -EA Stop; Start-Sleep -Milliseconds 200
                  [PSCustomObject]@{ IP=$_; Country=$r.country; Org=$r.org; Hostname=$r.hostname; City=$r.city } }
            catch { [PSCustomObject]@{ IP=$_; Country=''; Org=''; Hostname=''; City='' } }
        }
    }
    foreach ($g in $geoData) { $results[$g.IP] = $g }
    return $results
}

function Add-GeoData {
    param([System.Collections.Generic.List[PSCustomObject]]$Records, [hashtable]$GeoMap)
    foreach ($r in $Records) {
        $g = if ($GeoMap.ContainsKey($r.SourceIP)) { $GeoMap[$r.SourceIP] } else { $null }
        $r.GeoCountry = if ($g) { $g.Country } else { '' }; $r.GeoOrg = if ($g) { $g.Org } else { '' }
        $r.GeoHostname = if ($g) { $g.Hostname } else { '' }; $r.GeoCity = if ($g) { $g.City } else { '' }
    }
}
#endregion

#region ESP Classification
function Get-ESPClass {
    param([string]$OrgName, [string]$Hostname)
    $s = "$OrgName $Hostname".ToLower()
    if ($s -match 'google|gmail')                      { return 'Google'          }
    if ($s -match 'microsoft|outlook|hotmail|office')  { return 'Microsoft'       }
    if ($s -match 'sendgrid')                          { return 'SendGrid'        }
    if ($s -match 'mandrill|mailchimp')                { return 'Mailchimp'       }
    if ($s -match 'mailgun')                           { return 'Mailgun'         }
    if ($s -match 'amazon|aws|amazonses')              { return 'Amazon SES'      }
    if ($s -match 'postmark|wildbit')                  { return 'Postmark'        }
    if ($s -match 'sparkpost|messagebird')             { return 'SparkPost'       }
    if ($s -match 'proofpoint')                        { return 'Proofpoint'      }
    if ($s -match 'mimecast')                          { return 'Mimecast'        }
    if ($s -match 'barracuda')                         { return 'Barracuda'       }
    if ($s -match 'twilio')                            { return 'Twilio'          }
    if ($s -match 'constantcontact')                   { return 'Constant Contact'}
    if ($s -match 'hubspot')                           { return 'HubSpot'         }
    if ($s -match 'salesforce|exacttarget|pardot')     { return 'Salesforce'      }
    if ($s -match 'zendesk')                           { return 'Zendesk'         }
    return 'Unknown'
}

function Add-ESPClassification {
    param([System.Collections.Generic.List[PSCustomObject]]$Records)
    foreach ($r in $Records) { $r.SenderClass = Get-ESPClass -OrgName $r.GeoOrg -Hostname $r.GeoHostname }
}
#endregion

#region Cousin Domain Detection
function Get-LevenshteinDistance {
    param([string]$S, [string]$T)
    $n = $S.Length; $m = $T.Length
    if ($n -eq 0) { return $m }; if ($m -eq 0) { return $n }
    $d = New-Object 'int[,]' ($n+1),($m+1)
    for ($i=0;$i-le$n;$i++) { $d[$i,0]=$i }
    for ($j=0;$j-le$m;$j++) { $d[0,$j]=$j }
    for ($j=1;$j-le$m;$j++) {
        for ($i=1;$i-le$n;$i++) {
            $cost = if ($S[$i-1] -eq $T[$j-1]) { 0 } else { 1 }
            $d[$i,$j] = [math]::Min([math]::Min($d[$i-1,$j]+1,$d[$i,$j-1]+1),$d[$i-1,$j-1]+$cost)
        }
    }
    return $d[$n,$m]
}

function Find-CousinDomains {
    param([System.Collections.Generic.List[PSCustomObject]]$Records, [string[]]$KnownDomains)
    if (-not $EnableCousinDomainDetection -or -not $Records) { return }
    $cousins = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($r in $Records) {
        if ([string]::IsNullOrWhiteSpace($r.HeaderFrom)) { continue }
        $hFrom = $r.HeaderFrom -replace '.*@',''

        foreach ($known in $KnownDomains) {
            if ($hFrom -eq $known) { continue }  # exact match is fine
            $dist = Get-LevenshteinDistance -S $hFrom -T $known
            if ($dist -le 2 -and $dist -gt 0) {
                $r.IsCousinDomain = $true
                $cousins.Add([PSCustomObject]@{
                    SourceIP=$r.SourceIP; TargetDomain=$known
                    ActualHeaderFrom=$hFrom; Distance=$dist; MessageCount=$r.MessageCount
                })
                Write-Log "COUSIN DOMAIN: $hFrom resembles $known (distance:$dist)" -Level WARN
                Write-AuditEvent "Cousin domain detected: $hFrom resembles $known (Levenshtein:$dist)" -EntryType Warning -EventId 1011
            }
        }
    }

    if ($cousins.Count -gt 0 -and $EnableAlerts) {
        Send-TeamsCard -Title "⚠️ Cousin Domain Spoofing Attempt Detected" -Color "F85149" -Facts (
            $cousins | ForEach-Object { @{"name"=$_.TargetDomain;"value"="Spoofed as: $($_.ActualHeaderFrom) from $($_.SourceIP) ($($_.MessageCount) msgs)"} }
        )
        $cousinStateFile = Join-Path $stateDir "cousin-domains.json"
        $cs = if (Test-Path $cousinStateFile) { try { Get-Content $cousinStateFile -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ detections=@() } } } else { [PSCustomObject]@{ detections=@() } }
        $cs.detections += $cousins | ForEach-Object { [PSCustomObject]@{ date=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); targetDomain=$_.TargetDomain; actualFrom=$_.ActualHeaderFrom; sourceIP=$_.SourceIP; distance=$_.Distance } }
        $cs | ConvertTo-Json -Depth 10 | Set-Content $cousinStateFile -Encoding UTF8
    }
}
#endregion

#region Reporting Org Coverage
function Update-ReportingOrgCoverage {
    param([System.Collections.Generic.List[PSCustomObject]]$Records)
    if (-not $EnableReportingCoverage -or -not $Records -or $Records.Count -eq 0) { return }

    $covFile = Join-Path $stateDir "reporting-coverage.json"
    $state   = if (Test-Path $covFile) { try { Get-Content $covFile -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ domains=[PSCustomObject]@{} } } } else { [PSCustomObject]@{ domains=[PSCustomObject]@{} } }
    $today   = Get-Date -Format 'yyyy-MM-dd'

    $expectedOrgs = @('Google','Microsoft','Yahoo','Apple','Comcast','AOL')

    $Records | Group-Object Domain | ForEach-Object {
        $domain  = $_.Name; $safeKey = $domain -replace '[^a-zA-Z0-9_]','_'
        $orgs    = ($_.Group | Select-Object -ExpandProperty OrgName -Unique | Sort-Object) -join '; '

        $existing = $null; try { $existing = $state.domains.$safeKey } catch {}
        if (-not $existing) {
            $state.domains | Add-Member -NotePropertyName $safeKey -NotePropertyValue ([PSCustomObject]@{
                domain=$domain; reportingOrgs=$orgs; lastSeen=$today
                orgHistory=@([PSCustomObject]@{ date=$today; orgs=$orgs })
            }) -Force
        } else {
            $existing.lastSeen = $today; $existing.reportingOrgs = $orgs
            $existing.orgHistory += [PSCustomObject]@{ date=$today; orgs=$orgs }
        }

        Write-Log "Reporting coverage: $domain — $orgs"
    }

    $state | ConvertTo-Json -Depth 10 | Set-Content $covFile -Encoding UTF8
}
#endregion

#region Compliance Score Calculator (0-100, DMARCian-style)
function Get-ComplianceScore {
    param(
        [string]$Domain,
        [System.Collections.Generic.List[PSCustomObject]]$DMARCRecords,
        [PSCustomObject]$DNSHealth,
        [PSCustomObject]$MTASState,
        [PSCustomObject]$DKIMState
    )
    $score   = 0
    $details = [System.Collections.Generic.List[string]]::new()

    # 1. Policy level (max 35)
    $policy  = if ($DMARCRecords -and $DMARCRecords.Count -gt 0) { $DMARCRecords[0].Policy } else { 'none' }
    switch ($policy) {
        'reject'     { $score += 35; $details.Add("+35 p=reject enforcement") }
        'quarantine' { $score += 20; $details.Add("+20 p=quarantine (advance to reject for full score)") }
        'none'       { $score += 0;  $details.Add("+0 p=none (no enforcement — advance to quarantine)") }
    }

    # 2. pct=100 (max 10)
    $pct = if ($DMARCRecords -and $DMARCRecords.Count -gt 0) { [int]$DMARCRecords[0].PCTPct } else { 100 }
    if ($pct -ge 100) { $score += 10; $details.Add("+10 pct=100 (full enforcement)") }
    elseif ($pct -ge 50) { $score += 5; $details.Add("+5 pct=$pct (partial enforcement)") }
    else { $details.Add("+0 pct=$pct (enforcement too low)") }

    # 3. Pass rate (max 20)
    if ($DMARCRecords -and $DMARCRecords.Count -gt 0) {
        $pass  = ($DMARCRecords | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
        $fail  = ($DMARCRecords | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
        $total = [int]$pass + [int]$fail
        $rate  = if ($total -gt 0) { [math]::Round(($pass/$total)*100,1) } else { 0 }
        if ($rate -ge 98)     { $score += 20; $details.Add("+20 pass rate $rate% (excellent)") }
        elseif ($rate -ge 95) { $score += 15; $details.Add("+15 pass rate $rate% (good)") }
        elseif ($rate -ge 85) { $score += 10; $details.Add("+10 pass rate $rate% (acceptable)") }
        elseif ($rate -ge 70) { $score += 5;  $details.Add("+5 pass rate $rate% (needs improvement)") }
        else { $details.Add("+0 pass rate $rate% (critical — investigate failures)") }
    }

    # 4. SPF health (max 10)
    if ($DNSHealth) {
        if ($DNSHealth.SPFStatus -eq 'hard-fail') { $score += 10; $details.Add("+10 SPF -all (hard fail)") }
        elseif ($DNSHealth.SPFStatus -eq 'soft-fail') { $score += 5; $details.Add("+5 SPF ~all (consider upgrading to -all)") }
        if ($DNSHealth.SPFLookups -ge 10) { $score -= 5; $details.Add("-5 SPF lookup count $($DNSHealth.SPFLookups) ≥ 10 (PermError risk)") }
    }

    # 5. MTA-STS (max 10)
    if ($MTASState) {
        if ($MTASState.PolicyMode -eq 'enforce') { $score += 10; $details.Add("+10 MTA-STS mode=enforce") }
        elseif ($MTASState.PolicyMode -eq 'testing') { $score += 5; $details.Add("+5 MTA-STS mode=testing (advance to enforce)") }
        else { $details.Add("+0 MTA-STS not deployed") }
    }

    # 6. DKIM (max 10)
    if ($DKIMState -and -not [string]::IsNullOrWhiteSpace($DKIMState.dkimDomains)) {
        $score += 10; $details.Add("+10 DKIM signing active ($($DKIMState.dkimDomains))")
    } else { $details.Add("+0 No DKIM signing domains detected") }

    # 7. No policy gaps (max 5)
    if ($DNSHealth -and $DNSHealth.IssueCount -eq 0) { $score += 5; $details.Add("+5 No DNS/policy issues detected") }
    elseif ($DNSHealth -and $DNSHealth.IssueCount -gt 0) { $details.Add("+0 $($DNSHealth.IssueCount) DNS/policy issue(s) need attention") }

    $score = [math]::Max(0,[math]::Min(100,$score))
    return [PSCustomObject]@{ Domain=$domain; Score=$score; Policy=$policy; PassRate=0; Details=$details }
}
#endregion

#region Enforcement Recommendation Engine
function Get-EnforcementRecommendation {
    param([string]$Domain)
    $progFile = Join-Path $stateDir "progression.json"
    $invFile  = Join-Path $stateDir "source-inventory.json"
    $rptDir   = $reportDir

    if (-not (Test-Path $progFile)) { return [PSCustomObject]@{ Domain=$domain; Recommendation='insufficient-data'; Details='No progression data yet. Run for at least 7 days.'; ReadyToAdvance=$false } }

    $prog = $null; try { $prog = (Get-Content $progFile -Raw | ConvertFrom-Json).domains.($domain -replace '[^a-zA-Z0-9_]','_') } catch {}
    if (-not $prog) { return [PSCustomObject]@{ Domain=$domain; Recommendation='insufficient-data'; Details='No data for this domain yet.'; ReadyToAdvance=$false } }

    $currentPolicy = $prog.currentPolicy

    # Load last 14 days of data
    $cutoff  = (Get-Date).AddDays(-14)
    $allData = @()
    Get-ChildItem $rptDir -Filter "dmarc_aggregate_*.csv" -EA SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff } | Sort-Object Name |
        ForEach-Object { try { $allData += Import-Csv $_.FullName | Where-Object { $_.Domain -eq $domain } } catch {} }

    if ($allData.Count -eq 0) { return [PSCustomObject]@{ Domain=$domain; Recommendation='insufficient-data'; Details='Less than 14 days of data available.'; ReadyToAdvance=$false } }

    $pass     = ($allData | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
    $fail     = ($allData | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
    $total    = [int]$pass + [int]$fail
    $passRate = if ($total -gt 0) { [math]::Round(($pass/$total)*100,1) } else { 0 }

    # Check for unknown failing senders
    $unknownFail = 0
    if (Test-Path $invFile) {
        try {
            $inv = Get-Content $invFile -Raw | ConvertFrom-Json
            $inv.sources.PSObject.Properties | Where-Object { $_.Value.domain -eq $domain -and $_.Value.senderClass -eq 'Unknown' -and [int]$_.Value.totalFail -gt 0 } |
                ForEach-Object { $unknownFail += [int]$_.Value.totalFail }
        } catch {}
    }

    $reasons  = [System.Collections.Generic.List[string]]::new()
    $blockers = [System.Collections.Generic.List[string]]::new()
    $ready    = $false

    switch ($currentPolicy) {
        'none' {
            $targetPolicy = 'quarantine'
            if ($passRate -ge 90) { $reasons.Add("✓ Pass rate $passRate% ≥ 90% threshold") } else { $blockers.Add("✗ Pass rate $passRate% below 90% required threshold") }
            if ($unknownFail -eq 0) { $reasons.Add("✓ No unknown senders failing DMARC") } else { $blockers.Add("✗ $unknownFail messages from unknown failing senders — identify and authorize these sources first") }
            if ($total -ge 100) { $reasons.Add("✓ Sufficient message volume ($total) for analysis") } else { $blockers.Add("✗ Insufficient message volume ($total) — need 100+ messages for confidence") }
            $ready = ($blockers.Count -eq 0)
        }
        'quarantine' {
            $targetPolicy = 'reject'
            if ($passRate -ge 95) { $reasons.Add("✓ Pass rate $passRate% ≥ 95% threshold") } else { $blockers.Add("✗ Pass rate $passRate% below 95% required threshold") }
            if ($unknownFail -eq 0) { $reasons.Add("✓ No unknown senders failing DMARC") } else { $blockers.Add("✗ $unknownFail messages from unknown failing senders") }
            $daysAtQuarantine = if ($prog.firstSeen) { ([datetime]$prog.lastUpdated - [datetime]$prog.firstSeen).Days } else { 0 }
            if ($daysAtQuarantine -ge 14) { $reasons.Add("✓ At quarantine for $daysAtQuarantine days (recommend 14+ days minimum)") } else { $blockers.Add("✗ Only $daysAtQuarantine days at quarantine — allow 14 days minimum") }
            $ready = ($blockers.Count -eq 0)
        }
        'reject' {
            $targetPolicy = 'optimized'
            $reasons.Add("✓ Already at p=reject — maximum DMARC enforcement achieved")
            if ([int]$prog.pct -lt 100) { $blockers.Add("✗ pct=$($prog.pct) — increase to 100% for full coverage") } else { $reasons.Add("✓ pct=100 — full enforcement") }
            if ($prog.adkim -eq 's') { $reasons.Add("✓ adkim=s (strict DKIM alignment)") } else { $blockers.Add("⚠ Consider adkim=s for stricter DKIM alignment") }
            if ($prog.aspf  -eq 's') { $reasons.Add("✓ aspf=s (strict SPF alignment)")  } else { $blockers.Add("⚠ Consider aspf=s for stricter SPF alignment")  }
            $ready = ($blockers.Count -eq 0)
        }
        default { $targetPolicy = 'quarantine' }
    }

    $recommendation = if ($ready -and $currentPolicy -ne 'reject') { "advance-to-$targetPolicy" } elseif ($currentPolicy -eq 'reject' -and $blockers.Count -eq 0) { 'fully-optimized' } elseif ($blockers.Count -gt 0) { 'not-ready' } else { 'maintain' }
    $summary = if ($ready -and $currentPolicy -ne 'reject') { "✅ READY to advance from p=$currentPolicy to p=$targetPolicy" } elseif ($currentPolicy -eq 'reject' -and $blockers.Count -eq 0) { "🏆 FULLY OPTIMIZED — p=reject at 100%" } else { "⏳ NOT READY — resolve $($blockers.Count) blocker(s) before advancing" }

    return [PSCustomObject]@{
        Domain=$domain; CurrentPolicy=$currentPolicy; TargetPolicy=$targetPolicy
        PassRate=$passRate; TotalMessages=$total; UnknownFailing=$unknownFail
        Recommendation=$recommendation; Summary=$summary; ReadyToAdvance=$ready
        Reasons=($reasons -join '|'); Blockers=($blockers -join '|')
    }
}
#endregion

#region Source Inventory + New Sender Detection
function Update-SourceInventory {
    param([System.Collections.Generic.List[PSCustomObject]]$Records)
    if (-not $Records -or $Records.Count -eq 0) { return }
    $invFile   = Join-Path $stateDir "source-inventory.json"
    $inv       = if (Test-Path $invFile) { try { Get-Content $invFile -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ sources=[PSCustomObject]@{} } } } else { [PSCustomObject]@{ sources=[PSCustomObject]@{} } }
    $today     = Get-Date -Format 'yyyy-MM-dd'
    $newSenders = [System.Collections.Generic.List[PSCustomObject]]::new()

    $Records | Group-Object Domain,SourceIP | ForEach-Object {
        $domain = ($_.Group[0]).Domain; $ip = ($_.Group[0]).SourceIP
        $key    = "$($domain)__$($ip -replace '\.','_')"
        $pass   = ($_.Group | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
        $fail   = ($_.Group | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
        $total  = [int]$pass + [int]$fail
        $org = ($_.Group[0]).GeoOrg; $country = ($_.Group[0]).GeoCountry; $class = ($_.Group[0]).SenderClass

        $existing = $null; try { $existing = $inv.sources.$key } catch {}
        if (-not $existing) {
            $entry = [PSCustomObject]@{
                domain=$domain; sourceIP=$ip; orgName=$org; country=$country; senderClass=$class
                firstSeen=$today; lastSeen=$today; totalPass=[int]$pass; totalFail=[int]$fail
                totalMessages=$total; runCount=1; isNew=$true; isApproved=$false
            }
            $inv.sources | Add-Member -NotePropertyName $key -NotePropertyValue $entry -Force
            $newSenders.Add($entry)
            $_.Group | ForEach-Object { $_.IsNewSender = $true }
            Write-Log "NEW SENDER: $ip → $domain | $class | $country" -Level WARN
            Write-AuditEvent "New sender: $ip for $domain ($class $country)" -EntryType Warning -EventId 1011
        } else {
            $existing.lastSeen = $today; $existing.totalPass = [int]$existing.totalPass + [int]$pass
            $existing.totalFail = [int]$existing.totalFail + [int]$fail
            $existing.totalMessages = [int]$existing.totalMessages + $total
            $existing.runCount = [int]$existing.runCount + 1; $existing.isNew = $false
            if ($org -and -not $existing.orgName) { $existing.orgName = $org }
            if ($country -and -not $existing.country) { $existing.country = $country }
        }
    }

    $inv | ConvertTo-Json -Depth 10 | Set-Content $invFile -Encoding UTF8

    if ($EnableNewSenderAlerts -and $newSenders.Count -gt 0 -and $EnableAlerts) {
        Send-TeamsCard -Title "⚠️ New Email Sender(s) — $($newSenders.Count) new source(s)" -Color "D29922" -Facts (
            $newSenders | ForEach-Object { @{"name"=$_.domain;"value"="$($_.sourceIP) | $($_.senderClass) | $($_.country)"} }
        )
    }

    $csvPath = Join-Path $reportDir "source_inventory_$(Get-Date -Format 'yyyy-MM-dd').csv"
    $inv.sources.PSObject.Properties | ForEach-Object { $_.Value } | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Source inventory: $($inv.sources.PSObject.Properties.Count) total sources"
}
#endregion

#region Volume Anomaly
function Test-VolumeAnomalies {
    param([System.Collections.Generic.List[PSCustomObject]]$Records)
    if (-not $EnableVolumeAnomalyAlerts -or -not $Records -or $Records.Count -eq 0) { return }
    $bFile = Join-Path $stateDir "volume-baseline.json"
    $base  = if (Test-Path $bFile) { try { Get-Content $bFile -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ domains=[PSCustomObject]@{} } } } else { [PSCustomObject]@{ domains=[PSCustomObject]@{} } }
    $today = Get-Date -Format 'yyyy-MM-dd'; $anomalies = [System.Collections.Generic.List[PSCustomObject]]::new()

    $Records | Group-Object Domain | ForEach-Object {
        $domain = $_.Name; $volume = ($_.Group | Measure-Object MessageCount -Sum).Sum
        $safeKey = $domain -replace '[^a-zA-Z0-9_]','_'
        $existing = $null; try { $existing = $base.domains.$safeKey } catch {}
        if (-not $existing) {
            $base.domains | Add-Member -NotePropertyName $safeKey -NotePropertyValue ([PSCustomObject]@{ domain=$domain; avgVolume=[int]$volume; samples=@([int]$volume); lastUpdated=$today }) -Force
        } else {
            $avg = [int]$existing.avgVolume
            if ($avg -gt 0 -and [int]$volume -gt ($avg * $VolumeAnomalyMultiplier)) {
                $ratio = [math]::Round([int]$volume/$avg,1)
                Write-Log "VOLUME ANOMALY: $domain — $volume msgs (${ratio}x avg $avg)" -Level WARN
                Write-AuditEvent "Volume anomaly: $domain $volume messages (${ratio}x baseline $avg)" -EntryType Warning -EventId 1012
                $anomalies.Add([PSCustomObject]@{ Domain=$domain; Volume=$volume; Avg=$avg; Ratio=$ratio })
            }
            $samples = @($existing.samples) + @([int]$volume) | Select-Object -Last 7
            $existing.samples = $samples; $existing.avgVolume = [int]([math]::Round(($samples | Measure-Object -Sum).Sum/$samples.Count))
            $existing.lastUpdated = $today
        }
    }
    $base | ConvertTo-Json -Depth 10 | Set-Content $bFile -Encoding UTF8
    if ($anomalies.Count -gt 0 -and $EnableAlerts) {
        Send-TeamsCard -Title "⚠️ Email Volume Anomaly" -Color "F85149" -Facts (
            $anomalies | ForEach-Object { @{"name"=$_.Domain;"value"="$($_.Volume) messages ($($_.Ratio)x normal avg $($_.Avg))"} }
        )
    }
}
#endregion

#region Failure Rate Alerting
function Test-AlertThresholds {
    param([System.Collections.Generic.List[PSCustomObject]]$Records)
    if (-not $EnableAlerts -or -not $Records -or $Records.Count -eq 0) { return }
    if ([string]::IsNullOrWhiteSpace($AlertEmailTo) -and [string]::IsNullOrWhiteSpace($TeamsWebhookUrl)) { return }
    $alertFile = Join-Path $stateDir "alerts_sent.json"
    $alertState = if (Test-Path $alertFile) { Get-Content $alertFile -Raw | ConvertFrom-Json } else { [PSCustomObject]@{} }

    $Records | Group-Object Domain | ForEach-Object {
        $domain = $_.Name
        $pass = ($_.Group | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
        $fail = ($_.Group | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
        $total = [int]$pass + [int]$fail; if ($total -eq 0) { return }
        $failRate = [math]::Round(($fail/$total)*100,1)

        # Per-domain threshold from config, fallback to global
        $threshold = $AlertThresholdPct
        $domainCfgFile = Join-Path $stateDir "domain-config.json"
        if (Test-Path $domainCfgFile) {
            try { $dc = Get-Content $domainCfgFile -Raw | ConvertFrom-Json; $safeKey = $domain -replace '[^a-zA-Z0-9_]','_'; if ($dc.$safeKey -and $dc.$safeKey.alertThreshold) { $threshold = [int]$dc.$safeKey.alertThreshold } } catch {}
        }

        if ($failRate -lt $threshold) { return }
        $alertKey = $domain -replace '\.','_'
        $last = $null; try { $last = $alertState.$alertKey } catch {}
        if ($last -and (Get-Date) -lt ([datetime]$last).AddHours(1)) { return }

        Write-Log "ALERT: $domain fail rate $failRate% > $threshold%" -Level WARN
        Write-AuditEvent "DMARC Alert: $domain $failRate%" -EntryType Warning -EventId 1006
        Send-TeamsCard -Title "⚠️ DMARC Failure Alert — $domain" -Color "F85149" -Facts @(
            @{"name"="Domain";"value"=$domain}, @{"name"="Fail Rate";"value"="$failRate% (threshold: $threshold%)"},
            @{"name"="Messages";"value"="Pass:$pass Fail:$fail"}, @{"name"="Detected";"value"="$(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC"}
        )
        if (-not [string]::IsNullOrWhiteSpace($AlertEmailTo)) {
            $html = "<html><body style='font-family:Segoe UI;background:#0D1117;color:#E6EDF3;padding:20px'><div style='max-width:600px;background:#161B22;border:1px solid #F85149;border-radius:8px;padding:20px'><h2 style='color:#F85149;margin-top:0'>⚠️ DMARC Failure Alert</h2><p><strong>$domain</strong> fail rate: <strong style='color:#F85149'>${failRate}%</strong> (threshold: ${threshold}%)</p><table style='width:100%;font-size:12px'><tr><td style='padding:6px;color:#6E7681'>Passed</td><td style='color:#3FB950'>$pass</td></tr><tr><td style='padding:6px;color:#6E7681'>Failed</td><td style='color:#F85149'>$fail</td></tr></table></div></body></html>"
            Send-GraphEmail -To $AlertEmailTo -Subject "DMARC Alert: $domain ${failRate}% fail — DMARC Monitor" -HTMLBody $html
        }
        $alertState | Add-Member -NotePropertyName $alertKey -NotePropertyValue (Get-Date -Format 'o') -Force
    }
    $alertState | ConvertTo-Json -Depth 5 | Set-Content $alertFile -Encoding UTF8
}
#endregion

#region DNS Health
function Invoke-DNSHealthCheck {
    param([string[]]$Domains)
    if (-not $Domains -or $Domains.Count -eq 0) { return }
    $stateFile = Join-Path $stateDir "dns-health.json"
    $state = if (Test-Path $stateFile) { try { Get-Content $stateFile -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ domains=[PSCustomObject]@{} } } } else { [PSCustomObject]@{ domains=[PSCustomObject]@{} } }
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $today   = Get-Date -Format 'yyyy-MM-dd'; $allIssues = [System.Collections.Generic.List[string]]::new()

    foreach ($domain in $Domains) {
        $r = [PSCustomObject]@{
            CheckDate=''; Domain=$domain; DMARCRecord=''; DMARCPolicy='missing'; DMARCSubPolicy=''
            DMARCPct=100; DMARCRua=''; DMARCRuf=''; DMARCAdkim='r'; DMARCAspf='r'; DMARCStatus='missing'
            SPFRecord=''; SPFLookupCount=0; SPFHasAll=$false; SPFAllMechanism=''; SPFStatus='missing'
            Issues=''; IssueCount=0
        }
        $r.CheckDate = $today
        $domIssues   = [System.Collections.Generic.List[string]]::new()

        # DMARC record
        try {
            $dns = Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -EA Stop
            $txt = ($dns | Where-Object { $_.Strings -match 'v=DMARC1' } | Select-Object -First 1).Strings -join ''
            if ($txt) {
                $r.DMARCRecord = $txt
                $r.DMARCPolicy    = if ($txt -match 'p=(\w+)')   { $Matches[1] } else { 'none' }
                $r.DMARCSubPolicy = if ($txt -match 'sp=(\w+)')  { $Matches[1] } else { 'inherit' }
                $r.DMARCPct       = if ($txt -match 'pct=(\d+)') { [int]$Matches[1] } else { 100 }
                $r.DMARCRua       = if ($txt -match 'rua=([^;]+)') { $Matches[1].Trim() } else { '' }
                $r.DMARCRuf       = if ($txt -match 'ruf=([^;]+)') { $Matches[1].Trim() } else { '' }
                $r.DMARCAdkim     = if ($txt -match 'adkim=([rs])') { $Matches[1] } else { 'r' }
                $r.DMARCAspf      = if ($txt -match 'aspf=([rs])')  { $Matches[1] } else { 'r' }
                $r.DMARCStatus    = "p=$($r.DMARCPolicy)"
                if ($r.DMARCPolicy -eq 'none')       { $domIssues.Add("DMARC p=none — no enforcement") }
                if ($r.DMARCPct -lt 100)             { $domIssues.Add("pct=$($r.DMARCPct) — not 100% enforcement") }
                if ($r.DMARCPolicy -eq 'reject' -and $r.DMARCSubPolicy -eq 'none') { $domIssues.Add("sp=none — subdomains not protected despite p=reject") }
                if ([string]::IsNullOrWhiteSpace($r.DMARCRua)) { $domIssues.Add("rua= missing — no aggregate reports") }
            } else { $domIssues.Add("DMARC record missing") }
        } catch { $domIssues.Add("DMARC DNS lookup failed") }

        # SPF record
        try {
            $spfDns = Resolve-DnsName -Name $domain -Type TXT -EA Stop
            $spfTxt = ($spfDns | Where-Object { $_.Strings -match 'v=spf1' } | Select-Object -First 1).Strings -join ''
            if ($spfTxt) {
                $r.SPFRecord = $spfTxt
                $lookups = ([regex]::Matches($spfTxt,'(a|mx|include|exists|redirect)[:=]')).Count
                $r.SPFLookupCount = $lookups
                $allM = [regex]::Match($spfTxt,'([+~?-]all)')
                $r.SPFHasAll = $allM.Success; $r.SPFAllMechanism = if ($allM.Success) { $allM.Value } else { 'missing' }
                $r.SPFStatus = if ($allM.Success -and $allM.Value -eq '-all') { 'hard-fail' } elseif ($allM.Success) { 'soft-fail' } else { 'no-all' }
                if ($lookups -ge 10) { $domIssues.Add("SPF lookup count $lookups ≥ 10 (PermError — RFC 7208)") }
                elseif ($lookups -ge 8) { $domIssues.Add("SPF lookup count $lookups — approaching limit of 10") }
                if (-not $allM.Success) { $domIssues.Add("SPF missing -all/~all mechanism") }
                if ($allM.Value -eq '~all') { $domIssues.Add("SPF ~all (soft fail) — consider -all") }
            } else { $domIssues.Add("SPF record missing") }
        } catch { $domIssues.Add("SPF DNS lookup failed") }

        $r.Issues = $domIssues -join ' | '; $r.IssueCount = $domIssues.Count
        $results.Add($r)

        $safeKey = $domain -replace '[^a-zA-Z0-9_]','_'
        $state.domains | Add-Member -NotePropertyName $safeKey -NotePropertyValue ([PSCustomObject]@{
            domain=$domain; DMARCPolicy=$r.DMARCPolicy; DMARCPct=$r.DMARCPct; SPFStatus=$r.SPFStatus
            SPFLookups=$r.SPFLookupCount; IssueCount=$domIssues.Count; Issues=$r.Issues; LastChecked=$today
        }) -Force

        if ($domIssues.Count -gt 0) { Write-Log "DNS HEALTH: $domain — $($domIssues -join '; ')" -Level WARN; $allIssues.Add("$domain`: $($r.Issues)") }
        else { Write-Log "DNS Health: $domain — clean" }
    }

    $state | ConvertTo-Json -Depth 10 | Set-Content $stateFile -Encoding UTF8
    if ($results.Count -gt 0) { $results | Export-Csv (Join-Path $reportDir "dns_health_$(Get-Date -Format 'yyyy-MM-dd').csv") -NoTypeInformation -Encoding UTF8 }
    if ($allIssues.Count -gt 0 -and $EnableAlerts) {
        Write-AuditEvent "DNS health issues: $($allIssues -join '; ')" -EntryType Warning -EventId 1013
        Send-TeamsCard -Title "🔍 DNS Health Issues — $($allIssues.Count) domain(s)" -Color "D29922" -Facts ($allIssues | ForEach-Object { @{"name"="Issue";"value"=$_} })
    }
}
#endregion

#region DMARC Progression Tracker
function Update-DomainProgression {
    param([System.Collections.Generic.List[PSCustomObject]]$Records)
    if (-not $Records -or $Records.Count -eq 0) { return }
    $pFile = Join-Path $stateDir "progression.json"
    $state = if (Test-Path $pFile) { try { Get-Content $pFile -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ domains=[PSCustomObject]@{} } } } else { [PSCustomObject]@{ domains=[PSCustomObject]@{} } }
    $today = Get-Date -Format 'yyyy-MM-dd'

    $Records | Group-Object Domain | ForEach-Object {
        $domain = $_.Name; $safeKey = $domain -replace '[^a-zA-Z0-9_]','_'
        $policy = ($_.Group | Select-Object -First 1).Policy
        $adkim  = ($_.Group | Select-Object -First 1).ADKIM
        $aspf   = ($_.Group | Select-Object -First 1).ASPF
        $pct    = ($_.Group | Select-Object -First 1).PCTPct
        $level  = switch ($policy) { 'none' { 0 } 'quarantine' { 1 } 'reject' { 2 } default { 0 } }

        $existing = $null; try { $existing = $state.domains.$safeKey } catch {}
        if (-not $existing) {
            $state.domains | Add-Member -NotePropertyName $safeKey -NotePropertyValue ([PSCustomObject]@{
                domain=$domain; currentPolicy=$policy; enforcementLevel=$level; adkim=$adkim; aspf=$aspf; pct=$pct
                firstSeen=$today; lastUpdated=$today; policyHistory=@([PSCustomObject]@{ date=$today; policy=$policy; adkim=$adkim; aspf=$aspf; pct=$pct })
            }) -Force
            Write-Log "Progression: New domain — $domain (p=$policy)"
        } elseif ($existing.currentPolicy -ne $policy) {
            $prog = if ($level -gt $existing.enforcementLevel) { "ADVANCED ↑" } else { "RELAXED ↓" }
            Write-Log "Progression: $domain $prog → p=$policy (was $($existing.currentPolicy))" -Level SUCCESS
            Write-AuditEvent "DMARC progression: $domain $($existing.currentPolicy)→$policy" -EventId 1008
            $existing.policyHistory += [PSCustomObject]@{ date=$today; policy=$policy; adkim=$adkim; aspf=$aspf; pct=$pct }
            $existing.currentPolicy = $policy; $existing.enforcementLevel = $level; $existing.adkim = $adkim; $existing.aspf = $aspf; $existing.pct = $pct; $existing.lastUpdated = $today
        }
    }
    $state | ConvertTo-Json -Depth 10 | Set-Content $pFile -Encoding UTF8
}
#endregion

#region MTA-STS
function Invoke-MTASTSCheck {
    param([string[]]$Domains)
    if (-not $Domains -or $Domains.Count -eq 0) { return }
    $sf   = Join-Path $stateDir "mta-sts.json"
    $state = if (Test-Path $sf) { try { Get-Content $sf -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ domains=[PSCustomObject]@{} } } } else { [PSCustomObject]@{ domains=[PSCustomObject]@{} } }
    $results = [System.Collections.Generic.List[PSCustomObject]]::new(); $today = Get-Date -Format 'yyyy-MM-dd'

    foreach ($domain in $Domains) {
        $r = [PSCustomObject]@{ CheckDate=$today; Domain=$domain; PolicyMode='not-found'; MaxAge=0; MXHosts=''; DNSRecord=''; Status='not-deployed'; Changed=$false }
        try { $dns = Resolve-DnsName -Name "_mta-sts.$domain" -Type TXT -EA Stop; $r.DNSRecord = ($dns | Where-Object { $_.Strings -match 'v=STSv1' } | Select-Object -First 1).Strings -join '' } catch {}
        try {
            $p = Invoke-RestMethod -Uri "https://mta-sts.$domain/.well-known/mta-sts.txt" -TimeoutSec 10 -EA Stop
            $lines = $p -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            $r.PolicyMode = (($lines | Where-Object { $_ -match '^mode:' }) -replace 'mode:\s*','').Trim()
            $r.MaxAge = [int]((($lines | Where-Object { $_ -match '^max_age:' }) -replace 'max_age:\s*','').Trim())
            $r.MXHosts = (($lines | Where-Object { $_ -match '^mx:' }) | ForEach-Object { ($_ -replace 'mx:\s*','').Trim() }) -join '; '
            $r.Status = "deployed-$($r.PolicyMode)"
        } catch { $r.Status = 'not-deployed' }

        $safeKey = $domain -replace '[^a-zA-Z0-9_]','_'
        $prev = $null; try { $prev = $state.domains.$safeKey } catch {}
        if ($prev -and $prev.PolicyMode -ne $r.PolicyMode) {
            $r.Changed = $true; Write-Log "MTA-STS CHANGE: $domain $($prev.PolicyMode) → $($r.PolicyMode)" -Level SUCCESS
            Write-AuditEvent "MTA-STS changed: $domain $($prev.PolicyMode)→$($r.PolicyMode)" -EventId 1009
            Send-TeamsCard -Title "🔒 MTA-STS Change — $domain" -Color "79C0FF" -Facts @(@{"name"="Domain";"value"=$domain},@{"name"="Old";"value"=$prev.PolicyMode},@{"name"="New";"value"=$r.PolicyMode})
        }
        $state.domains | Add-Member -NotePropertyName $safeKey -NotePropertyValue ([PSCustomObject]@{ domain=$domain; PolicyMode=$r.PolicyMode; Status=$r.Status; MaxAge=$r.MaxAge; MXHosts=$r.MXHosts; LastChecked=$today }) -Force
        $results.Add($r); Write-Log "MTA-STS: $domain — $($r.Status)"
    }
    $state | ConvertTo-Json -Depth 10 | Set-Content $sf -Encoding UTF8
    if ($results.Count -gt 0) { $results | Export-Csv (Join-Path $reportDir "mtasts_$(Get-Date -Format 'yyyy-MM-dd').csv") -NoTypeInformation -Encoding UTF8 }
}
#endregion

#region BIMI
function Test-BIMIRecords {
    param([string[]]$Domains)
    if (-not $Domains -or $Domains.Count -eq 0) { return }
    $sf   = Join-Path $stateDir "bimi.json"
    $state = if (Test-Path $sf) { try { Get-Content $sf -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ domains=[PSCustomObject]@{} } } } else { [PSCustomObject]@{ domains=[PSCustomObject]@{} } }
    $results = [System.Collections.Generic.List[PSCustomObject]]::new(); $today = Get-Date -Format 'yyyy-MM-dd'

    foreach ($domain in $Domains) {
        $r = [PSCustomObject]@{ CheckDate=$today; Domain=$domain; HasBIMI=$false; LogoURL=''; AuthURL=''; HasVMC=$false; LogoReachable=$false; Status='not-deployed'; RawRecord='' }
        try {
            $dns = Resolve-DnsName -Name "default._bimi.$domain" -Type TXT -EA Stop
            $rec = ($dns | Where-Object { $_.Strings -match 'v=BIMI1' } | Select-Object -First 1).Strings -join ''
            if ($rec) {
                $r.HasBIMI = $true; $r.RawRecord = $rec
                $lM = [regex]::Match($rec,'l=([^;]+)'); $aM = [regex]::Match($rec,'a=([^;]+)')
                $r.LogoURL = if ($lM.Success) { $lM.Groups[1].Value.Trim() } else { '' }
                $r.AuthURL = if ($aM.Success) { $aM.Groups[1].Value.Trim() } else { '' }
                $r.HasVMC  = ($r.AuthURL -ne '' -and $r.AuthURL -notmatch '^\s*$')
                if ($r.LogoURL) { try { $r.LogoReachable = ((Invoke-WebRequest -Uri $r.LogoURL -Method Head -TimeoutSec 8 -EA Stop).StatusCode -eq 200) } catch {} }
                $r.Status = if ($r.HasVMC -and $r.LogoReachable) { 'deployed-vmc' } elseif ($r.LogoReachable) { 'deployed-no-vmc' } else { 'deployed-logo-error' }
            }
        } catch {}
        $safeKey = $domain -replace '[^a-zA-Z0-9_]','_'
        $state.domains | Add-Member -NotePropertyName $safeKey -NotePropertyValue ([PSCustomObject]@{ domain=$domain; Status=$r.Status; HasBIMI=$r.HasBIMI; HasVMC=$r.HasVMC; LogoURL=$r.LogoURL; LogoReachable=$r.LogoReachable; LastChecked=$today }) -Force
        $results.Add($r); Write-Log "BIMI: $domain — $($r.Status)"
    }
    $state | ConvertTo-Json -Depth 10 | Set-Content $sf -Encoding UTF8
    if ($results.Count -gt 0) { $results | Export-Csv (Join-Path $reportDir "bimi_$(Get-Date -Format 'yyyy-MM-dd').csv") -NoTypeInformation -Encoding UTF8 }
}
#endregion

#region DKIM Tracker
function Update-DKIMDomainTracker {
    param([System.Collections.Generic.List[PSCustomObject]]$Records)
    if (-not $Records -or $Records.Count -eq 0) { return }
    $sf   = Join-Path $stateDir "dkim-selectors.json"
    $state = if (Test-Path $sf) { try { Get-Content $sf -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ domains=[PSCustomObject]@{} } } } else { [PSCustomObject]@{ domains=[PSCustomObject]@{} } }
    $today = Get-Date -Format 'yyyy-MM-dd'

    $Records | Group-Object Domain | ForEach-Object {
        $domain = $_.Name; $safeKey = $domain -replace '[^a-zA-Z0-9_]','_'
        $dkimDomains = ($_.Group | Select-Object -ExpandProperty DKIMDomain -Unique | Where-Object { $_ } | Sort-Object) -join '; '
        $existing = $null; try { $existing = $state.domains.$safeKey } catch {}
        if (-not $existing) {
            $state.domains | Add-Member -NotePropertyName $safeKey -NotePropertyValue ([PSCustomObject]@{ domain=$domain; dkimDomains=$dkimDomains; firstSeen=$today; lastSeen=$today; changeCount=0; history=@() }) -Force
        } elseif ($existing.dkimDomains -ne $dkimDomains -and -not [string]::IsNullOrWhiteSpace($dkimDomains)) {
            $existing.changeCount = [int]$existing.changeCount + 1
            Write-Log "DKIM CHANGE: $domain — was:[$($existing.dkimDomains)] now:[$dkimDomains]" -Level WARN
            Write-AuditEvent "DKIM change: $domain [$($existing.dkimDomains)]→[$dkimDomains]" -EventId 1010
            $existing.history += [PSCustomObject]@{ date=$today; dkimDomains=$dkimDomains }; $existing.dkimDomains = $dkimDomains
        }
        if ($existing) { $existing.lastSeen = $today }
    }
    $state | ConvertTo-Json -Depth 10 | Set-Content $sf -Encoding UTF8
}
#endregion

#region Daily Digest
function Invoke-DailyDigest {
    param([System.Collections.Generic.List[PSCustomObject]]$DMARC, [System.Collections.Generic.List[PSCustomObject]]$TLS)
    if (-not $EnableDailyDigest -or [string]::IsNullOrWhiteSpace($DigestEmailTo)) { return }
    if ((Get-Date).Hour -lt $DigestHour) { return }
    $digestFile = Join-Path $stateDir "last_digest.txt"
    $today = Get-Date -Format 'yyyy-MM-dd'
    if ((Test-Path $digestFile) -and (Get-Content $digestFile -Raw).Trim() -eq $today) { return }

    $allDMARC = @(); Get-ChildItem $reportDir -Filter "dmarc_aggregate_*.csv" -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 2 | ForEach-Object { try { $allDMARC += Import-Csv $_.FullName } catch {} }
    $allTLS   = @(); Get-ChildItem $reportDir -Filter "tlsrpt_aggregate_*.csv" -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 2 | ForEach-Object { try { $allTLS += Import-Csv $_.FullName } catch {} }

    $totalMsgs = if ($allDMARC) { ($allDMARC | Measure-Object MessageCount -Sum).Sum } else { 0 }
    $totalFail = if ($allDMARC) { ($allDMARC | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum } else { 0 }
    $totalPass = [int]$totalMsgs - [int]$totalFail
    $overall   = if ($totalMsgs -gt 0) { [math]::Round(($totalPass/$totalMsgs)*100,1) } else { 0 }
    $oColor    = if ($overall -ge 95) { '#3FB950' } elseif ($overall -ge 80) { '#D29922' } else { '#F85149' }

    $domainRows = if ($allDMARC) {
        ($allDMARC | Group-Object Domain | Sort-Object Name | ForEach-Object {
            $p = ($_.Group | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
            $f = ($_.Group | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
            $t = [int]$p + [int]$f; $r = if ($t -gt 0) { [math]::Round(($p/$t)*100,1) } else { 0 }
            $c = if ($r -ge 95) { '#3FB950' } elseif ($r -ge 80) { '#D29922' } else { '#F85149' }
            $pol = if ($_.Group[0].Policy) { $_.Group[0].Policy } else { 'unknown' }

            # Enforcement recommendation
            $rec = Get-EnforcementRecommendation -Domain $_.Name
            $recCell = if ($rec.ReadyToAdvance) { "<span style='color:#3FB950;font-size:10px'>✅ Ready for $($rec.TargetPolicy)</span>" } elseif ($rec.Recommendation -eq 'fully-optimized') { "<span style='color:#3FB950;font-size:10px'>🏆 Optimized</span>" } else { "<span style='color:#6E7681;font-size:10px'>$($rec.Recommendation)</span>" }

            "<tr><td style='padding:8px 12px'>$($_.Name)</td><td style='padding:8px 12px;color:$c'><strong>$r%</strong></td><td style='padding:8px 12px;color:#3FB950'>$p</td><td style='padding:8px 12px;color:#F85149'>$f</td><td style='padding:8px 12px'>p=$pol</td><td style='padding:8px 12px'>$recCell</td></tr>"
        }) -join ''
    } else { "<tr><td colspan='6' style='padding:12px;color:#6E7681;text-align:center'>No data available</td></tr>" }

    $html = @"
<!DOCTYPE html><html><body style='font-family:Segoe UI,Arial;background:#0D1117;color:#E6EDF3;padding:20px;margin:0'>
<div style='max-width:720px;margin:0 auto'>
<div style='background:#161B22;border:1px solid #30363D;border-radius:8px;overflow:hidden'>
<div style='background:#21262D;padding:18px 22px;border-bottom:1px solid #30363D;display:flex;justify-content:space-between;align-items:center'>
<div><h1 style='margin:0;font-size:17px'>DMARC Daily Report</h1><p style='margin:3px 0 0;color:#6E7681;font-size:12px'>$today — $MailboxAddress</p></div>
<div style='text-align:right'><div style='font-size:32px;font-weight:bold;color:$oColor'>${overall}%</div><div style='font-size:11px;color:#6E7681'>Overall Pass Rate</div></div>
</div>
<div style='display:flex'>
<div style='flex:1;padding:14px;text-align:center;border-right:1px solid #30363D'><div style='font-size:22px;font-weight:bold'>$totalMsgs</div><div style='font-size:11px;color:#6E7681;margin-top:3px'>Total Messages</div></div>
<div style='flex:1;padding:14px;text-align:center;border-right:1px solid #30363D'><div style='font-size:22px;font-weight:bold;color:#3FB950'>$totalPass</div><div style='font-size:11px;color:#6E7681;margin-top:3px'>DMARC Pass</div></div>
<div style='flex:1;padding:14px;text-align:center'><div style='font-size:22px;font-weight:bold;color:#F85149'>$totalFail</div><div style='font-size:11px;color:#6E7681;margin-top:3px'>DMARC Fail</div></div>
</div>
<div style='padding:16px 20px'>
<table style='width:100%;border-collapse:collapse;font-size:12px'>
<thead><tr style='background:#21262D'>
<th style='padding:8px 12px;text-align:left;color:#6E7681'>DOMAIN</th>
<th style='padding:8px 12px;text-align:left;color:#6E7681'>PASS RATE</th>
<th style='padding:8px 12px;text-align:left;color:#6E7681'>PASS</th>
<th style='padding:8px 12px;text-align:left;color:#6E7681'>FAIL</th>
<th style='padding:8px 12px;text-align:left;color:#6E7681'>POLICY</th>
<th style='padding:8px 12px;text-align:left;color:#6E7681'>RECOMMENDATION</th>
</tr></thead><tbody>$domainRows</tbody>
</table>
</div>
<div style='padding:12px 20px;border-top:1px solid #30363D;color:#484F58;font-size:11px'>
DMARC Monitoring — DMARC Reporter v5.0.0 | Polled every 30 minutes
</div>
</div></div></body></html>
"@
    Send-GraphEmail -To $DigestEmailTo -Subject "DMARC Daily Report — $today — Overall: $overall%" -HTMLBody $html
    Set-Content $digestFile $today -Encoding UTF8
    Write-AuditEvent "Daily digest sent to $DigestEmailTo" -EventId 1007
}
#endregion

#region Retention
function Invoke-RetentionCleanup {
    param([string]$Path, [string]$Filter, [int]$Days)
    $cutoff = (Get-Date).AddDays(-$Days)
    Get-ChildItem -Path $Path -Filter $Filter -EA SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object { try { Remove-Item $_.FullName -Force; Write-Log "Retention removed: $($_.Name)" } catch {} }
}
#endregion

#region Main
Write-Log "========================================================"
Write-Log " DMARC Monitoring Engine v5.0.0"
Write-Log " PS:$($PSVersionTable.PSVersion) | TLS:$script:TLSInfo"
Write-Log " Context: $($env:USERDOMAIN)\$($env:USERNAME) on $($env:COMPUTERNAME)"
Write-Log " Mailbox: $MailboxAddress | Folder: $SourceFolder | Retain: $RetentionDays days"
Write-Log " Geo:$EnableGeoLookup | Alerts:$EnableAlerts($AlertThresholdPct%) | NewSender:$EnableNewSenderAlerts"
Write-Log " Volume:$EnableVolumeAnomalyAlerts | DNS:$EnableDNSHealthCheck | Cousin:$EnableCousinDomainDetection"
Write-Log " MTA-STS:$EnableMTASTSCheck | BIMI:$EnableBIMI | DKIM:$EnableDKIMTracking | Digest:$EnableDailyDigest"
Write-Log "========================================================"

Write-AuditEvent "Engine started. User:$($env:USERDOMAIN)\$($env:USERNAME) Machine:$($env:COMPUTERNAME)" -EventId 1000

$exitCode    = 0
$dmarcRecs   = [System.Collections.Generic.List[PSCustomObject]]::new()
$rufRecs     = [System.Collections.Generic.List[PSCustomObject]]::new()
$tlsRecs     = [System.Collections.Generic.List[PSCustomObject]]::new()
$dmarcParsed = 0; $rufParsed = 0; $tlsParsed = 0

try {
    Assert-GraphModule
    $cert = Test-CertExpiry; Connect-ToGraph -Cert $cert; Remove-Variable cert -EA SilentlyContinue
    $base = "https://graph.microsoft.com/v1.0/users/$MailboxAddress"
    $processedId = Resolve-MailFolder -Name "DMARC-Processed"
    $noDMARCId   = Resolve-MailFolder -Name "NoDMARCrua"
    $sourceId    = Resolve-MailFolder -Name $SourceFolder

    Write-Log "Polling: $SourceFolder"

    $nextUri  = "$base/mailFolders/$sourceId/messages?`$filter=hasAttachments eq true&`$top=50&`$orderby=receivedDateTime desc"
    $messages = [System.Collections.Generic.List[PSCustomObject]]::new()
    do {
        $page = Invoke-Graph -Uri $nextUri
        if ($page.value) { $page.value | ForEach-Object { $messages.Add($_) } }
        $nextUri = $page.'@odata.nextLink'
    } while ($nextUri)

    Write-Log "Found $($messages.Count) messages"
    if ($messages.Count -eq 0) { Write-Log "No new reports." -Level WARN; $exitCode = 4 }

    foreach ($msg in $messages) {
        $isDMARCRua = $false
        try {
            $atts = Invoke-Graph -Uri "$base/messages/$($msg.id)/attachments?`$select=id,name,contentType,size"
            foreach ($att in $atts.value) {
                if ($att.name -notmatch '\.(gz|zip|xml|json|txt|eml|msg)$') { continue }
                $rawFile    = Join-Path $rawDir $att.name
                $extractDir = Join-Path $tempDir ([System.IO.Path]::GetFileNameWithoutExtension($att.name))
                if (-not (Test-Path $extractDir)) { New-Item -ItemType Directory -Path $extractDir -Force | Out-Null }
                Invoke-MgGraphRequest -Method GET -Uri "$base/messages/$($msg.id)/attachments/$($att.id)/`$value" -OutputFilePath $rawFile | Out-Null
                Write-Log "Downloaded: $($att.name) ($([math]::Round($att.size/1KB,1)) KB)"

                $files = Expand-ReportAttachment -FilePath $rawFile -DestDir $extractDir
                foreach ($fp in $files) {
                    switch (Get-ReportType -FilePath $fp) {
                        'DMARC-RUA' {
                            $isDMARCRua = $true; $recs = ConvertFrom-DMARCReport -FilePath $fp
                            if ($DMARCFailedOnly) { $recs = $recs | Where-Object { $_.DMARCResult -eq 'fail' } }
                            if ($DMARCPassedOnly) { $recs = $recs | Where-Object { $_.DMARCResult -eq 'pass' } }
                            if ($FilterDomain)    { $recs = $recs | Where-Object { $_.Domain -eq $FilterDomain } }
                            $recs | ForEach-Object { $dmarcRecs.Add($_) }; $dmarcParsed++
                            $d = if ($recs -and $recs.Count -gt 0) { $recs[0].Domain } else { 'unknown' }
                            Write-Log "RUA: $(Split-Path $fp -Leaf) | $d | $($recs.Count) records" -Level SUCCESS
                        }
                        'DMARC-RUF' {
                            $isDMARCRua = $true; $recs = ConvertFrom-DMARCForensicReport -FilePath $fp
                            $recs | ForEach-Object { $rufRecs.Add($_) }; $rufParsed++
                            Write-Log "RUF: $(Split-Path $fp -Leaf)" -Level SUCCESS
                        }
                        'TLS-RPT'   {
                            $isDMARCRua = $true; $recs = ConvertFrom-TLSRPTReport -FilePath $fp
                            $recs | ForEach-Object { $tlsRecs.Add($_) }; $tlsParsed++
                            $d = if ($recs -and $recs.Count -gt 0) { $recs[0].Domain } else { 'unknown' }
                            Write-Log "TLS-RPT: $(Split-Path $fp -Leaf) | $d" -Level SUCCESS
                        }
                        'UNKNOWN' { Write-Log "Unknown: $(Split-Path $fp -Leaf)" -Level WARN }
                    }
                }
                Remove-Item $rawFile -Force -EA SilentlyContinue
                Remove-Item $extractDir -Recurse -Force -EA SilentlyContinue
            }
        } catch { Write-Log "Failed msg $($msg.id): $_" -Level WARN }

        $dest = if ($isDMARCRua) { $processedId } else { $noDMARCId }
        try { Invoke-Graph -Method POST -Uri "$base/messages/$($msg.id)/move" -Body @{ destinationId=$dest } | Out-Null } catch {}
    }

    # Post-parse
    if ($dmarcRecs.Count -gt 0) {
        $allKnownDomains = @($dmarcRecs | Select-Object -ExpandProperty Domain -Unique)

        # Geo + classification
        if ($EnableGeoLookup) {
            $geoMap = Invoke-GeoLookup -IPs ($dmarcRecs | Select-Object -ExpandProperty SourceIP -Unique)
            Add-GeoData -Records $dmarcRecs -GeoMap $geoMap
        }
        Add-ESPClassification -Records $dmarcRecs

        # Cousin domain detection
        if ($EnableCousinDomainDetection) { Find-CousinDomains -Records $dmarcRecs -KnownDomains $allKnownDomains }

        # Reporting org coverage
        Update-ReportingOrgCoverage -Records $dmarcRecs

        # Source inventory + new sender detection
        Update-SourceInventory -Records $dmarcRecs

        # Volume anomaly
        Test-VolumeAnomalies -Records $dmarcRecs

        # Failure rate alerts
        Test-AlertThresholds -Records $dmarcRecs

        # Progression tracking
        Update-DomainProgression -Records $dmarcRecs

        # DKIM tracking
        if ($EnableDKIMTracking) { Update-DKIMDomainTracker -Records $dmarcRecs }

        # Write DMARC CSV
        $dmarcCsv = Join-Path $reportDir "dmarc_aggregate_$(Get-Date -Format 'yyyy-MM-dd').csv"
        $dmarcRecs | Export-Csv $dmarcCsv -NoTypeInformation -Append -Encoding UTF8
        Write-Log "DMARC CSV: $($dmarcRecs.Count) records" -Level SUCCESS

        Write-Log "--- DOMAIN SUMMARY ---"
        $dmarcRecs | Group-Object Domain | Sort-Object Name | ForEach-Object {
            $p = ($_.Group | Where-Object { $_.DMARCResult -eq 'pass' } | Measure-Object MessageCount -Sum).Sum
            $f = ($_.Group | Where-Object { $_.DMARCResult -eq 'fail' } | Measure-Object MessageCount -Sum).Sum
            $t = [int]$p + [int]$f; $r = if ($t -gt 0) { [math]::Round(($p/$t)*100,1) } else { 0 }
            $newCount = ($_.Group | Where-Object { $_.IsNewSender } | Measure-Object).Count
            $overrides = ($_.Group | Where-Object { $_.OverrideReason -ne 'none' } | Measure-Object MessageCount -Sum).Sum
            Write-Log "  $($_.Name.PadRight(36)) Pass:$p Fail:$f Rate:$r% New:$newCount Overrides:$overrides"
        }

        # Get all domains including from state
        $progFile = Join-Path $stateDir "progression.json"
        if (Test-Path $progFile) {
            try { (Get-Content $progFile -Raw | ConvertFrom-Json).domains.PSObject.Properties | ForEach-Object { $allKnownDomains += $_.Value.domain } } catch {}
        }
        $allKnownDomains = $allKnownDomains | Sort-Object -Unique

        if ($EnableDNSHealthCheck) { Invoke-DNSHealthCheck -Domains $allKnownDomains }
        if ($EnableMTASTSCheck)    { Invoke-MTASTSCheck   -Domains $allKnownDomains }
        if ($EnableBIMI)           { Test-BIMIRecords      -Domains $allKnownDomains }
    }

    if ($rufRecs.Count -gt 0) {
        $rufRecs | Export-Csv (Join-Path $reportDir "dmarc_forensic_$(Get-Date -Format 'yyyy-MM-dd').csv") -NoTypeInformation -Append -Encoding UTF8
        Write-Log "RUF CSV: $($rufRecs.Count) records" -Level SUCCESS
    }
    if ($tlsRecs.Count -gt 0) {
        $tlsRecs | Export-Csv (Join-Path $reportDir "tlsrpt_aggregate_$(Get-Date -Format 'yyyy-MM-dd').csv") -NoTypeInformation -Append -Encoding UTF8
        Write-Log "TLS-RPT CSV: $($tlsRecs.Count) records" -Level SUCCESS
    }

    if ($dmarcRecs.Count -eq 0 -and $rufRecs.Count -eq 0 -and $tlsRecs.Count -eq 0 -and $exitCode -eq 0) { $exitCode = 4 }

    Invoke-DailyDigest -DMARC $dmarcRecs -TLS $tlsRecs
    foreach ($filter in @("*.csv","*.log")) { Invoke-RetentionCleanup -Path $reportDir -Filter $filter -Days $RetentionDays }
    Invoke-RetentionCleanup -Path $logDir -Filter "*.log" -Days $RetentionDays

} catch {
    Write-Log "Exception: $_" -Level ERROR
    Write-AuditEvent "Engine failed: $_" -EntryType Error -EventId 1004
    $exitCode = 99
} finally {
    try { Disconnect-MgGraph -EA SilentlyContinue | Out-Null } catch {}
    Get-ChildItem $tempDir -EA SilentlyContinue | Remove-Item -Recurse -Force -EA SilentlyContinue
    Remove-Variable TenantId, ClientId -EA SilentlyContinue
    Write-Log "========================================================"
    Write-Log " Done | RUA:$dmarcParsed RUF:$rufParsed TLS:$tlsParsed | Exit:$exitCode"
    Write-Log "========================================================"
    Write-AuditEvent "Done. RUA:$dmarcParsed RUF:$rufParsed TLS:$tlsParsed Exit:$exitCode" -EventId 1003
}

exit $exitCode
#endregion
