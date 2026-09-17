#Requires -Version 5.1
<#
.SYNOPSIS
    DMARC Monitor — client registry and reporting periods.

.DESCRIPTION
    An MSP bills a CLIENT, not a domain. A client is one or more domains, a
    reporting cadence, and the people who receive the report. Everything here
    exists to turn "what did we do for Acme last month" into something
    answerable, because that question is what the invoice is for.

    Mirrors the clients table in db/schema.sql so this file migrates into the
    database later without reshaping.

    Dot-source to use. Defines functions only and performs no work on load.

.NOTES
    Reports are generated to a folder for a human to review and send. Nothing
    here emails a client: a report that goes out automatically is a report
    that goes out during an incident, in a month the data was wrong, or to a
    client who has just churned.
#>

Set-StrictMode -Version Latest

#region Client registry
function Get-ClientRegistryPath {
    param([Parameter(Mandatory)] [string]$WorkingDir)
    return (Join-Path $WorkingDir 'State\clients.json')
}

function ConvertTo-ClientId {
    <#
    .SYNOPSIS
        A stable, filesystem-safe id for a client name.

    .DESCRIPTION
        Becomes a folder name under Reports\Clients, so it must not carry a
        path separator, a drive letter, a trailing dot or a reserved Windows
        device name. "CON", "PRN", "NUL" and friends cannot be created as
        directories on Windows at all, and a name ending in a dot or space is
        silently mangled.
    #>
    param([Parameter(Mandatory)] [string]$Name)

    $id = $Name.Trim().ToLowerInvariant()
    $id = $id -replace '[^a-z0-9]+', '-'
    $id = $id.Trim('-')
    if ([string]::IsNullOrWhiteSpace($id)) { $id = 'client' }

    $reserved = @('con','prn','aux','nul','com1','com2','com3','com4','com5','com6','com7','com8','com9',
                  'lpt1','lpt2','lpt3','lpt4','lpt5','lpt6','lpt7','lpt8','lpt9')
    if ($reserved -contains $id) { $id = "$id-client" }

    if ($id.Length -gt 64) { $id = $id.Substring(0, 64).Trim('-') }
    return $id
}

function Get-ClientRegistry {
    <#
        Always returns a registry object, even when the file is absent or
        corrupt. A reporting run must not die because nobody has onboarded a
        client yet.
    #>
    param([Parameter(Mandatory)] [string]$WorkingDir)

    $empty = [PSCustomObject]@{
        providerName = 'Your Company'
        clients      = [PSCustomObject]@{}
    }
    $path = Get-ClientRegistryPath -WorkingDir $WorkingDir
    if (-not (Test-Path $path)) { return $empty }
    try { $reg = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $empty }
    if ($null -eq $reg) { return $empty }
    if (-not $reg.PSObject.Properties['clients'] -or $null -eq $reg.clients) {
        $reg | Add-Member -NotePropertyName clients -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    if (-not $reg.PSObject.Properties['providerName'] -or [string]::IsNullOrWhiteSpace($reg.providerName)) {
        $reg | Add-Member -NotePropertyName providerName -NotePropertyValue 'Your Company' -Force
    }
    return $reg
}

function Get-AllClients {
    param([Parameter(Mandatory)] [string]$WorkingDir, [switch]$IncludeInactive)
    $reg = Get-ClientRegistry -WorkingDir $WorkingDir
    $all = @($reg.clients.PSObject.Properties | ForEach-Object { $_.Value })
    if ($IncludeInactive) { return $all }
    return @($all | Where-Object { $_.isActive })
}

function Get-Client {
    param([Parameter(Mandatory)] [string]$WorkingDir, [Parameter(Mandatory)] [string]$ClientId)
    $reg = Get-ClientRegistry -WorkingDir $WorkingDir
    if ($reg.clients.PSObject.Properties[$ClientId]) { return $reg.clients.$ClientId }
    return $null
}

function Get-ClientForDomain {
    <#
        Which client owns a domain. Used to route a finding to whoever is
        billed for it.
    #>
    param([Parameter(Mandatory)] [string]$WorkingDir, [Parameter(Mandatory)] [string]$Domain)
    foreach ($c in (Get-AllClients -WorkingDir $WorkingDir -IncludeInactive)) {
        foreach ($d in @($c.domains)) {
            if ($d -and ($d -eq $Domain)) { return $c }
        }
    }
    return $null
}

function Set-Client {
    <#
    .SYNOPSIS
        Creates or updates a client.

    .PARAMETER Cadence
        'monthly' bills and reports on calendar months. 'weekly' is for a
        client in active remediation who needs to see movement.
    #>
    param(
        [Parameter(Mandatory)] [string]$WorkingDir,
        [Parameter(Mandatory)] [string]$Name,
        [string[]]$Domains = @(),
        [ValidateSet('monthly','weekly')] [string]$Cadence = 'monthly',
        [string[]]$Contacts = @(),
        [string]$Notes = '',
        [string]$ClientId,
        [bool]$IsActive = $true
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { throw 'A client needs a name.' }

    $path = Get-ClientRegistryPath -WorkingDir $WorkingDir
    $dir  = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

    $reg = Get-ClientRegistry -WorkingDir $WorkingDir
    $id  = if ($ClientId) { $ClientId } else { ConvertTo-ClientId -Name $Name }

    $existing = if ($reg.clients.PSObject.Properties[$id]) { $reg.clients.$id } else { $null }
    $onboarded = if ($existing -and $existing.PSObject.Properties['onboardedAt'] -and $existing.onboardedAt) {
        $existing.onboardedAt
    } else {
        (Get-Date -Format 'yyyy-MM-dd')
    }

    # Normalise domains: lower case, de-duplicated, blanks dropped. A domain
    # listed twice would double-count every message in that client's report.
    $doms = @($Domains | ForEach-Object { if ($_) { $_.Trim().ToLowerInvariant() } } |
        Where-Object { $_ } | Select-Object -Unique)

    $reg.clients | Add-Member -NotePropertyName $id -NotePropertyValue ([PSCustomObject]@{
        id           = $id
        name         = $Name.Trim()
        domains      = $doms
        cadence      = $Cadence
        contacts     = @($Contacts | Where-Object { $_ })
        notes        = $Notes
        onboardedAt  = $onboarded
        isActive     = $IsActive
        updatedAt    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }) -Force

    $tmp = "$path.tmp"
    $reg | ConvertTo-Json -Depth 10 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $path -Force
    return $reg.clients.$id
}

function Remove-Client {
    param([Parameter(Mandatory)] [string]$WorkingDir, [Parameter(Mandatory)] [string]$ClientId)
    $path = Get-ClientRegistryPath -WorkingDir $WorkingDir
    if (-not (Test-Path $path)) { return }
    $reg = Get-ClientRegistry -WorkingDir $WorkingDir
    if (-not $reg.clients.PSObject.Properties[$ClientId]) { return }
    $reg.clients.PSObject.Properties.Remove($ClientId)
    $tmp = "$path.tmp"
    $reg | ConvertTo-Json -Depth 10 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $path -Force
}

function Set-ProviderName {
    # Whose name appears on the report.
    param([Parameter(Mandatory)] [string]$WorkingDir, [Parameter(Mandatory)] [string]$Name)
    $path = Get-ClientRegistryPath -WorkingDir $WorkingDir
    $dir  = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $reg = Get-ClientRegistry -WorkingDir $WorkingDir
    $reg | Add-Member -NotePropertyName providerName -NotePropertyValue $Name.Trim() -Force
    $tmp = "$path.tmp"
    $reg | ConvertTo-Json -Depth 10 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $path -Force
}

function Get-UnassignedDomains {
    <#
        Domains the engine has seen that belong to no client. These are
        unbilled work: somebody's reports are arriving and nobody is being
        invoiced for reading them.
    #>
    param(
        [Parameter(Mandatory)] [string]$WorkingDir,
        [AllowEmptyCollection()] [string[]]$KnownDomains = @()
    )
    $assigned = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in (Get-AllClients -WorkingDir $WorkingDir -IncludeInactive)) {
        foreach ($d in @($c.domains)) { if ($d) { [void]$assigned.Add($d) } }
    }
    return @($KnownDomains | Where-Object { $_ -and -not $assigned.Contains($_) } | Select-Object -Unique)
}
#endregion

#region Reporting periods
function Get-ReportPeriod {
    <#
    .SYNOPSIS
        The window a report covers, and the window it is compared against.

    .DESCRIPTION
        Monthly means the CALENDAR month that has ended, compared against the
        month before it. Running on 3 March reports February against January,
        not "the last 30 days", because a client reconciles a report against
        an invoice and both have to mean the same thing.

        Weekly is a rolling seven days ending yesterday, compared against the
        seven before that. Yesterday rather than today because aggregate
        reports for a day arrive throughout the following day, so a window
        ending today is always missing data and would show a fake decline.

    .PARAMETER AsOf
        Treated as "now". Explicit so the boundaries are testable rather than
        dependent on when the suite happens to run.
    #>
    param(
        [Parameter(Mandatory)] [ValidateSet('monthly','weekly')] [string]$Cadence,
        [datetime]$AsOf = (Get-Date)
    )

    $asOfDay = $AsOf.Date

    if ($Cadence -eq 'monthly') {
        $firstOfThisMonth = [datetime]::new($asOfDay.Year, $asOfDay.Month, 1)
        $start = $firstOfThisMonth.AddMonths(-1)
        $end   = $firstOfThisMonth.AddDays(-1)
        $prevStart = $start.AddMonths(-1)
        $prevEnd   = $start.AddDays(-1)
        $label     = $start.ToString('MMMM yyyy')
        $prevLabel = $prevStart.ToString('MMMM yyyy')
    } else {
        $end   = $asOfDay.AddDays(-1)
        $start = $end.AddDays(-6)          # inclusive seven days
        $prevEnd   = $start.AddDays(-1)
        $prevStart = $prevEnd.AddDays(-6)
        $label     = "$($start.ToString('d MMM')) to $($end.ToString('d MMM yyyy'))"
        $prevLabel = "$($prevStart.ToString('d MMM')) to $($prevEnd.ToString('d MMM yyyy'))"
    }

    return [PSCustomObject]@{
        Cadence       = $Cadence
        Start         = $start
        End           = $end
        Label         = $label
        PreviousStart = $prevStart
        PreviousEnd   = $prevEnd
        PreviousLabel = $prevLabel
        Days          = [int](($end - $start).TotalDays) + 1
    }
}

function Test-DateInPeriod {
    <#
        Inclusive on both ends, compared by DATE. A report row timestamped
        late on the last day of the month belongs to that month.
    #>
    param(
        [Parameter(Mandatory)] [AllowNull()] $Date,
        [Parameter(Mandatory)] $Period,
        [switch]$Previous
    )
    if ($null -eq $Date) { return $false }

    $d = $null
    if ($Date -is [datetime]) { $d = $Date.Date }
    else {
        $parsed = [datetime]::MinValue
        # Invariant first: report dates are written as yyyy-MM-dd, and a
        # machine with a non-UK locale must not read 03/04 as 4 March.
        if ([datetime]::TryParse([string]$Date, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { $d = $parsed.Date }
        elseif ([datetime]::TryParse([string]$Date, [ref]$parsed)) { $d = $parsed.Date }
        else { return $false }
    }

    $s = if ($Previous) { $Period.PreviousStart } else { $Period.Start }
    $e = if ($Previous) { $Period.PreviousEnd }   else { $Period.End }
    return ($d -ge $s.Date -and $d -le $e.Date)
}
#endregion

#region Report analysis
function Measure-DMARCRecordSet {
    <#
    .SYNOPSIS
        Totals for one set of aggregate rows.

    .DESCRIPTION
        MessageCount is the number of messages a row represents, not one. A
        single row routinely stands for thousands, so counting rows instead of
        summing MessageCount understates a large sender and overstates a
        trivial one. Every figure a client sees comes from this function.
    #>
    param([AllowNull()] [AllowEmptyCollection()] $Records)

    $out = [PSCustomObject]@{
        Messages     = 0
        Passing      = 0
        Failing      = 0
        PassRate     = 0.0
        SourceCount  = 0
        DomainCount  = 0
    }

    $rows = @($Records | Where-Object { $_ })
    if ($rows.Count -eq 0) { return $out }

    $ips     = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $domains = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($r in $rows) {
        $n = 0
        try { $n = [int]$r.MessageCount } catch { $n = 0 }
        if ($n -lt 0) { $n = 0 }          # a negative count is corrupt input, not a credit
        $out.Messages += $n

        $res = ''
        try { $res = [string]$r.DMARCResult } catch { }
        if ($res -and $res.Trim().ToLowerInvariant() -eq 'pass') { $out.Passing += $n } else { $out.Failing += $n }

        try { if ($r.SourceIP) { [void]$ips.Add([string]$r.SourceIP) } } catch { }
        try { if ($r.Domain)   { [void]$domains.Add([string]$r.Domain) } } catch { }
    }

    $out.SourceCount = $ips.Count
    $out.DomainCount = $domains.Count
    if ($out.Messages -gt 0) {
        $out.PassRate = [math]::Round(($out.Passing / $out.Messages) * 100, 1)
    }
    return $out
}

function Get-ChangeDescription {
    <#
    .SYNOPSIS
        A period-over-period change, in words a client can read.

    .DESCRIPTION
        Returns a direction and a phrase rather than a bare delta, because
        "up" is good for pass rate and bad for failures, and the report should
        not make the reader work that out. Also refuses to quote a percentage
        change from a zero baseline, which is the classic way a report claims
        an infinite improvement.
    #>
    param(
        [double]$Current,
        [double]$Previous,
        [switch]$HigherIsBetter,
        [string]$Unit = ''
    )

    $result = [PSCustomObject]@{
        Delta       = [math]::Round($Current - $Previous, 1)
        PercentText = ''
        Direction   = 'flat'   # up | down | flat
        IsGood      = $true
        Text        = ''
    }

    if ($Current -gt $Previous)      { $result.Direction = 'up' }
    elseif ($Current -lt $Previous)  { $result.Direction = 'down' }

    if ($result.Direction -eq 'flat') {
        $result.Text = 'unchanged from the previous period'
        return $result
    }

    $result.IsGood = if ($HigherIsBetter) { $result.Direction -eq 'up' } else { $result.Direction -eq 'down' }

    if ($Previous -eq 0) {
        # No baseline to divide by. Say so rather than inventing a percentage.
        $result.PercentText = ''
        $result.Text = "up from none in the previous period"
        if ($result.Direction -eq 'down') { $result.Text = 'down to none from the previous period' }
        return $result
    }

    $pct = [math]::Round((($Current - $Previous) / [math]::Abs($Previous)) * 100, 1)
    $result.PercentText = "$([math]::Abs($pct))%"
    $word = if ($result.Direction -eq 'up') { 'up' } else { 'down' }
    $abs  = [math]::Abs($result.Delta)
    $result.Text = "$word $abs$Unit ($($result.PercentText)) on the previous period"
    return $result
}

function Get-ClientReportFindings {
    <#
    .SYNOPSIS
        The things worth telling a client, worst first.

    .DESCRIPTION
        This is the part that answers "why am I paying for this". A pass-rate
        table does not justify an invoice; "we caught X before it broke your
        mail" does. Each finding carries the work done or the work needed, so
        the report reads as a record of service rather than a dashboard dump.

        Pure: takes already-loaded state and returns findings. No file or DNS
        access, so it is testable without a working directory.
    #>
    param(
        [AllowNull()] $DnsHealth,        # map of domain -> health entry
        [AllowNull()] $Progression,      # map of domain -> progression entry
        [AllowNull()] $SourceInventory,  # map of key -> source entry
        [AllowEmptyCollection()] [string[]]$Domains = @(),
        [AllowNull()] $Period
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $add = {
        param($Severity, $Title, $Detail, $Domain)
        $findings.Add([PSCustomObject]@{
            Severity = $Severity; Title = $Title; Detail = $Detail; Domain = $Domain
        })
    }

    foreach ($d in @($Domains | Where-Object { $_ })) {
        $key = $d -replace '[^a-zA-Z0-9_]', '_'

        $h = $null
        if ($DnsHealth -and $DnsHealth.PSObject.Properties[$key]) { $h = $DnsHealth.$key }

        if ($h) {
            # Silently-inert records first: the client believes they are
            # protected and they are not.
            if ($h.PSObject.Properties['SilentCriticalCodes']) {
                foreach ($code in @($h.SilentCriticalCodes | Where-Object { $_ })) {
                    & $add 'critical' 'A published record was not taking effect' `
                        "The DNS record for $d parsed correctly but was being ignored by receivers ($code). Records in this state look healthy in any checker, so this is found by inspection rather than reported by anything." $d
                }
            }

            $lookups = 0
            if ($h.PSObject.Properties['SPFLookups']) { try { $lookups = [int]$h.SPFLookups } catch { } }
            if ($lookups -ge 10) {
                & $add 'critical' 'SPF record exceeded its lookup limit' `
                    "$d used $lookups DNS lookups against a hard limit of 10. Over that limit SPF fails permanently for every message, including legitimate ones." $d
            } elseif ($lookups -ge 8) {
                & $add 'high' 'SPF record is close to its lookup limit' `
                    "$d used $lookups of 10 permitted DNS lookups. Adding one more sending service would break SPF for all mail from this domain." $d
            }

            $policy = ''
            if ($h.PSObject.Properties['DMARCPolicy']) { $policy = [string]$h.DMARCPolicy }
            if ($policy -eq 'missing') {
                & $add 'critical' 'No DMARC policy published' `
                    "$d has no DMARC record, so nobody can be told to reject mail that impersonates it, and no visibility is being collected." $d
            } elseif ($policy -eq 'none') {
                & $add 'medium' 'Domain is monitoring only, not yet enforcing' `
                    "$d publishes p=none. Impersonation is visible but nothing is being blocked. Moving to enforcement is the point of the exercise." $d
            }
        }

        $p = $null
        if ($Progression -and $Progression.PSObject.Properties[$key]) { $p = $Progression.$key }
        if ($p -and $p.PSObject.Properties['currentPolicy'] -and $p.currentPolicy -eq 'reject') {
            & $add 'good' 'Domain is fully enforcing' `
                "$d publishes p=reject. Mail that fails authentication for this domain is refused outright by receiving servers." $d
        }
    }

    # Senders seen but never authorised. Each is either a shadow-IT service
    # the client did not tell anyone about, or someone impersonating them.
    if ($SourceInventory) {
        $unapproved = @($SourceInventory.PSObject.Properties | ForEach-Object { $_.Value } | Where-Object {
            $_ -and $_.PSObject.Properties['isApproved'] -and (-not $_.isApproved) -and
            $_.PSObject.Properties['domain'] -and ($Domains -contains $_.domain)
        })
        if ($unapproved.Count -gt 0) {
            & $add 'high' "$($unapproved.Count) sending source(s) not yet authorised" `
                "Mail was seen from $($unapproved.Count) source(s) that are not on the approved list. Each is either a service nobody recorded, or someone sending as you." ''
        }
    }

    $rank = @{ 'critical' = 0; 'high' = 1; 'medium' = 2; 'low' = 3; 'good' = 4 }
    # Plain array, not ",$array": the comma stops the pipeline unrolling it,
    # so a caller that defensively writes @(...) ends up with the whole list
    # nested inside a one-element array. Callers wrap with @() instead.
    return @($findings | Sort-Object @{ Expression = { $rank[$_.Severity] } }, Domain, Title)
}
#endregion
