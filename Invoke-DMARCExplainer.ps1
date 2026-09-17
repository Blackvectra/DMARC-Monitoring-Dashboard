#Requires -Version 5.1
<#
.SYNOPSIS
    DMARC Monitor — turns an aggregate report into plain English.

.DESCRIPTION
    Every DMARC tool renders the XML as a table. A table moves the confusion
    rather than removing it: it shows that SPF said "pass" and DMARC said
    "fail" and leaves the reader to work out how both can be true.

    That gap is the whole problem. DMARC does not ask "did SPF pass". It asks
    "did SPF pass FOR THE DOMAIN THE READER SEES". A message can authenticate
    perfectly for bounce.sendgrid.net and still fail DMARC for acme.com,
    because the recipient sees acme.com and nothing authenticated that.

    This file encodes that explanation, plus the handful of other cases that
    account for most of what confuses people:

      * authenticated but not aligned  (the case above)
      * DKIM survived, SPF did not     (ordinary forwarding, not an attack)
      * SPF aligned, DKIM absent       (works, but breaks the moment it is forwarded)
      * nothing authenticated          (unauthorised sender, or impersonation)
      * a policy override              (mailing list or forwarder; not a real failure)
      * sampling under pct             (the policy was not applied to this mail at all)

    Pure functions: a parsed record in, an explanation out. No DNS, no files,
    no live data, so every case is testable.

    Dot-source to use. Defines functions only and performs no work on load.
#>

Set-StrictMode -Version Latest

#region Helpers
function Get-RecordField {
    <#
        Reads a field that may be absent, because a report from a small
        receiver often omits optional elements the big providers always send.
    #>
    param([AllowNull()] $Record, [Parameter(Mandatory)] [string]$Name, $Default = '')
    if ($null -eq $Record) { return $Default }
    if (-not $Record.PSObject.Properties[$Name]) { return $Default }
    $v = $Record.$Name
    if ($null -eq $v) { return $Default }
    return $v
}

function Format-MessageCount {
    param([int]$Count)
    if ($Count -eq 1) { return '1 message' }
    return "$($Count.ToString('N0')) messages"
}

function Test-DomainAligned {
    <#
    .SYNOPSIS
        Whether an authenticating domain aligns with the visible From domain.

    .DESCRIPTION
        Relaxed alignment (the default) accepts a subdomain: mail.acme.com
        aligns with acme.com. Strict requires an exact match. This is the rule
        that decides whether an authentication result counts for DMARC at all.
    #>
    param(
        [AllowNull()] [string]$AuthDomain,
        [AllowNull()] [string]$FromDomain,
        [ValidateSet('r','s')] [string]$Mode = 'r'
    )
    if ([string]::IsNullOrWhiteSpace($AuthDomain) -or [string]::IsNullOrWhiteSpace($FromDomain)) { return $false }
    $a = $AuthDomain.Trim().TrimEnd('.').ToLowerInvariant()
    $f = $FromDomain.Trim().TrimEnd('.').ToLowerInvariant()
    if ($a -eq $f) { return $true }
    if ($Mode -eq 's') { return $false }
    # Relaxed: the organisational domains must match. Without a public-suffix
    # list the honest approximation is a subdomain relationship either way.
    return ($a.EndsWith(".$f") -or $f.EndsWith(".$a"))
}
#endregion

#region Per-source explanation
function Get-SourceExplanation {
    <#
    .SYNOPSIS
        Explains one row of a DMARC aggregate report.

    .DESCRIPTION
        Returns the explanation as structured fields rather than a paragraph,
        so the same analysis renders into a client report, the dashboard, or a
        console without being rewritten.

        Verdict is what a human should conclude, not what the protocol said:
        'fine', 'fragile', 'misconfigured', 'unauthorised', 'suspicious' or
        'not-applied'. A protocol failure caused by a mailing list is not the
        same thing as a protocol failure caused by someone spoofing you, and a
        report that calls both "fail" is the reason people ignore these.

    .PARAMETER ServiceName
        Optional friendly name for the sending service, resolved from the
        sender catalog by the caller. "SendGrid" explains far more than
        149.72.x.x does.
    #>
    param(
        [Parameter(Mandatory)] [AllowNull()] $Record,
        [string]$ServiceName = ''
    )

    $count     = 0
    try { $count = [int](Get-RecordField $Record 'MessageCount' 0) } catch { $count = 0 }
    if ($count -lt 0) { $count = 0 }

    $ip        = [string](Get-RecordField $Record 'SourceIP' '')
    $domain    = [string](Get-RecordField $Record 'Domain' '')
    $headerFrom= [string](Get-RecordField $Record 'HeaderFrom' '')
    $dkim      = ([string](Get-RecordField $Record 'DKIMResult' '')).Trim().ToLowerInvariant()
    $spf       = ([string](Get-RecordField $Record 'SPFResult'  '')).Trim().ToLowerInvariant()
    $disp      = ([string](Get-RecordField $Record 'Disposition' 'none')).Trim().ToLowerInvariant()
    $override  = ([string](Get-RecordField $Record 'OverrideReason' 'none')).Trim().ToLowerInvariant()
    $spfDomain = [string](Get-RecordField $Record 'SPFDomain' '')
    $dkimDomain= [string](Get-RecordField $Record 'DKIMDomain' '')
    $policy    = ([string](Get-RecordField $Record 'Policy' 'none')).Trim().ToLowerInvariant()
    $adkim     = ([string](Get-RecordField $Record 'ADKIM' 'r')).Trim().ToLowerInvariant()
    $aspf      = ([string](Get-RecordField $Record 'ASPF'  'r')).Trim().ToLowerInvariant()

    # The domain the recipient actually sees. Fall back to the policy domain
    # when the receiver omitted header_from, which some smaller ones do.
    $visible = if ($headerFrom) { $headerFrom } else { $domain }
    $who     = if ($ServiceName) { $ServiceName } else { "the server at $ip" }
    $whoFull = if ($ServiceName) { "$ServiceName ($ip)" } else { $ip }

    $out = [PSCustomObject]@{
        SourceIP      = $ip
        Service       = $ServiceName
        MessageCount  = $count
        Verdict       = 'fine'
        Headline      = ''
        WhatHappened  = ''
        WhyItMatters  = ''
        WhatToDo      = ''
        IsActionable  = $false
    }

    $msgs = Format-MessageCount $count

    # A policy override means the receiver decided NOT to apply the policy,
    # usually because it recognised a mailing list or a forwarder. The
    # authentication failure is real but it is not the sender's problem.
    if ($override -and $override -ne 'none') {
        $human = switch -Regex ($override) {
            'mailing_list'       { 'a mailing list' }
            'forwarded'          { 'a forwarding service' }
            'trusted_forwarder'  { 'a forwarder it trusts' }
            'sampled_out'        { 'sampling' }
            'local_policy'       { 'its own local policy' }
            default              { $override }
        }
        if ($override -match 'sampled_out') {
            $out.Verdict      = 'not-applied'
            $out.Headline     = "$msgs from $who were not covered by your policy"
            $out.WhatHappened = "Your DMARC record asks receivers to apply the policy to only a percentage of mail (pct=). This mail fell outside that sample, so no policy was applied to it whatever the authentication result."
            $out.WhyItMatters = 'Partial enforcement leaves a proportion of impersonation unblocked, and makes your reports harder to read because some failures were never acted on.'
            $out.WhatToDo     = 'Remove the pct= tag once you are confident, so the policy applies to all of your mail.'
            $out.IsActionable = $true
            return $out
        }
        $out.Verdict      = 'fine'
        $out.Headline     = "$msgs from $who failed authentication, but the receiver recognised $human"
        $out.WhatHappened = "Authentication failed because $human changed the message in transit, which is normal and expected. The receiver recognised this and chose not to apply your policy."
        $out.WhyItMatters = 'This is not an attack and not a misconfiguration. Counting it as a failure is what makes DMARC reports look alarming when nothing is wrong.'
        $out.WhatToDo     = 'Nothing. This will keep appearing and can be ignored.'
        return $out
    }

    $dkimAligned = ($dkim -eq 'pass')
    $spfAligned  = ($spf  -eq 'pass')

    # Did anything authenticate at all, even for the wrong domain? This is
    # what separates "your ESP is misconfigured" from "somebody is spoofing
    # you", and it is the distinction every table-based tool loses.
    $dkimAuthedElsewhere = ((-not $dkimAligned) -and $dkimDomain -and -not (Test-DomainAligned -AuthDomain $dkimDomain -FromDomain $visible -Mode $adkim))
    $spfAuthedElsewhere  = ((-not $spfAligned)  -and $spfDomain  -and -not (Test-DomainAligned -AuthDomain $spfDomain  -FromDomain $visible -Mode $aspf))

    if ($dkimAligned -and $spfAligned) {
        $out.Verdict      = 'fine'
        $out.Headline     = "$msgs from $who passed everything"
        $out.WhatHappened = "Both SPF and DKIM authenticated, and both did so for $visible, which is the domain your recipients see."
        $out.WhyItMatters = 'This is what fully authenticated mail looks like. It will be delivered normally even under a reject policy.'
        $out.WhatToDo     = 'Nothing.'
        return $out
    }

    if ($dkimAligned -and -not $spfAligned) {
        $out.Verdict      = 'fine'
        $out.Headline     = "$msgs from $who passed on DKIM; SPF did not, which is normal here"
        $out.WhatHappened = "DKIM authenticated for $visible, so DMARC passed. SPF did not, which is what happens when mail is forwarded: forwarding changes the sending server but leaves the DKIM signature intact."
        $out.WhyItMatters = 'DMARC needs only one of the two to pass and align. DKIM surviving forwarding is exactly why it is the more reliable of the two.'
        $out.WhatToDo     = 'Nothing. This is DKIM doing its job.'
        return $out
    }

    if ($spfAligned -and -not $dkimAligned) {
        $out.Verdict      = 'fragile'
        $out.Headline     = "$msgs from $who passed on SPF alone, with no working DKIM"
        $out.WhatHappened = "SPF authenticated for $visible so DMARC passed. DKIM did not sign this mail, or signed it for a domain that does not match $visible."
        $out.WhyItMatters = 'SPF alone is brittle. The moment one of these messages is forwarded, SPF breaks and there is no DKIM signature to fall back on, so it will fail DMARC and be rejected once you enforce.'
        $out.WhatToDo     = "Enable DKIM signing on $who so this mail survives forwarding."
        $out.IsActionable = $true
        return $out
    }

    # Nothing aligned. Now the important distinction.
    if ($dkimAuthedElsewhere -or $spfAuthedElsewhere) {
        $authed = @()
        if ($spfAuthedElsewhere)  { $authed += "SPF authenticated for $spfDomain" }
        if ($dkimAuthedElsewhere) { $authed += "DKIM signed as $dkimDomain" }

        $out.Verdict      = 'misconfigured'
        $out.Headline     = "$msgs from $whoFull authenticated, but for the wrong domain"
        $out.WhatHappened = "$($authed -join ', '), but your recipients see $visible. DMARC only counts authentication that matches the visible From address, so this is recorded as a failure even though the checks themselves succeeded."
        $out.WhyItMatters = "This is almost always a real service of yours that was set up with the provider's own domain rather than yours. Under a quarantine or reject policy this mail starts going to junk or being refused, and it is usually mail you care about, such as invoices or password resets."
        # ${visible} because a bare $visible: reads as a scope qualifier.
        $out.WhatToDo     = "Configure $who to sign as ${visible}: add its DKIM records to your DNS and set the return path to your own domain. There is nothing to fix at the receiving end."
        $out.IsActionable = $true
        return $out
    }

    if ($ServiceName) {
        $out.Verdict      = 'unauthorised'
        $out.Headline     = "$msgs from $whoFull failed authentication entirely"
        $out.WhatHappened = "Nothing authenticated for $visible. The source is recognisable as $ServiceName, so this is most likely a service someone in the business is using that was never added to your DNS."
        $out.WhyItMatters = "Once you enforce, this mail stops being delivered. If it is a real service, someone will notice only when their mail disappears."
        $out.WhatToDo     = "Confirm whether $ServiceName is yours. If it is, authorise it before enforcing. If not, this is somebody sending as you."
        $out.IsActionable = $true
        return $out
    }

    $out.Verdict      = 'suspicious'
    $out.Headline     = "$msgs from $ip failed authentication entirely, from an unrecognised source"
    $out.WhatHappened = "Nothing authenticated for $visible, and the sending server does not match any known mail provider."
    $out.WhyItMatters = if ($policy -eq 'none') {
        'This is what impersonation looks like in a report. Your policy is currently p=none, so none of it was blocked.'
    } else {
        "Your policy is p=$policy, so receivers were asked to act on this."
    }
    $out.WhatToDo     = 'Check whether this is a service of yours sending from unfamiliar infrastructure. If it is not, this is exactly the traffic DMARC enforcement exists to stop.'
    $out.IsActionable = $true
    return $out
}
#endregion

#region Disposition
function Get-DispositionExplanation {
    <#
        What the receiver actually DID, as opposed to what it concluded. The
        difference between "failed" and "was blocked" is the difference
        between a warning and an outage, and reports state it in a single
        word that people misread.
    #>
    param(
        [string]$Disposition = 'none',
        [string]$Policy = 'none',
        [int]$MessageCount = 0
    )
    $d = $Disposition.Trim().ToLowerInvariant()
    $msgs = Format-MessageCount $MessageCount

    switch ($d) {
        'reject' {
            return "$msgs were refused outright and never reached the recipient, because your policy is p=reject."
        }
        'quarantine' {
            return "$msgs were delivered to junk rather than the inbox, because your policy is p=quarantine."
        }
        default {
            if ($Policy -eq 'none') {
                return "$msgs were delivered normally. Your policy is p=none, so receivers were asked to report but not to act."
            }
            return "$msgs were delivered normally despite the policy, usually because the receiver recognised a forwarder or applied its own judgement."
        }
    }
}
#endregion

#region Report-level narrative
function Get-ReportExplanation {
    <#
    .SYNOPSIS
        Explains a whole aggregate report: who sent it, what it covers, and
        what it says.

    .DESCRIPTION
        One DMARC report is one receiver's view of one domain over one window.
        Saying so explicitly heads off the most common misreading, which is
        treating a single report as the full picture of a domain's mail.

    .PARAMETER Records
        Parsed records from one report, as produced by ConvertFrom-DMARCReport.

    .PARAMETER ServiceResolver
        Optional scriptblock taking a source IP and returning a friendly
        service name. Supplied by the caller so this file needs no catalog.
    #>
    param(
        [AllowNull()] [AllowEmptyCollection()] $Records,
        [scriptblock]$ServiceResolver
    )

    $rows = @($Records | Where-Object { $_ })

    $out = [PSCustomObject]@{
        Domain        = ''
        Reporter      = ''
        PeriodStart   = ''
        PeriodEnd     = ''
        Policy        = ''
        TotalMessages = 0
        PassingCount  = 0
        FailingCount  = 0
        Summary       = ''
        Sources       = @()
        ActionCount   = 0
    }
    if ($rows.Count -eq 0) {
        $out.Summary = 'This report contains no records, which means the receiver saw no mail claiming to be from your domain during the period.'
        return $out
    }

    $first = $rows[0]
    $out.Domain      = [string](Get-RecordField $first 'Domain' '')
    $out.Reporter    = [string](Get-RecordField $first 'OrgName' '')
    $out.PeriodStart = [string](Get-RecordField $first 'ReportDate' '')
    $out.PeriodEnd   = [string](Get-RecordField $first 'ReportEnd' '')
    $out.Policy      = ([string](Get-RecordField $first 'Policy' 'none')).ToLowerInvariant()

    # Group by source so one line per sending server, not one per XML row.
    $explanations = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($r in $rows) {
        $n = 0
        try { $n = [int](Get-RecordField $r 'MessageCount' 0) } catch { $n = 0 }
        if ($n -lt 0) { $n = 0 }
        $out.TotalMessages += $n
        if (([string](Get-RecordField $r 'DMARCResult' '')).Trim().ToLowerInvariant() -eq 'pass') {
            $out.PassingCount += $n
        } else {
            $out.FailingCount += $n
        }

        $svc = ''
        if ($ServiceResolver) {
            try { $svc = [string](& $ServiceResolver ([string](Get-RecordField $r 'SourceIP' ''))) } catch { $svc = '' }
        }
        $explanations.Add((Get-SourceExplanation -Record $r -ServiceName $svc))
    }

    $rank = @{ 'suspicious' = 0; 'unauthorised' = 1; 'misconfigured' = 2; 'not-applied' = 3; 'fragile' = 4; 'fine' = 5 }
    $out.Sources = @($explanations | Sort-Object @{ Expression = { $rank[$_.Verdict] } }, @{ Expression = { -$_.MessageCount } })
    $out.ActionCount = @($explanations | Where-Object { $_.IsActionable }).Count

    $reporter = if ($out.Reporter) { $out.Reporter } else { 'A receiving mail provider' }
    $window   = if ($out.PeriodStart -and $out.PeriodEnd -and ($out.PeriodStart -ne $out.PeriodEnd)) {
        "between $($out.PeriodStart) and $($out.PeriodEnd)"
    } elseif ($out.PeriodStart) { "on $($out.PeriodStart)" } else { 'during the reporting period' }

    $rate = if ($out.TotalMessages -gt 0) { [math]::Round(($out.PassingCount / $out.TotalMessages) * 100, 1) } else { 0 }
    $pass = "$($out.PassingCount.ToString('N0')) of $($out.TotalMessages.ToString('N0')) ($rate%) authenticated correctly"

    $tail = if ($out.ActionCount -eq 0) {
        'Nothing in this report needs action.'
    } elseif ($out.ActionCount -eq 1) {
        'One sending source needs attention, explained below.'
    } else {
        "$($out.ActionCount) sending sources need attention, explained below, worst first."
    }

    $out.Summary = "$reporter saw $(Format-MessageCount $out.TotalMessages) claiming to come from $($out.Domain) $window. $pass. This is one receiver's view of your mail, not all of it. $tail"
    return $out
}
#endregion
