#Requires -Version 5.1
<#
.SYNOPSIS
    DMARC Monitor — DNS remediation engine

.DESCRIPTION
    Closes the loop between "here is the DNS record you need" and "it is
    published". Competitors surface the finding and leave the operator to go
    edit DNS by hand; this plans the exact change, shows the before/after,
    publishes it through the provider's API, verifies propagation, and can
    roll it back.

    Dot-source this file to use the functions. It defines functions only and
    performs no work on load. Coverage lives in tests/DnsRemediation.Tests.ps1.

    SAFETY POSTURE — this writes DNS for a client's production mail, so a bad
    change stops their email:
      * Nothing is ever applied without an explicit -Confirm from the caller.
      * Every plan is validated before it can be applied. An SPF change that
        would exceed the RFC 7208 10-lookup cap is refused, not warned about,
        because exceeding it is a PermError that fails the whole record.
      * The current record is snapshotted before any write, and the snapshot
        is what Undo-DNSChangePlan restores.
      * Providers are pluggable and the Manual provider is always available,
        so an unsupported registrar degrades to copy-paste rather than to
        "unsupported".

.NOTES
    Engineer : DMARC Monitoring Dashboard
#>

# Dot-source this file to use the planners; it defines functions only.
Set-StrictMode -Version Latest

# Secret storage for provider credentials. Loaded here rather than by each
# caller so that a credential is resolved exactly one way everywhere. Absent,
# the planners still work and only the automatic-publish path is unavailable,
# which is the correct degradation: planning needs no credential.
$script:SecretStoreDir  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:SecretStorePath = Join-Path $script:SecretStoreDir 'Invoke-SecretStore.ps1'
if (Test-Path $script:SecretStorePath) { . $script:SecretStorePath }

#region SPF record model
# RFC 7208 limits that make or break a record. Exceeding the lookup cap is a
# PermError: evaluation stops and every message fails SPF, so the planner
# treats it as a hard refusal rather than advice.
$script:SPFMaxLookups      = 10
$script:SPFMaxStringLength = 255   # a single DNS character-string
$script:SPFMaxTotalLength  = 512   # practical ceiling for a TXT RDATA set

function ConvertFrom-SPFRecord {
    <#
    .SYNOPSIS
        Parses an SPF record into its ordered terms.

    .DESCRIPTION
        Returns a structured view rather than a string so the planner can
        insert, remove and reorder terms without regex surgery on the
        original text. Order is preserved because SPF evaluates left to
        right and the position of 'all' is what terminates evaluation.
    #>
    param([string]$Record)

    $result = [PSCustomObject]@{
        IsValid     = $false
        Version     = ''
        Terms       = [System.Collections.Generic.List[PSCustomObject]]::new()
        AllTerm     = $null
        Error       = ''
        Raw         = $Record
    }

    if ([string]::IsNullOrWhiteSpace($Record)) {
        $result.Error = 'Record is empty'
        return $result
    }

    $trimmed = $Record.Trim()
    if ($trimmed -notmatch '(?i)^v=spf1(\s|$)') {
        $result.Error = "Record does not start with v=spf1"
        return $result
    }
    $result.Version = 'spf1'

    $tokens = $trimmed -split '\s+' | Where-Object { $_ -and $_ -notmatch '(?i)^v=spf1$' }
    foreach ($tok in $tokens) {
        $qualifier = '+'
        $body      = $tok
        if ($tok -match '^([+~?-])(.+)$') {
            $qualifier = $Matches[1]
            $body      = $Matches[2]
        }

        $kind  = 'unknown'
        $value = ''
        switch -Regex ($body) {
            '(?i)^include:(.+)$'  { $kind = 'include';  $value = $Matches[1]; break }
            '(?i)^redirect=(.+)$' { $kind = 'redirect'; $value = $Matches[1]; break }
            '(?i)^exists:(.+)$'   { $kind = 'exists';   $value = $Matches[1]; break }
            '(?i)^exp=(.+)$'      { $kind = 'exp';      $value = $Matches[1]; break }
            '(?i)^ip4:(.+)$'      { $kind = 'ip4';      $value = $Matches[1]; break }
            '(?i)^ip6:(.+)$'      { $kind = 'ip6';      $value = $Matches[1]; break }
            '(?i)^all$'           { $kind = 'all';      $value = '';          break }
            '(?i)^a([:/].*)?$'    { $kind = 'a';        $value = ($body -replace '(?i)^a:?', ''); break }
            '(?i)^mx([:/].*)?$'   { $kind = 'mx';       $value = ($body -replace '(?i)^mx:?', ''); break }
            '(?i)^ptr(:.*)?$'     { $kind = 'ptr';      $value = ($body -replace '(?i)^ptr:?', ''); break }
            default               { $kind = 'unknown';  $value = $body }
        }

        $term = [PSCustomObject]@{
            Kind           = $kind
            Qualifier      = $qualifier
            Value          = $value
            Text           = $tok
            CostsLookup    = ($kind -in @('include','redirect','exists','a','mx','ptr'))
        }
        $result.Terms.Add($term)
        if ($kind -eq 'all') { $result.AllTerm = $term }
    }

    $result.IsValid = $true
    return $result
}

function ConvertTo-SPFRecord {
    <#  Renders a parsed record back to a string, keeping 'all' last.  #>
    param([PSCustomObject]$Parsed)

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add('v=spf1')

    # 'all' must be the final term: SPF stops at the first match, so anything
    # after it is unreachable. redirect= is likewise only consulted when no
    # mechanism matched, so it also belongs at the end.
    $ordered = @($Parsed.Terms | Where-Object { $_.Kind -notin @('all','redirect','exp') }) +
               @($Parsed.Terms | Where-Object { $_.Kind -eq 'redirect' }) +
               @($Parsed.Terms | Where-Object { $_.Kind -eq 'exp' }) +
               @($Parsed.Terms | Where-Object { $_.Kind -eq 'all' })

    foreach ($t in $ordered) { if ($t) { $parts.Add($t.Text) } }
    return ($parts -join ' ')
}

function Get-SPFRecordLookupCount {
    <#  Lookup cost of a parsed record. Mirrors Get-SPFLookupCount in the
        engine, but operates on the parsed model so the planner can cost a
        record it has not rendered yet.  #>
    param([PSCustomObject]$Parsed)
    return @($Parsed.Terms | Where-Object { $_.CostsLookup }).Count
}
#endregion

#region SPF change planning
function New-SPFIncludePlan {
    <#
    .SYNOPSIS
        Plans the addition of an include: mechanism to an existing SPF record.

    .DESCRIPTION
        This is the operation behind "authorize this sender". The interesting
        part is not building the string, it is refusing to build one that
        breaks the client's mail:

          * Already present      -> no-op, reported as such rather than
                                    duplicating the include.
          * Would exceed 10      -> REFUSED. Adding an 11th lookup turns the
            lookups                 whole record into a PermError, so every
                                    message starts failing SPF. Callers are
                                    pointed at flattening instead.
          * Record too long      -> refused, with the rendered length.
          * No 'all' term        -> allowed, but flagged: a record without a
                                    terminal all is an implicit neutral and
                                    weakens enforcement.

    .PARAMETER CurrentRecord
        The SPF TXT record as published today. Empty means none exists, and
        the plan will create one.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [AllowEmptyString()] [string]$CurrentRecord,
        # AllowEmptyString so an empty value returns a structured refusal plan
        # like every other rejection here, rather than a binding exception the
        # caller has to catch separately.
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$IncludeDomain,
        [ValidateSet('-all','~all','?all')] [string]$DefaultAll = '~all'
    )

    $plan = [PSCustomObject]@{
        Domain          = $Domain
        RecordType      = 'TXT'
        Name            = $Domain
        Action          = 'none'
        CurrentValue    = $CurrentRecord
        NewValue        = ''
        LookupsBefore   = 0
        LookupsAfter    = 0
        IsSafe          = $false
        IsNoOp          = $false
        Blockers        = [System.Collections.Generic.List[string]]::new()
        Warnings        = [System.Collections.Generic.List[string]]::new()
        Summary         = ''
    }

    if ([string]::IsNullOrWhiteSpace($IncludeDomain)) {
        $plan.Blockers.Add('No include domain supplied')
        $plan.Summary = 'Nothing to do: no include domain supplied'
        return $plan
    }

    # No record yet: create a minimal correct one.
    if ([string]::IsNullOrWhiteSpace($CurrentRecord)) {
        $plan.Action       = 'create'
        $plan.NewValue     = "v=spf1 include:$IncludeDomain $DefaultAll"
        $plan.LookupsAfter = 1
        $plan.IsSafe       = $true
        $plan.Summary      = "Create SPF for $Domain authorizing $IncludeDomain"
        $plan.Warnings.Add("No SPF record existed; creating one with $DefaultAll")
        return $plan
    }

    $parsed = ConvertFrom-SPFRecord -Record $CurrentRecord
    if (-not $parsed.IsValid) {
        $plan.Blockers.Add("Current record could not be parsed: $($parsed.Error)")
        $plan.Summary = "Refusing to modify an unparseable SPF record"
        return $plan
    }

    $plan.LookupsBefore = Get-SPFRecordLookupCount -Parsed $parsed

    $already = $parsed.Terms | Where-Object {
        $_.Kind -eq 'include' -and $_.Value -ieq $IncludeDomain
    }
    if ($already) {
        $plan.Action       = 'none'
        $plan.IsNoOp       = $true
        $plan.IsSafe       = $true
        $plan.NewValue     = $CurrentRecord
        $plan.LookupsAfter = $plan.LookupsBefore
        $plan.Summary      = "include:$IncludeDomain is already present - no change needed"
        return $plan
    }

    # Build the candidate.
    $newTerm = [PSCustomObject]@{
        Kind = 'include'; Qualifier = '+'; Value = $IncludeDomain
        Text = "include:$IncludeDomain"; CostsLookup = $true
    }
    $candidate = ConvertFrom-SPFRecord -Record $CurrentRecord
    $candidate.Terms.Add($newTerm)

    $plan.NewValue     = ConvertTo-SPFRecord -Parsed $candidate
    $plan.LookupsAfter = Get-SPFRecordLookupCount -Parsed $candidate
    $plan.Action       = 'update'

    if ($plan.LookupsAfter -gt $script:SPFMaxLookups) {
        $plan.Blockers.Add(
            "Adding include:$IncludeDomain takes the record to $($plan.LookupsAfter) DNS lookups, " +
            "over the RFC 7208 limit of $script:SPFMaxLookups. Publishing it would cause a PermError " +
            "and every message would start failing SPF. Flatten the record first.")
    }

    if ($plan.NewValue.Length -gt $script:SPFMaxTotalLength) {
        $plan.Blockers.Add("Resulting record is $($plan.NewValue.Length) characters, over the $script:SPFMaxTotalLength practical limit")
    }

    if ($plan.LookupsAfter -eq $script:SPFMaxLookups) {
        $plan.Warnings.Add("This uses the last available DNS lookup ($script:SPFMaxLookups of $script:SPFMaxLookups). The next sender cannot be added without flattening.")
    } elseif ($plan.LookupsAfter -ge 8) {
        $plan.Warnings.Add("Record will be at $($plan.LookupsAfter) of $script:SPFMaxLookups lookups - approaching the limit")
    }

    if (-not $parsed.AllTerm) {
        $plan.Warnings.Add("Record has no terminal 'all' mechanism, which leaves the result neutral for unlisted senders")
    }

    $plan.IsSafe  = ($plan.Blockers.Count -eq 0)
    $plan.Summary = if ($plan.IsSafe) {
        "Add include:$IncludeDomain to $Domain ($($plan.LookupsBefore) -> $($plan.LookupsAfter) lookups)"
    } else {
        "REFUSED: $($plan.Blockers[0])"
    }
    return $plan
}

function New-SPFRemovePlan {
    <#  Plans removal of an include, for de-authorizing a sender that is no
        longer in use. Removing stale includes is also the cheapest way to
        recover lookup headroom.  #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [Parameter(Mandatory)] [string]$CurrentRecord,
        [Parameter(Mandatory)] [string]$IncludeDomain
    )

    $plan = [PSCustomObject]@{
        Domain        = $Domain
        RecordType    = 'TXT'
        Name          = $Domain
        Action        = 'none'
        CurrentValue  = $CurrentRecord
        NewValue      = ''
        LookupsBefore = 0
        LookupsAfter  = 0
        IsSafe        = $false
        IsNoOp        = $false
        Blockers      = [System.Collections.Generic.List[string]]::new()
        Warnings      = [System.Collections.Generic.List[string]]::new()
        Summary       = ''
    }

    $parsed = ConvertFrom-SPFRecord -Record $CurrentRecord
    if (-not $parsed.IsValid) {
        $plan.Blockers.Add("Current record could not be parsed: $($parsed.Error)")
        $plan.Summary = 'Refusing to modify an unparseable SPF record'
        return $plan
    }
    $plan.LookupsBefore = Get-SPFRecordLookupCount -Parsed $parsed

    $match = $parsed.Terms | Where-Object { $_.Kind -eq 'include' -and $_.Value -ieq $IncludeDomain }
    if (-not $match) {
        $plan.IsNoOp       = $true
        $plan.IsSafe       = $true
        $plan.NewValue     = $CurrentRecord
        $plan.LookupsAfter = $plan.LookupsBefore
        $plan.Summary      = "include:$IncludeDomain is not present - no change needed"
        return $plan
    }

    $kept = $parsed.Terms | Where-Object { -not ($_.Kind -eq 'include' -and $_.Value -ieq $IncludeDomain) }
    $candidate = ConvertFrom-SPFRecord -Record $CurrentRecord
    $candidate.Terms.Clear()
    foreach ($t in $kept) { $candidate.Terms.Add($t) }

    $plan.Action       = 'update'
    $plan.NewValue     = ConvertTo-SPFRecord -Parsed $candidate
    $plan.LookupsAfter = Get-SPFRecordLookupCount -Parsed $candidate
    $plan.IsSafe       = $true
    $plan.Summary      = "Remove include:$IncludeDomain from $Domain ($($plan.LookupsBefore) -> $($plan.LookupsAfter) lookups)"
    $plan.Warnings.Add("Any sender still relying on $IncludeDomain will begin failing SPF once this is published")
    return $plan
}
#endregion

#region Silent failure detection
<#
    A record can be syntactically fine, published, and completely inert.

    The motivating case is real and third-party checkable: a live customer of
    a commercial DMARC vendor publishes

        v=spf1 redirect=_xxxxx.sdmarc.net ip4:41.121.57.146 include:spf.protection.outlook.com -all

    RFC 7208 s6.1: "any redirect modifier MUST be ignored if there is an all
    mechanism anywhere in the record". The record ends -all, so the redirect is
    ignored and the vendor's hosted record is never consulted. The customer is
    paying for managed SPF that does nothing, their dashboard shows a healthy
    published record, and nothing anywhere reports a problem.

    That is the whole category this region addresses: configurations that pass
    a "does the record exist and parse" check while doing nothing, or doing
    something other than what the operator believes. None of them raise an
    error. All of them are detectable from the published DNS alone.

    Every check cites the clause that makes it a failure rather than an
    opinion, so a finding can be defended to a client who disagrees.
#>

function New-AuthFinding {
    param(
        [Parameter(Mandatory)] [ValidateSet('critical','high','medium','low','info')] [string]$Severity,
        [Parameter(Mandatory)] [string]$Code,
        [Parameter(Mandatory)] [string]$Title,
        [Parameter(Mandatory)] [string]$Detail,
        [string]$Reference = '',
        [string]$Evidence  = '',
        [string]$Remediation = ''
    )
    return [PSCustomObject]@{
        Severity    = $Severity
        Code        = $Code
        Title       = $Title
        Detail      = $Detail
        Reference   = $Reference
        Evidence    = $Evidence
        Remediation = $Remediation
    }
}

function Test-SPFSilentFailure {
    <#
    .SYNOPSIS
        Finds SPF configurations that are published but not doing what the
        operator thinks.

    .PARAMETER SpfRecords
        ALL v=spf1 TXT records found at the domain, not just the first. More
        than one is itself a hard failure and cannot be detected from a single
        record.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [AllowEmptyCollection()] [string[]]$SpfRecords = @()
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $records  = @($SpfRecords | Where-Object { $_ -and $_.Trim() })

    if ($records.Count -eq 0) {
        $findings.Add((New-AuthFinding -Severity 'high' -Code 'SPF_MISSING' `
            -Title 'No SPF record published' `
            -Detail "No v=spf1 TXT record found at $Domain. Receivers have nothing to check the envelope sender against, so SPF cannot contribute to DMARC alignment." `
            -Reference 'RFC 7208' `
            -Remediation 'Publish an SPF record listing the services authorized to send for this domain.'))
        return ,$findings.ToArray()
    }

    # RFC 7208 s4.5: more than one SPF record is a permerror. Not "the first
    # one wins" - the whole evaluation fails, so a domain that looks like it
    # has SPF has none.
    if ($records.Count -gt 1) {
        $findings.Add((New-AuthFinding -Severity 'critical' -Code 'SPF_MULTIPLE_RECORDS' `
            -Title "$($records.Count) SPF records published, which is a permanent error" `
            -Detail "RFC 7208 requires exactly one v=spf1 record. When more than one is present the check returns permerror and SPF fails for every message, including legitimate ones. This commonly happens when a second service is onboarded and adds its own record instead of editing the existing one." `
            -Reference 'RFC 7208 s4.5' `
            -Evidence ($records -join '  ||  ') `
            -Remediation 'Merge the records into one, combining their mechanisms, and delete the others.'))
        # Everything below reads the first record; the multiple-record failure
        # dominates anyway.
    }

    $raw    = $records[0]
    $parsed = ConvertFrom-SPFRecord -Record $raw
    if (-not $parsed.IsValid) {
        $findings.Add((New-AuthFinding -Severity 'critical' -Code 'SPF_UNPARSEABLE' `
            -Title 'SPF record cannot be parsed' `
            -Detail "The record at $Domain does not parse as SPF: $($parsed.Error). Receivers will treat this as permerror." `
            -Reference 'RFC 7208 s4.5' -Evidence $raw))
        return ,$findings.ToArray()
    }

    $redirect = $parsed.Terms | Where-Object { $_.Kind -eq 'redirect' } | Select-Object -First 1

    # THE headline check. A published redirect= that is silently ignored.
    if ($redirect -and $parsed.AllTerm) {
        $findings.Add((New-AuthFinding -Severity 'critical' -Code 'SPF_REDIRECT_NEUTERED_BY_ALL' `
            -Title 'redirect= is silently ignored because an all mechanism is present' `
            -Detail "RFC 7208 requires a redirect modifier to be ignored whenever an all mechanism appears anywhere in the record. This record contains both, so the redirect to '$($redirect.Value)' is never followed and whatever it points at is never consulted. The record still parses, still resolves, and still looks correct in any tool that only checks whether SPF exists. If the redirect target is a managed or delegated SPF service, that service is doing nothing for this domain." `
            -Reference 'RFC 7208 s6.1' `
            -Evidence $raw `
            -Remediation "Remove the '$($parsed.AllTerm.Text)' mechanism so the redirect takes effect, or drop the redirect and list the mechanisms inline. A record cannot use both."))
    }

    # +all authorizes the entire internet. Almost always a typo for -all or a
    # leftover from testing.
    $allTerm = $parsed.AllTerm
    if ($allTerm -and $allTerm.Qualifier -eq '+') {
        $findings.Add((New-AuthFinding -Severity 'critical' -Code 'SPF_PLUS_ALL' `
            -Title '+all authorizes every host on the internet to send as this domain' `
            -Detail "A '+all' mechanism passes SPF for any sending IP whatsoever, which defeats the purpose of publishing SPF and hands anyone a passing SPF result for this domain." `
            -Reference 'RFC 7208 s5.1' -Evidence $raw `
            -Remediation "Replace '+all' with '-all', or '~all' while still identifying senders."))
    }

    # An all that is not last makes every later term unreachable.
    if ($allTerm) {
        $lastTerm = $parsed.Terms[$parsed.Terms.Count - 1]
        if ($lastTerm -and $lastTerm.Kind -ne 'all' -and -not $redirect) {
            $unreachable = @($parsed.Terms[($parsed.Terms.IndexOf($allTerm) + 1)..($parsed.Terms.Count - 1)] |
                             Where-Object { $_ } | ForEach-Object { $_.Text })
            if ($unreachable.Count -gt 0) {
                $findings.Add((New-AuthFinding -Severity 'high' -Code 'SPF_TERMS_AFTER_ALL' `
                    -Title 'Mechanisms appear after all and are never evaluated' `
                    -Detail "SPF stops at the first matching mechanism and 'all' always matches, so every term after it is unreachable. These are silently ignored: $($unreachable -join ', ')." `
                    -Reference 'RFC 7208 s5.1' -Evidence $raw `
                    -Remediation "Move '$($allTerm.Text)' to the end of the record."))
            }
        }
    }

    # Neither all nor redirect: the result is neutral, which DMARC treats as
    # a non-pass. Operators frequently believe this is a default-deny.
    if (-not $allTerm -and -not $redirect) {
        $findings.Add((New-AuthFinding -Severity 'medium' -Code 'SPF_NO_TERMINAL' `
            -Title 'No all mechanism and no redirect, so unlisted senders get a neutral result' `
            -Detail 'Without a terminal all or a redirect, a sender that matches nothing produces neutral rather than fail. Neutral does not contribute to DMARC alignment, so the record provides no protection against unlisted senders.' `
            -Reference 'RFC 7208 s4.7' -Evidence $raw `
            -Remediation "Append '-all' once the authorized senders are known, or '~all' while still identifying them."))
    }

    # Lookup cap. Exceeding it is permerror for the whole record.
    $lookups = Get-SPFRecordLookupCount -Parsed $parsed
    if ($lookups -gt $script:SPFMaxLookups) {
        $findings.Add((New-AuthFinding -Severity 'critical' -Code 'SPF_LOOKUP_LIMIT_EXCEEDED' `
            -Title "$lookups DNS lookups exceeds the limit of $script:SPFMaxLookups" `
            -Detail "RFC 7208 caps a record at $script:SPFMaxLookups DNS-costing terms. Beyond that, evaluation stops and returns permerror, so SPF fails for every message including legitimate ones. The record still looks correct because the failure only appears during evaluation." `
            -Reference 'RFC 7208 s4.6.4' -Evidence $raw `
            -Remediation 'Remove unused includes, or flatten the record to inline the IP ranges behind them.'))
    } elseif ($lookups -eq $script:SPFMaxLookups) {
        $findings.Add((New-AuthFinding -Severity 'medium' -Code 'SPF_LOOKUP_LIMIT_REACHED' `
            -Title "At the $script:SPFMaxLookups-lookup limit with no headroom" `
            -Detail 'The next sender added to this record will push it over the limit and break SPF entirely. Note the count can also rise without any local change, because an upstream include may add lookups of its own.' `
            -Reference 'RFC 7208 s4.6.4' -Evidence $raw `
            -Remediation 'Flatten or prune before authorizing another sender.'))
    }

    # ptr is deprecated and many receivers ignore it outright.
    $ptr = $parsed.Terms | Where-Object { $_.Kind -eq 'ptr' }
    if ($ptr) {
        $findings.Add((New-AuthFinding -Severity 'medium' -Code 'SPF_PTR_DEPRECATED' `
            -Title 'ptr mechanism is deprecated and unreliable' `
            -Detail 'RFC 7208 says the ptr mechanism SHOULD NOT be used: it is slow, fails badly on DNS errors, and burdens .arpa nameservers. Some receivers skip it entirely, so senders it was meant to authorize may fail SPF anyway.' `
            -Reference 'RFC 7208 s5.5' -Evidence $raw `
            -Remediation 'Replace ptr with explicit ip4/ip6 ranges or an include for the sending service.'))
    }

    return ,$findings.ToArray()
}

function Test-DMARCSilentFailure {
    <#
    .SYNOPSIS
        Finds DMARC configurations that are published but not enforcing, not
        reporting, or not applied at all.

    .PARAMETER ReportDomainVerifier
        Scriptblock taking (policyDomain, externalDomain) and returning $true
        when the RFC 7489 s7.1 authorisation record exists. Supplied by tests;
        production passes a DNS resolver. When omitted the external-destination
        check is reported as unverified rather than skipped silently.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [AllowEmptyCollection()] [string[]]$DmarcRecords = @(),
        [scriptblock]$ReportDomainVerifier
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $records  = @($DmarcRecords | Where-Object { $_ -and $_.Trim() })

    if ($records.Count -eq 0) {
        $findings.Add((New-AuthFinding -Severity 'high' -Code 'DMARC_MISSING' `
            -Title 'No DMARC record published' `
            -Detail "No v=DMARC1 TXT record at _dmarc.$Domain. Receivers have no policy to apply and no address to send reports to, so nothing about this domain's mail is visible or enforced." `
            -Reference 'RFC 7489 s6.1' `
            -Remediation 'Publish v=DMARC1; p=none with a rua= address and collect reports before enforcing.'))
        return ,$findings.ToArray()
    }

    # RFC 7489 s6.6.3: multiple records means DMARC is not applied AT ALL.
    # Not "the first wins" - the domain is silently unprotected.
    if ($records.Count -gt 1) {
        $findings.Add((New-AuthFinding -Severity 'critical' -Code 'DMARC_MULTIPLE_RECORDS' `
            -Title "$($records.Count) DMARC records published, so DMARC is not applied at all" `
            -Detail 'RFC 7489 says that when policy discovery finds multiple records, DMARC processing is abandoned for the message. The domain is therefore completely unprotected despite appearing to have a policy, and no reports are generated.' `
            -Reference 'RFC 7489 s6.6.3' `
            -Evidence ($records -join '  ||  ') `
            -Remediation 'Delete all but one DMARC record.'))
    }

    $raw = $records[0]

    if ($raw -notmatch '(?i)^\s*v=DMARC1\s*;') {
        $findings.Add((New-AuthFinding -Severity 'critical' -Code 'DMARC_BAD_VERSION' `
            -Title 'Record does not begin with v=DMARC1' `
            -Detail 'RFC 7489 requires v=DMARC1 as the first tag. A record that does not start with it is not recognised as DMARC and is ignored entirely.' `
            -Reference 'RFC 7489 s6.3' -Evidence $raw))
        return ,$findings.ToArray()
    }

    $policy = if ($raw -match '(?i)\bp=(none|quarantine|reject)\b') { $Matches[1].ToLowerInvariant() } else { $null }
    if (-not $policy) {
        $findings.Add((New-AuthFinding -Severity 'critical' -Code 'DMARC_NO_POLICY' `
            -Title 'No valid p= tag' `
            -Detail 'The p= tag is required and must be none, quarantine or reject. Without it the record is invalid and receivers ignore it, leaving the domain unprotected.' `
            -Reference 'RFC 7489 s6.3' -Evidence $raw))
    }

    # pct=0 means the policy applies to nothing.
    if ($raw -match '(?i)\bpct=(\d+)\b') {
        $pct = [int]$Matches[1]
        if ($pct -eq 0) {
            $findings.Add((New-AuthFinding -Severity 'high' -Code 'DMARC_PCT_ZERO' `
                -Title "pct=0 means the policy is applied to no messages" `
                -Detail "p=$policy is published but pct=0 applies it to zero percent of failing mail. The domain reads as enforcing in any tool that only looks at p=, while behaving exactly as p=none." `
                -Reference 'RFC 7489 s6.3' -Evidence $raw `
                -Remediation 'Raise pct, or drop the tag entirely to apply the policy to all failing mail.'))
        } elseif ($pct -lt 100 -and $policy -in @('quarantine','reject')) {
            $findings.Add((New-AuthFinding -Severity 'medium' -Code 'DMARC_PCT_PARTIAL' `
                -Title "pct=$pct applies the policy to only $pct% of failing mail" `
                -Detail "The remaining $((100 - $pct))% is treated as p=none, so most spoofed mail is still delivered. This is correct during a ramp and a gap if it was forgotten." `
                -Reference 'RFC 7489 s6.3' -Evidence $raw `
                -Remediation 'Raise to pct=100 once the ramp is complete.'))
        }
    }

    # Enforcing with no reporting address is flying blind.
    $ruaMatch = [regex]::Match($raw, '(?i)\brua=([^;]+)')
    if (-not $ruaMatch.Success) {
        $sev = if ($policy -in @('quarantine','reject')) { 'high' } else { 'medium' }
        $findings.Add((New-AuthFinding -Severity $sev -Code 'DMARC_NO_RUA' `
            -Title 'No rua= address, so no aggregate reports are received' `
            -Detail "Without rua= no receiver sends aggregate reports, so there is no visibility into who is sending as this domain or whether enforcement is breaking legitimate mail. At p=$policy that means enforcing without being able to see the consequences." `
            -Reference 'RFC 7489 s6.3' -Evidence $raw `
            -Remediation 'Add rua=mailto: pointing at the mailbox this platform ingests.'))
    } else {
        # RFC 7489 s7.1 external destination verification. Without the
        # authorisation record at the DESTINATION, conforming receivers refuse
        # to send reports - and nothing anywhere reports that refusal. The
        # domain simply never receives data.
        foreach ($uri in ($ruaMatch.Groups[1].Value -split ',')) {
            $u = $uri.Trim()
            if ($u -notmatch '(?i)^mailto:') {
                $findings.Add((New-AuthFinding -Severity 'high' -Code 'DMARC_RUA_NOT_MAILTO' `
                    -Title "rua= entry '$u' is not a mailto: URI" `
                    -Detail 'RFC 7489 requires report destinations to be URIs; in practice only mailto: is supported by receivers. A malformed entry is ignored, and if it is the only one no reports arrive.' `
                    -Reference 'RFC 7489 s6.3' -Evidence $raw))
                continue
            }
            $addr = ($u -replace '(?i)^mailto:', '') -replace '!.*$', ''
            if ($addr -notmatch '@') { continue }
            $destDomain = ($addr -split '@')[-1].Trim()
            if (-not $destDomain) { continue }

            $isExternal = -not ($destDomain -ieq $Domain -or $destDomain -imatch "\.$([regex]::Escape($Domain))$")
            if (-not $isExternal) { continue }

            if (-not $ReportDomainVerifier) {
                $findings.Add((New-AuthFinding -Severity 'info' -Code 'DMARC_RUA_EXTERNAL_UNVERIFIED' `
                    -Title "Reports go to an external domain ($destDomain) - authorisation not checked" `
                    -Detail "rua= points outside $Domain, which requires an authorisation record at $Domain._report._dmarc.$destDomain. No verifier was supplied so this was not checked." `
                    -Reference 'RFC 7489 s7.1' -Evidence $raw))
                continue
            }

            $authorized = $false
            try { $authorized = [bool](& $ReportDomainVerifier $Domain $destDomain) } catch { $authorized = $false }

            if (-not $authorized) {
                $findings.Add((New-AuthFinding -Severity 'critical' -Code 'DMARC_RUA_EXTERNAL_UNAUTHORIZED' `
                    -Title "Aggregate reports are silently discarded: $destDomain has not authorised reports for $Domain" `
                    -Detail "rua= sends reports to $addr, which is outside $Domain. RFC 7489 requires the destination to publish '$Domain._report._dmarc.$destDomain  TXT  v=DMARC1' before conforming receivers will send anything. That record is absent, so receivers refuse and no report ever arrives. Nothing surfaces an error: the DMARC record looks correct and the reports simply never come." `
                    -Reference 'RFC 7489 s7.1' -Evidence $raw `
                    -Remediation "Publish  $Domain._report._dmarc.$destDomain  TXT  ""v=DMARC1""  in the $destDomain zone."))
            }
        }
    }

    # sp=none under an enforcing policy leaves every subdomain open, which is
    # exactly what a spoofer will use.
    if ($raw -match '(?i)\bsp=(none|quarantine|reject)\b') {
        $sp = $Matches[1].ToLowerInvariant()
        if ($sp -eq 'none' -and $policy -in @('quarantine','reject')) {
            $findings.Add((New-AuthFinding -Severity 'high' -Code 'DMARC_SUBDOMAIN_UNPROTECTED' `
                -Title "p=$policy but sp=none leaves every subdomain unprotected" `
                -Detail "The organisational domain enforces, but sp=none tells receivers to apply no policy to subdomains. An attacker can send as anything.$Domain and pass. This is a common way an apparently-enforcing domain remains spoofable." `
                -Reference 'RFC 7489 s6.3' -Evidence $raw `
                -Remediation 'Remove sp= so subdomains inherit p=, or set sp= to match.'))
        }
    }

    return ,$findings.ToArray()
}

function Test-AuthenticationSilentFailures {
    <#
    .SYNOPSIS
        Runs every silent-failure check for a domain and returns the findings
        ordered by severity.

    .DESCRIPTION
        Built to be runnable against a domain nobody has onboarded yet: it
        needs only published DNS. That makes it usable as a pre-sales check
        as well as an ongoing one - point it at a prospect's domain and show
        them what is quietly broken.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [AllowEmptyCollection()] [string[]]$SpfRecords = @(),
        [AllowEmptyCollection()] [string[]]$DmarcRecords = @(),
        [scriptblock]$ReportDomainVerifier
    )

    $all = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($f in (Test-SPFSilentFailure -Domain $Domain -SpfRecords $SpfRecords)) { $all.Add($f) }

    $dmarcArgs = @{ Domain = $Domain; DmarcRecords = $DmarcRecords }
    if ($ReportDomainVerifier) { $dmarcArgs['ReportDomainVerifier'] = $ReportDomainVerifier }
    foreach ($f in (Test-DMARCSilentFailure @dmarcArgs)) { $all.Add($f) }

    $rank = @{ 'critical' = 0; 'high' = 1; 'medium' = 2; 'low' = 3; 'info' = 4 }
    $ordered = @($all | Sort-Object @{ Expression = { $rank[$_.Severity] } }, Code)

    return [PSCustomObject]@{
        Domain       = $Domain
        Findings     = $ordered
        CriticalCount= @($ordered | Where-Object Severity -eq 'critical').Count
        HighCount    = @($ordered | Where-Object Severity -eq 'high').Count
        TotalCount   = $ordered.Count
        IsSilentlyBroken = (@($ordered | Where-Object Severity -eq 'critical').Count -gt 0)
    }
}
#endregion

#region DKIM change planning
function New-DKIMPlan {
    <#
    .SYNOPSIS
        Turns a sender-catalog entry into the DKIM records to publish.

    .DESCRIPTION
        The catalog stores each service's DKIM shape as a template with
        placeholders the operator would otherwise have to fill in by hand from
        the vendor's admin console. This substitutes what we can derive
        ({your-domain} and its hyphenated form) and reports what it cannot,
        rather than emitting a record containing a literal "{account-id}"
        that would silently fail to resolve.

        Services with no DKIM of their own (relays that sign as the customer,
        or SaaS that does not offer custom signing) return an empty plan with
        an explanation instead of a fabricated record.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [Parameter(Mandatory)] [PSCustomObject]$CatalogService,
        [hashtable]$Placeholders = @{}
    )

    $plan = [PSCustomObject]@{
        Domain            = $Domain
        ServiceName       = $CatalogService.name
        Records           = [System.Collections.Generic.List[PSCustomObject]]::new()
        UnresolvedTokens  = [System.Collections.Generic.List[string]]::new()
        Instructions      = ''
        IsActionable      = $false
        Summary           = ''
    }

    $plan.Instructions = if ($CatalogService.PSObject.Properties.Name -contains 'authInstructions') {
        [string]$CatalogService.authInstructions
    } else { '' }

    $template = if ($CatalogService.PSObject.Properties.Name -contains 'dkimCnameTemplate') {
        [string]$CatalogService.dkimCnameTemplate
    } else { '' }

    if ([string]::IsNullOrWhiteSpace($template)) {
        $selectors = @()
        if ($CatalogService.PSObject.Properties.Name -contains 'dkimSelectors') {
            $selectors = @($CatalogService.dkimSelectors)
        }
        $plan.Summary = if ($selectors.Count -gt 0) {
            "$($CatalogService.name) publishes DKIM under selector(s) $($selectors -join ', '); retrieve the key from its admin console"
        } else {
            "$($CatalogService.name) does not publish a customer-specific DKIM key"
        }
        return $plan
    }

    # Substitute what we can derive from the domain itself.
    $resolved = $template
    $resolved = $resolved -replace '\{your-domain-hyphens\}', ($Domain -replace '\.', '-')
    $resolved = $resolved -replace '\{your-domain\}', $Domain
    foreach ($key in $Placeholders.Keys) {
        $resolved = $resolved -replace ([regex]::Escape("{$key}")), [string]$Placeholders[$key]
    }

    # Anything still in braces has to come from the vendor's console.
    foreach ($m in [regex]::Matches($resolved, '\{([a-z0-9\-]+)\}')) {
        $tok = $m.Groups[1].Value
        if (-not $plan.UnresolvedTokens.Contains($tok)) { $plan.UnresolvedTokens.Add($tok) }
    }

    foreach ($line in ($resolved -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        # Template lines look like: <name> CNAME <value>  /  <name> TXT (...)
        if ($t -match '^(?<name>\S+)\s+(?<type>CNAME|TXT)\s+(?<value>.+)$') {
            $plan.Records.Add([PSCustomObject]@{
                Name       = $Matches['name']
                RecordType = $Matches['type']
                Value      = $Matches['value'].Trim()
                IsComplete = ($Matches['value'] -notmatch '\{[a-z0-9\-]+\}' -and $Matches['name'] -notmatch '\{[a-z0-9\-]+\}')
            })
        } else {
            $plan.Records.Add([PSCustomObject]@{
                Name = ''; RecordType = 'note'; Value = $t
                IsComplete = ($t -notmatch '\{[a-z0-9\-]+\}')
            })
        }
    }

    $actionable = @($plan.Records | Where-Object { $_.RecordType -in @('CNAME','TXT') -and $_.IsComplete })
    $plan.IsActionable = ($actionable.Count -gt 0)
    $plan.Summary = if ($plan.IsActionable) {
        "$($actionable.Count) DKIM record(s) ready to publish for $($CatalogService.name)"
    } elseif ($plan.UnresolvedTokens.Count -gt 0) {
        "Needs $($plan.UnresolvedTokens -join ', ') from the $($CatalogService.name) admin console before publishing"
    } else {
        "No publishable DKIM records derived for $($CatalogService.name)"
    }
    return $plan
}
#endregion

#region DMARC change planning
function New-DMARCPolicyPlan {
    <#
    .SYNOPSIS
        Plans a DMARC policy advancement.

    .DESCRIPTION
        Advancing policy is the point of the whole product, and it is also the
        change most capable of dropping legitimate mail. The planner therefore
        refuses to skip a rung: none -> reject in one step is rejected in
        favour of none -> quarantine, because quarantine is recoverable and
        reject is not.

        A pct ramp is supported for the same reason: p=reject pct=25 applies
        the policy to a quarter of failing mail, so a mistake costs a quarter
        as much while the reports still show what would happen.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [AllowEmptyString()] [string]$CurrentRecord,
        [ValidateSet('none','quarantine','reject')] [string]$TargetPolicy,
        [ValidateRange(1,100)] [int]$TargetPct = 100,
        [switch]$AllowPolicySkip
    )

    $plan = [PSCustomObject]@{
        Domain         = $Domain
        RecordType     = 'TXT'
        Name           = "_dmarc.$Domain"
        Action         = 'none'
        CurrentValue   = $CurrentRecord
        NewValue       = ''
        CurrentPolicy  = 'none'
        TargetPolicy   = $TargetPolicy
        IsSafe         = $false
        IsNoOp         = $false
        Blockers       = [System.Collections.Generic.List[string]]::new()
        Warnings       = [System.Collections.Generic.List[string]]::new()
        Summary        = ''
    }

    $rank = @{ 'none' = 0; 'quarantine' = 1; 'reject' = 2 }

    if ([string]::IsNullOrWhiteSpace($CurrentRecord)) {
        # No DMARC at all. Starting anywhere above none without observation
        # data is how you lose mail you did not know you were sending.
        if ($TargetPolicy -ne 'none' -and -not $AllowPolicySkip) {
            $plan.Blockers.Add(
                "No DMARC record exists for $Domain. Publish p=none first and collect at least " +
                "two weeks of reports before enforcing, otherwise unknown legitimate senders " +
                "are silently affected.")
            $plan.Summary = "REFUSED: $($plan.Blockers[0])"
            return $plan
        }
        $plan.Action   = 'create'
        $plan.NewValue = "v=DMARC1; p=$TargetPolicy; rua=mailto:dmarc@$Domain"
        $plan.IsSafe   = $true
        $plan.Summary  = "Create DMARC record for $Domain at p=$TargetPolicy"
        $plan.Warnings.Add("Set rua= to the mailbox this tool ingests, or no reports will reach it")
        return $plan
    }

    if ($CurrentRecord -notmatch '(?i)v=DMARC1') {
        $plan.Blockers.Add('Current record is not a DMARC record')
        $plan.Summary = 'Refusing to modify a record that is not DMARC'
        return $plan
    }

    $plan.CurrentPolicy = if ($CurrentRecord -match '(?i)\bp=(none|quarantine|reject)\b') { $Matches[1].ToLowerInvariant() } else { 'none' }
    $currentPct         = if ($CurrentRecord -match '(?i)\bpct=(\d+)\b') { [int]$Matches[1] } else { 100 }

    if ($plan.CurrentPolicy -eq $TargetPolicy -and $currentPct -eq $TargetPct) {
        $plan.IsNoOp   = $true
        $plan.IsSafe   = $true
        $plan.NewValue = $CurrentRecord
        $plan.Summary  = "Already at p=$TargetPolicy pct=$TargetPct - no change needed"
        return $plan
    }

    $from = $rank[$plan.CurrentPolicy]
    $to   = $rank[$TargetPolicy]

    if (($to - $from) -gt 1 -and -not $AllowPolicySkip) {
        $plan.Blockers.Add(
            "Refusing to jump p=$($plan.CurrentPolicy) straight to p=$TargetPolicy. " +
            "Advance to p=quarantine first: quarantine sends failing mail to junk and is " +
            "recoverable, reject discards it outright and is not.")
        $plan.Summary = "REFUSED: $($plan.Blockers[0])"
        return $plan
    }

    if ($to -lt $from) {
        $plan.Warnings.Add("This WEAKENS enforcement from p=$($plan.CurrentPolicy) to p=$TargetPolicy")
    }

    # Rebuild preserving every other tag the operator had set.
    $tags = [ordered]@{}
    foreach ($part in ($CurrentRecord -split ';')) {
        $t = $part.Trim()
        if (-not $t) { continue }
        if ($t -match '^(?<k>[A-Za-z]+)=(?<v>.*)$') { $tags[$Matches['k'].ToLowerInvariant()] = $Matches['v'].Trim() }
    }
    $tags['v'] = 'DMARC1'
    $tags['p'] = $TargetPolicy
    if ($TargetPct -eq 100) { $tags.Remove('pct') } else { $tags['pct'] = "$TargetPct" }

    # v= must come first per RFC 7489, p= second by convention.
    $ordered = [System.Collections.Generic.List[string]]::new()
    $ordered.Add("v=$($tags['v'])")
    $ordered.Add("p=$($tags['p'])")
    foreach ($k in $tags.Keys) {
        if ($k -in @('v','p')) { continue }
        $ordered.Add("$k=$($tags[$k])")
    }

    $plan.Action   = 'update'
    $plan.NewValue = ($ordered -join '; ')
    $plan.IsSafe   = ($plan.Blockers.Count -eq 0)

    if (-not $tags.Contains('rua')) {
        $plan.Warnings.Add("No rua= tag: enforcing without aggregate reporting means flying blind")
    }

    $plan.Summary = if ($plan.IsSafe) {
        $pctNote = if ($TargetPct -ne 100) { " at pct=$TargetPct" } else { '' }
        "Advance $Domain from p=$($plan.CurrentPolicy) to p=$TargetPolicy$pctNote"
    } else { "REFUSED: $($plan.Blockers[0])" }
    return $plan
}
#endregion

#region SPF flattening
function Resolve-SPFIncludeToIPs {
    <#
    .SYNOPSIS
        Expands an include: chain into the literal ip4/ip6 ranges behind it.

    .DESCRIPTION
        Flattening trades maintainability for lookup headroom. It is the
        standard escape hatch when a record is at the RFC 7208 cap and a new
        sender still has to be authorized, and it is sold as a paid add-on by
        several competitors.

        The trade has a real cost that callers must understand: a flattened
        record is a point-in-time snapshot. When the provider changes its
        sending ranges - which large ESPs do without notice - the flattened
        copy goes stale and mail from the new ranges starts failing. That is
        why New-SPFFlattenPlan records a RefreshBy date and why the state it
        writes is designed to be re-run on a schedule.

        -Resolver lets tests supply canned zone data; production passes
        Resolve-DnsName.
    #>
    param(
        [Parameter(Mandatory)] [string]$IncludeDomain,
        [int]$Depth = 0,
        [int]$MaxDepth = 10,
        [System.Collections.Generic.HashSet[string]]$Visited,
        [scriptblock]$Resolver
    )

    if (-not $Visited) {
        $Visited = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    }

    $result = [PSCustomObject]@{
        Domain       = $IncludeDomain
        IPs          = [System.Collections.Generic.List[string]]::new()
        Unresolvable = [System.Collections.Generic.List[string]]::new()
        Errors       = [System.Collections.Generic.List[string]]::new()
    }

    if ($Depth -gt $MaxDepth) {
        $result.Errors.Add("Max include depth reached at $IncludeDomain")
        return $result
    }
    if (-not $Visited.Add($IncludeDomain)) {
        # Already expanded on this path. Not an error - a shared _spf include
        # reached twice is common - just nothing further to contribute.
        return $result
    }

    $record = $null
    try {
        if ($Resolver) {
            $record = & $Resolver $IncludeDomain
        } else {
            $dns = Resolve-DnsName -Name $IncludeDomain -Type TXT -EA Stop
            $rec = $dns | Where-Object { $_.Strings -match 'v=spf1' } | Select-Object -First 1
            if ($rec) { $record = ($rec.Strings -join '') }
        }
    } catch {
        $result.Errors.Add("DNS lookup failed for $IncludeDomain : $_")
        return $result
    }

    if ([string]::IsNullOrWhiteSpace($record)) {
        $result.Errors.Add("No SPF record found at $IncludeDomain")
        return $result
    }

    $parsed = ConvertFrom-SPFRecord -Record $record
    if (-not $parsed.IsValid) {
        $result.Errors.Add("Unparseable SPF at $IncludeDomain : $($parsed.Error)")
        return $result
    }

    foreach ($term in $parsed.Terms) {
        switch ($term.Kind) {
            'ip4' { $result.IPs.Add("ip4:$($term.Value)") }
            'ip6' { $result.IPs.Add("ip6:$($term.Value)") }
            'include' {
                $child = Resolve-SPFIncludeToIPs -IncludeDomain $term.Value -Depth ($Depth + 1) `
                            -MaxDepth $MaxDepth -Visited $Visited -Resolver $Resolver
                foreach ($ip in $child.IPs)          { $result.IPs.Add($ip) }
                foreach ($u  in $child.Unresolvable) { $result.Unresolvable.Add($u) }
                foreach ($e  in $child.Errors)       { $result.Errors.Add($e) }
            }
            'redirect' {
                $child = Resolve-SPFIncludeToIPs -IncludeDomain $term.Value -Depth ($Depth + 1) `
                            -MaxDepth $MaxDepth -Visited $Visited -Resolver $Resolver
                foreach ($ip in $child.IPs)          { $result.IPs.Add($ip) }
                foreach ($u  in $child.Unresolvable) { $result.Unresolvable.Add($u) }
                foreach ($e  in $child.Errors)       { $result.Errors.Add($e) }
            }
            default {
                # a, mx, ptr and exists resolve against the *sending* host at
                # evaluation time, so they cannot be reduced to a fixed list
                # without changing what the record means. Flattening them
                # would silently narrow the authorized set.
                if ($term.CostsLookup) {
                    $result.Unresolvable.Add($term.Text)
                }
            }
        }
    }
    return $result
}

function New-SPFFlattenPlan {
    <#
    .SYNOPSIS
        Plans a flattened replacement for an SPF record that is at the cap.

    .DESCRIPTION
        Replaces include: mechanisms with the ip4/ip6 ranges behind them,
        freeing the lookups they consumed. Mechanisms that cannot be reduced
        without changing meaning (a, mx, ptr, exists) are preserved as-is and
        still counted.

        Refuses to produce a record that would not actually help, or that
        would exceed the length limit. Flattening a record that is already
        under the cap is reported as unnecessary rather than performed, since
        the maintenance burden is only worth taking on when it buys something.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [Parameter(Mandatory)] [string]$CurrentRecord,
        [scriptblock]$Resolver,
        [int]$RefreshDays = 30
    )

    $plan = [PSCustomObject]@{
        Domain          = $Domain
        RecordType      = 'TXT'
        Name            = $Domain
        Action          = 'none'
        CurrentValue    = $CurrentRecord
        NewValue        = ''
        LookupsBefore   = 0
        LookupsAfter    = 0
        FlattenedFrom   = [System.Collections.Generic.List[string]]::new()
        PreservedTerms  = [System.Collections.Generic.List[string]]::new()
        RefreshBy       = (Get-Date).AddDays($RefreshDays).ToString('yyyy-MM-dd')
        IsSafe          = $false
        Blockers        = [System.Collections.Generic.List[string]]::new()
        Warnings        = [System.Collections.Generic.List[string]]::new()
        Summary         = ''
    }

    $parsed = ConvertFrom-SPFRecord -Record $CurrentRecord
    if (-not $parsed.IsValid) {
        $plan.Blockers.Add("Current record could not be parsed: $($parsed.Error)")
        $plan.Summary = 'Refusing to flatten an unparseable SPF record'
        return $plan
    }
    $plan.LookupsBefore = Get-SPFRecordLookupCount -Parsed $parsed

    $includes = @($parsed.Terms | Where-Object { $_.Kind -in @('include','redirect') })
    if ($includes.Count -eq 0) {
        $plan.Summary = 'Nothing to flatten: the record contains no include or redirect terms'
        return $plan
    }

    $allIPs  = [System.Collections.Generic.List[string]]::new()
    $seenIP  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $errors  = [System.Collections.Generic.List[string]]::new()

    foreach ($inc in $includes) {
        $r = Resolve-SPFIncludeToIPs -IncludeDomain $inc.Value -Resolver $Resolver
        foreach ($ip in $r.IPs) { if ($seenIP.Add($ip)) { $allIPs.Add($ip) } }
        foreach ($e in $r.Errors) { $errors.Add($e) }
        foreach ($u in $r.Unresolvable) {
            $plan.Warnings.Add("$($inc.Value) uses '$u', which resolves at evaluation time and cannot be flattened without narrowing the authorized set")
        }
        if ($r.IPs.Count -gt 0) { $plan.FlattenedFrom.Add($inc.Value) }
    }

    if ($errors.Count -gt 0) {
        foreach ($e in $errors) { $plan.Blockers.Add($e) }
        $plan.Summary = "REFUSED: could not fully resolve every include - flattening a partial set would drop authorized senders"
        return $plan
    }

    if ($allIPs.Count -eq 0) {
        $plan.Blockers.Add('No IP ranges were recovered from the include chain')
        $plan.Summary = 'REFUSED: flattening would produce a record authorizing nothing'
        return $plan
    }

    # Keep every term we did not flatten, in its original order.
    $keptTerms = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $parsed.Terms) {
        if ($t.Kind -in @('include','redirect')) { continue }
        if ($t.Kind -eq 'all') { continue }   # re-appended last
        $keptTerms.Add($t.Text)
        if ($t.CostsLookup) { $plan.PreservedTerms.Add($t.Text) }
    }

    $allText = if ($parsed.AllTerm) { $parsed.AllTerm.Text } else { '~all' }
    $parts   = @('v=spf1') + $keptTerms + $allIPs + @($allText)
    $plan.NewValue     = ($parts -join ' ')
    $plan.LookupsAfter = @($plan.PreservedTerms).Count
    $plan.Action       = 'update'

    if ($plan.NewValue.Length -gt $script:SPFMaxTotalLength) {
        $plan.Blockers.Add(
            "Flattened record is $($plan.NewValue.Length) characters, over the $script:SPFMaxTotalLength limit. " +
            "Split the ranges across a sub-include, or drop senders that are no longer in use.")
    }

    if ($plan.LookupsAfter -ge $plan.LookupsBefore) {
        $plan.Blockers.Add("Flattening would not reduce the lookup count ($($plan.LookupsBefore) -> $($plan.LookupsAfter)); it is not worth the maintenance burden")
    }

    $plan.IsSafe = ($plan.Blockers.Count -eq 0)
    $plan.Warnings.Add("Flattened records are a point-in-time snapshot. Re-run flattening by $($plan.RefreshBy) or mail from newly-added provider ranges will start failing.")

    $plan.Summary = if ($plan.IsSafe) {
        "Flatten ${Domain}: $($plan.LookupsBefore) -> $($plan.LookupsAfter) lookups, $($allIPs.Count) ranges inlined from $($plan.FlattenedFrom.Count) include(s)"
    } else {
        "REFUSED: $($plan.Blockers[0])"
    }
    return $plan
}
#endregion

#region DNS provider abstraction
<#
    A provider is a plain object exposing three script blocks:

        GetRecords  { param($Name, $Type)                  -> @( @{Name;Type;Value;TTL;Id} ) }
        SetRecord   { param($Name, $Type, $Value, $TTL)    -> @{Success;Id;Error} }
        RemoveRecord{ param($RecordId)                     -> @{Success;Error} }

    Kept as script blocks rather than classes so a test can substitute an
    in-memory provider with no ceremony, and so adding a registrar is one
    function rather than a type hierarchy.

    The Manual provider is always available and is what an unsupported
    registrar degrades to: it "applies" a change by emitting copy-paste
    instructions rather than failing.
#>

function New-ManualDNSProvider {
    <#  Always-available fallback. Records what it was asked to do so the
        caller can render instructions; never touches the network.  #>
    param()
    $emitted = [System.Collections.Generic.List[PSCustomObject]]::new()
    return [PSCustomObject]@{
        Name         = 'Manual'
        IsAutomatic  = $false
        Emitted      = $emitted
        GetRecords   = {
            param($Name, $Type)
            # Manual provider cannot read the zone; callers fall back to a
            # live DNS query for the current value.
            return @()
        }.GetNewClosure()
        SetRecord    = {
            param($Name, $Type, $Value, $TTL)
            $emitted.Add([PSCustomObject]@{ Action='set'; Name=$Name; Type=$Type; Value=$Value; TTL=$TTL })
            return @{ Success = $true; Id = "manual:$Name/$Type"; Error = '' }
        }.GetNewClosure()
        RemoveRecord = {
            param($RecordId)
            $emitted.Add([PSCustomObject]@{ Action='remove'; Id=$RecordId })
            return @{ Success = $true; Error = '' }
        }.GetNewClosure()
    }
}

function New-CloudflareDNSProvider {
    <#
    .SYNOPSIS
        Cloudflare DNS provider.

    .DESCRIPTION
        Uses a scoped API token (Zone:DNS:Edit on the target zone only), not a
        Global API Key. A Global Key can do anything to the whole account; a
        scoped token limits the blast radius of this tool to DNS on one zone,
        which is the right posture for something that edits a client's
        production mail routing.
    #>
    param(
        [Parameter(Mandatory)] [string]$ApiToken,
        [Parameter(Mandatory)] [string]$ZoneId,
        [string]$BaseUri = 'https://api.cloudflare.com/client/v4'
    )

    $headers = @{ 'Authorization' = "Bearer $ApiToken"; 'Content-Type' = 'application/json' }

    return [PSCustomObject]@{
        Name        = 'Cloudflare'
        IsAutomatic = $true
        ZoneId      = $ZoneId
        GetRecords  = {
            param($Name, $Type)
            $uri = "$BaseUri/zones/$ZoneId/dns_records?type=$Type&name=$([uri]::EscapeDataString($Name))"
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -EA Stop
            if (-not $resp.success) { throw "Cloudflare API error: $(($resp.errors | ForEach-Object { $_.message }) -join '; ')" }
            return @($resp.result | ForEach-Object {
                [PSCustomObject]@{ Name=$_.name; Type=$_.type; Value=$_.content; TTL=$_.ttl; Id=$_.id }
            })
        }.GetNewClosure()
        SetRecord   = {
            param($Name, $Type, $Value, $TTL)
            try {
                $existing = Invoke-RestMethod -Method GET -Headers $headers -EA Stop `
                    -Uri "$BaseUri/zones/$ZoneId/dns_records?type=$Type&name=$([uri]::EscapeDataString($Name))"
                $body = @{ type=$Type; name=$Name; content=$Value; ttl=$(if ($TTL) { $TTL } else { 300 }) } | ConvertTo-Json
                if ($existing.result -and $existing.result.Count -gt 0) {
                    $id = $existing.result[0].id
                    $r = Invoke-RestMethod -Method PUT -Headers $headers -Body $body -EA Stop `
                        -Uri "$BaseUri/zones/$ZoneId/dns_records/$id"
                } else {
                    $r = Invoke-RestMethod -Method POST -Headers $headers -Body $body -EA Stop `
                        -Uri "$BaseUri/zones/$ZoneId/dns_records"
                }
                if (-not $r.success) { return @{ Success=$false; Id=''; Error=(($r.errors | ForEach-Object { $_.message }) -join '; ') } }
                return @{ Success=$true; Id=$r.result.id; Error='' }
            } catch {
                return @{ Success=$false; Id=''; Error="$_" }
            }
        }.GetNewClosure()
        RemoveRecord = {
            param($RecordId)
            try {
                $r = Invoke-RestMethod -Method DELETE -Headers $headers -EA Stop `
                    -Uri "$BaseUri/zones/$ZoneId/dns_records/$RecordId"
                return @{ Success=$true; Error='' }
            } catch { return @{ Success=$false; Error="$_" } }
        }.GetNewClosure()
    }
}

function New-AzureDNSProvider {
    <#
    .SYNOPSIS
        Azure DNS provider, for clients whose zones live in the same tenant
        as everything else in this product.

    .DESCRIPTION
        Takes an already-acquired bearer token rather than doing its own auth,
        so it composes with the certificate-based Graph auth the rest of the
        tool already performs instead of introducing a second credential path.
    #>
    param(
        [Parameter(Mandatory)] [string]$AccessToken,
        [Parameter(Mandatory)] [string]$SubscriptionId,
        [Parameter(Mandatory)] [string]$ResourceGroup,
        [Parameter(Mandatory)] [string]$ZoneName,
        [string]$ApiVersion = '2018-05-01'
    )

    $headers = @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    $base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/dnsZones/$ZoneName"

    # Azure addresses records by name relative to the zone apex, with '@' for
    # the apex itself.
    $relativeName = {
        param($Name, $Zone)
        if ($Name -ieq $Zone) { return '@' }
        if ($Name -imatch "\.$([regex]::Escape($Zone))$") { return ($Name -ireplace "\.$([regex]::Escape($Zone))$", '') }
        return $Name
    }

    return [PSCustomObject]@{
        Name        = 'AzureDNS'
        IsAutomatic = $true
        ZoneName    = $ZoneName
        GetRecords  = {
            param($Name, $Type)
            $rel = & $relativeName $Name $ZoneName
            try {
                $r = Invoke-RestMethod -Method GET -Headers $headers -EA Stop `
                    -Uri "$base/$Type/$rel`?api-version=$ApiVersion"
                $vals = switch ($Type) {
                    'TXT'   { @($r.properties.TXTRecords   | ForEach-Object { ($_.value -join '') }) }
                    'CNAME' { @($r.properties.CNAMERecord.cname) }
                    default { @() }
                }
                return @($vals | Where-Object { $_ } | ForEach-Object {
                    [PSCustomObject]@{ Name=$Name; Type=$Type; Value=$_; TTL=$r.properties.TTL; Id="$Type/$rel" }
                })
            } catch { return @() }
        }.GetNewClosure()
        SetRecord   = {
            param($Name, $Type, $Value, $TTL)
            $rel = & $relativeName $Name $ZoneName
            $ttlValue = if ($TTL) { $TTL } else { 300 }
            $props = switch ($Type) {
                'TXT'   { @{ TTL=$ttlValue; TXTRecords=@(@{ value=@($Value) }) } }
                'CNAME' { @{ TTL=$ttlValue; CNAMERecord=@{ cname=$Value } } }
                default { $null }
            }
            if (-not $props) { return @{ Success=$false; Id=''; Error="Unsupported record type $Type" } }
            try {
                $body = @{ properties = $props } | ConvertTo-Json -Depth 6
                $null = Invoke-RestMethod -Method PUT -Headers $headers -Body $body -EA Stop `
                    -Uri "$base/$Type/$rel`?api-version=$ApiVersion"
                return @{ Success=$true; Id="$Type/$rel"; Error='' }
            } catch { return @{ Success=$false; Id=''; Error="$_" } }
        }.GetNewClosure()
        RemoveRecord = {
            param($RecordId)
            try {
                $null = Invoke-RestMethod -Method DELETE -Headers $headers -EA Stop `
                    -Uri "$base/$RecordId`?api-version=$ApiVersion"
                return @{ Success=$true; Error='' }
            } catch { return @{ Success=$false; Error="$_" } }
        }.GetNewClosure()
    }
}

function New-InMemoryDNSProvider {
    <#  Test double. Behaves like a real provider against a hashtable zone so
        apply/verify/rollback can be exercised without touching DNS.  #>
    param([hashtable]$InitialZone = @{})

    $zone = @{}
    foreach ($k in $InitialZone.Keys) { $zone[$k] = $InitialZone[$k] }

    return [PSCustomObject]@{
        Name        = 'InMemory'
        IsAutomatic = $true
        Zone        = $zone
        GetRecords  = {
            param($Name, $Type)
            $key = "$Type|$Name"
            if (-not $zone.ContainsKey($key)) { return @() }
            return @([PSCustomObject]@{ Name=$Name; Type=$Type; Value=$zone[$key]; TTL=300; Id=$key })
        }.GetNewClosure()
        SetRecord   = {
            param($Name, $Type, $Value, $TTL)
            $key = "$Type|$Name"
            $zone[$key] = $Value
            return @{ Success=$true; Id=$key; Error='' }
        }.GetNewClosure()
        RemoveRecord = {
            param($RecordId)
            if ($zone.ContainsKey($RecordId)) { $zone.Remove($RecordId) }
            return @{ Success=$true; Error='' }
        }.GetNewClosure()
    }
}
#endregion

#region Provider configuration
# Where a domain's DNS lives, persisted alongside the other state files. The
# credential is NOT here: the row carries only non-secret coordinates plus an
# opaque ref into the secret store, matching dns_provider_configs in the
# schema so this file migrates into the database without reshaping.

function Get-DNSProviderConfigPath {
    param([Parameter(Mandatory)] [string]$WorkingDir)
    return (Join-Path $WorkingDir 'State\dns-providers.json')
}

function ConvertTo-ProviderKey {
    <#
    .SYNOPSIS
        The storage key for a domain. One function, so read and write cannot
        disagree.

    .DESCRIPTION
        '*' is the wildcard entry and needs a stable key of its own: naive
        sanitising maps it to '_', which then does not match a lookup for '*'
        and leaves the wildcard silently unreachable.
    #>
    param([Parameter(Mandatory)] [string]$Domain)
    if ($Domain -eq '*') { return '__wildcard__' }
    return ($Domain -replace '[^a-zA-Z0-9_.-]', '_')
}

function Get-DNSProviderConfig {
    <#
    .SYNOPSIS
        The provider configured for a domain, or $null.

    .DESCRIPTION
        Falls back to the wildcard entry '*' when the domain has no entry of
        its own, so an MSP whose whole estate is on one Cloudflare account
        configures it once rather than per domain.
    #>
    param(
        [Parameter(Mandatory)] [string]$WorkingDir,
        [Parameter(Mandatory)] [string]$Domain
    )
    $path = Get-DNSProviderConfigPath -WorkingDir $WorkingDir
    if (-not (Test-Path $path)) { return $null }
    try { $store = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    if (-not $store.PSObject.Properties['providers']) { return $null }

    $key = ConvertTo-ProviderKey -Domain $Domain
    if ($store.providers.PSObject.Properties[$key]) { return $store.providers.$key }
    $wild = ConvertTo-ProviderKey -Domain '*'
    if ($store.providers.PSObject.Properties[$wild]) { return $store.providers.$wild }
    return $null
}

function Get-AllDNSProviderConfigs {
    param([Parameter(Mandatory)] [string]$WorkingDir)
    $path = Get-DNSProviderConfigPath -WorkingDir $WorkingDir
    if (-not (Test-Path $path)) { return @() }
    try { $store = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return @() }
    if (-not $store.PSObject.Properties['providers']) { return @() }
    return @($store.providers.PSObject.Properties | ForEach-Object { $_.Value })
}

function Set-DNSProviderConfig {
    <#
    .SYNOPSIS
        Saves a domain's provider coordinates and stores its credential.

    .DESCRIPTION
        The credential goes to the secret store and only its ref is persisted
        here. On rotation the existing ref is reused, so the config row does
        not churn and the audit trail stays continuous.

        Nothing is written to either store unless BOTH succeed: a config row
        pointing at a secret that was never stored reads as "configured" and
        fails at the provider on every apply.
    #>
    param(
        [Parameter(Mandatory)] [string]$WorkingDir,
        [Parameter(Mandatory)] [string]$Domain,      # '*' for all domains
        [Parameter(Mandatory)] [ValidateSet('cloudflare','azuredns','manual')] [string]$Provider,
        [hashtable]$Coordinates = @{},
        [AllowEmptyString()] [string]$Secret = '',
        [string]$TenantId = 'local',
        [string]$Backend = 'dpapi'
    )

    $path = Get-DNSProviderConfigPath -WorkingDir $WorkingDir
    $dir  = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

    $store = if (Test-Path $path) {
        try { Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { [PSCustomObject]@{ providers = [PSCustomObject]@{} } }
    } else { [PSCustomObject]@{ providers = [PSCustomObject]@{} } }
    if (-not $store.PSObject.Properties['providers']) {
        $store | Add-Member -NotePropertyName providers -NotePropertyValue ([PSCustomObject]@{}) -Force
    }

    $key      = ConvertTo-ProviderKey -Domain $Domain
    $existing = if ($store.providers.PSObject.Properties[$key]) { $store.providers.$key } else { $null }

    # Reuse the existing ref so rotation keeps one identity for this credential.
    $ref = ''
    if ($existing -and $existing.PSObject.Properties['credential_ref'] -and (Test-CredentialRefShape -Ref $existing.credential_ref)) {
        $ref = $existing.credential_ref
    }

    if ($Provider -ne 'manual' -and -not [string]::IsNullOrEmpty($Secret)) {
        if (-not $ref) { $ref = New-CredentialRef -TenantId $TenantId -Purpose $Provider }
        # Throws if the backend is unavailable, before anything is persisted.
        Set-StoredSecret -Ref $ref -Value $Secret -Backend $Backend
    } elseif ($Provider -eq 'manual') {
        $ref = ''
    }

    $store.providers | Add-Member -NotePropertyName $key -NotePropertyValue ([PSCustomObject]@{
        domain         = $Domain
        provider       = $Provider
        config_json    = ($Coordinates | ConvertTo-Json -Compress)
        credential_ref = $ref
        secret_backend = $Backend
        updated_at     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }) -Force

    $tmp = "$path.tmp"
    $store | ConvertTo-Json -Depth 10 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $path -Force
    return $store.providers.$key
}

function Remove-DNSProviderConfig {
    <#
    .SYNOPSIS
        Deletes a domain's provider config AND its stored credential.

    .DESCRIPTION
        The secret goes first. A credential outliving the row that explained
        what it was for is one nobody will ever rotate or revoke.
    #>
    param(
        [Parameter(Mandatory)] [string]$WorkingDir,
        [Parameter(Mandatory)] [string]$Domain,
        [string]$Backend = 'dpapi'
    )
    $path = Get-DNSProviderConfigPath -WorkingDir $WorkingDir
    if (-not (Test-Path $path)) { return }
    try { $store = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return }
    if (-not $store.PSObject.Properties['providers']) { return }

    $key = ConvertTo-ProviderKey -Domain $Domain
    if (-not $store.providers.PSObject.Properties[$key]) { return }

    $entry = $store.providers.$key
    if ($entry.PSObject.Properties['credential_ref'] -and (Test-CredentialRefShape -Ref $entry.credential_ref)) {
        $b = if ($entry.PSObject.Properties['secret_backend'] -and $entry.secret_backend) { $entry.secret_backend } else { $Backend }
        try { Remove-StoredSecret -Ref $entry.credential_ref -Backend $b } catch { }
    }

    $store.providers.PSObject.Properties.Remove($key)
    $tmp = "$path.tmp"
    $store | ConvertTo-Json -Depth 10 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $path -Force
}

function New-DNSProviderFromConfig {
    <#
    .SYNOPSIS
        Turns a stored config into a live provider, or explains why it cannot.

    .DESCRIPTION
        The only bridge between stored configuration and a provider that can
        write. Returns a result object rather than throwing, because "no
        provider configured" is the normal state for a client nobody has
        onboarded and the UI has to say so calmly rather than crash.

        An unconfigured or unusable provider falls back to Manual, never to
        nothing: the operator still gets the exact record to paste. Degrading
        to copy-paste is the correct failure mode for a tool that edits
        production mail routing.
    #>
    param(
        [AllowNull()] $ProviderConfig,
        [string]$Backend = 'dpapi'
    )

    $result = [PSCustomObject]@{
        Provider     = $null
        IsAutomatic  = $false
        Reason       = ''
        ProviderName = 'manual'
    }

    if (-not (Get-Command Resolve-ProviderCredential -ErrorAction SilentlyContinue)) {
        $result.Provider = New-ManualDNSProvider
        $result.Reason   = 'Secret store is unavailable, so changes must be published by hand.'
        return $result
    }

    $cred = Resolve-ProviderCredential -ProviderConfig $ProviderConfig -Backend $Backend
    if ($cred.Provider) { $result.ProviderName = $cred.Provider }

    if (-not $cred.IsConfigured) {
        $result.Provider = New-ManualDNSProvider
        $result.Reason   = $cred.Reason
        return $result
    }

    if ($cred.Provider -eq 'manual') {
        $result.Provider = New-ManualDNSProvider
        $result.Reason   = $cred.Reason
        return $result
    }

    # Splatting needs a plain variable; @(...)[0] is array indexing, not splat.
    $splat = $cred.Arguments
    try {
        switch ($cred.Provider) {
            'cloudflare' { $result.Provider = New-CloudflareDNSProvider @splat }
            'azuredns'   { $result.Provider = New-AzureDNSProvider      @splat }
            default {
                $result.Provider = New-ManualDNSProvider
                $result.Reason   = "Provider '$($cred.Provider)' cannot publish automatically."
                return $result
            }
        }
    } catch {
        $result.Provider = New-ManualDNSProvider
        $result.Reason   = "The $($cred.Provider) provider could not be initialised: $($_.Exception.Message)"
        return $result
    }

    $result.IsAutomatic = $true
    $result.Reason      = "Changes publish through $($cred.Provider) and are verified afterwards."
    return $result
}
#endregion

#region Apply, verify, rollback
function Invoke-DNSChangePlan {
    <#
    .SYNOPSIS
        Applies a plan produced by one of the New-*Plan functions.

    .DESCRIPTION
        The guardrails, in the order they fire:

          1. A plan that is not IsSafe is refused outright. Blockers exist
             because publishing would break something; there is deliberately
             no -Force to override them.
          2. A no-op plan returns without writing. Re-running a remediation
             should be idempotent, not churn the zone.
          3. Without -Confirm nothing is written. The default is a dry run
             that returns exactly what WOULD change, so the caller can show
             a diff and get a human decision.
          4. The live current value is snapshotted immediately before the
             write, not taken from the plan. A plan built ten minutes ago may
             have gone stale, and the snapshot is what rollback restores, so
             it has to reflect reality at the moment of the write.

    .PARAMETER Confirm
        Required to actually write. Absent, this is a dry run.
    #>
    param(
        [Parameter(Mandatory)] [PSCustomObject]$Plan,
        [Parameter(Mandatory)] [PSCustomObject]$Provider,
        [switch]$Confirm,
        [string]$AppliedBy = $env:USERNAME,
        [string]$Reason = ''
    )

    $result = [PSCustomObject]@{
        PlanSummary   = $Plan.Summary
        Domain        = $Plan.Domain
        Name          = $Plan.Name
        RecordType    = $Plan.RecordType
        Applied       = $false
        DryRun        = (-not $Confirm)
        Snapshot      = $null
        NewValue      = $Plan.NewValue
        ProviderName  = $Provider.Name
        RecordId      = ''
        AppliedAt     = ''
        AppliedBy     = $AppliedBy
        Reason        = $Reason
        Error         = ''
        Blockers      = $Plan.Blockers
    }

    if (-not $Plan.IsSafe) {
        $result.Error = "Plan is not safe to apply: $($Plan.Blockers -join '; ')"
        return $result
    }

    if ($Plan.IsNoOp) {
        $result.Error = ''
        $result.PlanSummary = "$($Plan.Summary) (nothing written)"
        return $result
    }

    if (-not $Confirm) {
        # Dry run. Still read the live value so the caller can show a true
        # before/after rather than the possibly-stale one in the plan.
        try {
            $live = & $Provider.GetRecords $Plan.Name $Plan.RecordType
            $result.Snapshot = if ($live -and $live.Count -gt 0) { $live[0].Value } else { $Plan.CurrentValue }
        } catch {
            $result.Snapshot = $Plan.CurrentValue
        }
        return $result
    }

    # Snapshot immediately before writing; this is the rollback target.
    try {
        $live = & $Provider.GetRecords $Plan.Name $Plan.RecordType
        $result.Snapshot = if ($live -and $live.Count -gt 0) { $live[0].Value } else { $Plan.CurrentValue }
    } catch {
        $result.Error = "Could not read the current record before writing: $_"
        return $result
    }

    try {
        $set = & $Provider.SetRecord $Plan.Name $Plan.RecordType $Plan.NewValue 300
        if (-not $set.Success) {
            $result.Error = "Provider refused the write: $($set.Error)"
            return $result
        }
        $result.Applied   = $true
        $result.RecordId  = $set.Id
        $result.AppliedAt = (Get-Date).ToString('o')
    } catch {
        $result.Error = "Write failed: $_"
    }
    return $result
}

function Test-DNSChangePropagation {
    <#
    .SYNOPSIS
        Confirms a published change is actually visible in DNS.

    .DESCRIPTION
        A successful provider API call means the record was accepted, not that
        resolvers are serving it. Without this step an operator marks a client
        remediated while their mail is still failing, which is worse than not
        having applied the change at all.

        -Resolver lets tests supply canned responses; production passes
        Resolve-DnsName.
    #>
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$ExpectedValue,
        [string]$RecordType = 'TXT',
        [int]$TimeoutSeconds = 120,
        [int]$PollSeconds = 10,
        [scriptblock]$Resolver
    )

    $outcome = [PSCustomObject]@{
        Name          = $Name
        Expected      = $ExpectedValue
        Observed      = ''
        IsPropagated  = $false
        Attempts      = 0
        ElapsedSeconds= 0
        Error         = ''
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $started  = Get-Date

    while ((Get-Date) -lt $deadline) {
        $outcome.Attempts++
        try {
            $observed = if ($Resolver) {
                & $Resolver $Name $RecordType
            } else {
                $dns = Resolve-DnsName -Name $Name -Type $RecordType -DnsOnly -EA Stop
                ($dns | Where-Object { $_.Strings } | ForEach-Object { $_.Strings -join '' }) -join "`n"
            }
            $outcome.Observed = [string]$observed
            if ($outcome.Observed -and $outcome.Observed -match [regex]::Escape($ExpectedValue)) {
                $outcome.IsPropagated   = $true
                $outcome.ElapsedSeconds = [int]((Get-Date) - $started).TotalSeconds
                return $outcome
            }
        } catch {
            $outcome.Error = "$_"
        }
        if ((Get-Date).AddSeconds($PollSeconds) -ge $deadline) { break }
        Start-Sleep -Seconds $PollSeconds
    }

    $outcome.ElapsedSeconds = [int]((Get-Date) - $started).TotalSeconds
    if (-not $outcome.Error) {
        $outcome.Error = "Change not visible after $($outcome.ElapsedSeconds)s. TTL on the previous record may still be in effect."
    }
    return $outcome
}

function Undo-DNSChangePlan {
    <#
    .SYNOPSIS
        Restores the snapshot taken before a change was applied.

    .DESCRIPTION
        Takes the result object from Invoke-DNSChangePlan rather than a plan,
        because the snapshot is the only trustworthy record of what was there
        before. Refuses to act on a result that was a dry run or that never
        applied, so a mistaken rollback cannot itself overwrite a good record.
    #>
    param(
        [Parameter(Mandatory)] [PSCustomObject]$AppliedResult,
        [Parameter(Mandatory)] [PSCustomObject]$Provider,
        [switch]$Confirm
    )

    $out = [PSCustomObject]@{
        Domain       = $AppliedResult.Domain
        Name         = $AppliedResult.Name
        RestoredTo   = $AppliedResult.Snapshot
        Restored     = $false
        DryRun       = (-not $Confirm)
        Error        = ''
    }

    if (-not $AppliedResult.Applied) {
        $out.Error = 'Nothing to roll back: this change was never applied'
        return $out
    }
    if ([string]::IsNullOrWhiteSpace([string]$AppliedResult.Snapshot)) {
        $out.Error = 'No snapshot was captured, so the previous value is unknown. Restore manually.'
        return $out
    }
    if (-not $Confirm) { return $out }

    try {
        $set = & $Provider.SetRecord $AppliedResult.Name $AppliedResult.RecordType $AppliedResult.Snapshot 300
        if ($set.Success) { $out.Restored = $true }
        else { $out.Error = "Provider refused the restore: $($set.Error)" }
    } catch { $out.Error = "Restore failed: $_" }
    return $out
}
#endregion

#region Audit trail
function Write-RemediationAudit {
    <#
    .SYNOPSIS
        Appends a change to the remediation audit log.

    .DESCRIPTION
        For an MSP this is not bookkeeping, it is the evidence behind the
        invoice: what was changed for which client, when, by whom, and why.
        It is also what makes an unexplained DNS drift event answerable -
        "was that us?" is the first question after a drift alert.

        Written with the same atomic .tmp + Move-Item pattern the engine uses
        for its other state, so a crash mid-write cannot corrupt the history.
    #>
    param(
        [Parameter(Mandatory)] [string]$StateDir,
        [Parameter(Mandatory)] [PSCustomObject]$AppliedResult,
        [string]$ClientId = '',
        [PSCustomObject]$Propagation
    )

    $file = Join-Path $StateDir 'remediation-audit.json'
    $state = if (Test-Path $file) {
        try { Get-Content $file -Raw | ConvertFrom-Json } catch { [PSCustomObject]@{ changes = @() } }
    } else { [PSCustomObject]@{ changes = @() } }

    $entry = [PSCustomObject]@{
        id           = [guid]::NewGuid().ToString()
        clientId     = $ClientId
        domain       = $AppliedResult.Domain
        recordName   = $AppliedResult.Name
        recordType   = $AppliedResult.RecordType
        previousValue= $AppliedResult.Snapshot
        newValue     = $AppliedResult.NewValue
        provider     = $AppliedResult.ProviderName
        appliedBy    = $AppliedResult.AppliedBy
        appliedAt    = $AppliedResult.AppliedAt
        reason       = $AppliedResult.Reason
        summary      = $AppliedResult.PlanSummary
        propagated   = if ($Propagation) { [bool]$Propagation.IsPropagated } else { $null }
        rolledBack   = $false
    }

    $changes = [System.Collections.Generic.List[object]]::new()
    if ($state.PSObject.Properties.Name -contains 'changes' -and $state.changes) {
        foreach ($c in $state.changes) { $changes.Add($c) }
    }
    $changes.Add($entry)
    # Unlike the drift log this is deliberately uncapped: it is billing
    # evidence and a compliance record, so nothing is silently discarded.

    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $tmp = "$file.tmp"
    ([PSCustomObject]@{ changes = $changes }) | ConvertTo-Json -Depth 10 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $file -Force

    return $entry
}
#endregion

