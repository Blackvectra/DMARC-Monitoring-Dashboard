<#
    Turning a DMARC report into plain English.

    A wrong explanation is worse than a table. A table confuses people, who
    then go and ask someone. A confident, fluent, wrong explanation gets
    believed and acted on: an operator told "this is spoofing" about their own
    invoicing provider will happily enforce and cut off their own invoices.

    So these tests care less about wording and more about the VERDICT: whether
    each case is classified as somebody else's normal behaviour, your own
    misconfiguration, or an actual impersonation attempt.
#>

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-DMARCExplainer.ps1')

    function Row {
        param(
            [int]$Count = 100,
            [string]$DKIM = 'fail', [string]$SPF = 'fail',
            [string]$SPFDomain = '', [string]$DKIMDomain = '',
            [string]$HeaderFrom = 'acme.com', [string]$Domain = 'acme.com',
            [string]$Disposition = 'none', [string]$Override = 'none',
            [string]$Policy = 'none', [string]$IP = '203.0.113.9',
            [string]$ADKIM = 'r', [string]$ASPF = 'r'
        )
        [PSCustomObject]@{
            MessageCount = $Count; DKIMResult = $DKIM; SPFResult = $SPF
            SPFDomain = $SPFDomain; DKIMDomain = $DKIMDomain
            HeaderFrom = $HeaderFrom; Domain = $Domain
            Disposition = $Disposition; OverrideReason = $Override
            Policy = $Policy; SourceIP = $IP; ADKIM = $ADKIM; ASPF = $ASPF
            OrgName = 'google.com'; ReportDate = '2026-03-01'; ReportEnd = '2026-03-02'
            DMARCResult = $(if ($DKIM -eq 'pass' -or $SPF -eq 'pass') { 'pass' } else { 'fail' })
        }
    }
}

Describe 'alignment' {

    It 'accepts an exact match' {
        Test-DomainAligned -AuthDomain 'acme.com' -FromDomain 'acme.com' | Should -BeTrue
    }

    It 'accepts a subdomain under relaxed alignment' {
        Test-DomainAligned -AuthDomain 'mail.acme.com' -FromDomain 'acme.com' -Mode 'r' | Should -BeTrue
    }

    It 'rejects a subdomain under strict alignment' {
        Test-DomainAligned -AuthDomain 'mail.acme.com' -FromDomain 'acme.com' -Mode 's' | Should -BeFalse
    }

    It 'rejects an unrelated domain' {
        Test-DomainAligned -AuthDomain 'sendgrid.net' -FromDomain 'acme.com' | Should -BeFalse
    }

    It 'is not fooled by a domain that merely ends with the same letters' {
        # notacme.com must not align with acme.com.
        Test-DomainAligned -AuthDomain 'notacme.com' -FromDomain 'acme.com' | Should -BeFalse
    }

    It 'ignores case and a trailing dot' {
        Test-DomainAligned -AuthDomain 'ACME.COM.' -FromDomain 'acme.com' | Should -BeTrue
    }

    It 'returns false rather than throwing on missing input' -ForEach @(
        @{ A = $null;      F = 'acme.com' }
        @{ A = 'acme.com'; F = $null }
        @{ A = '';         F = '' }
    ) {
        { Test-DomainAligned -AuthDomain $A -FromDomain $F } | Should -Not -Throw
        Test-DomainAligned -AuthDomain $A -FromDomain $F | Should -BeFalse
    }
}

Describe 'mail that is genuinely fine' {

    It 'calls a fully aligned message fine and asks for no action' {
        $e = Get-SourceExplanation -Record (Row -DKIM 'pass' -SPF 'pass')
        $e.Verdict      | Should -Be 'fine'
        $e.IsActionable | Should -BeFalse
    }

    It 'recognises forwarded mail rescued by DKIM as normal, not a problem' {
        # SPF breaks on forwarding; DKIM survives. This is DMARC working.
        $e = Get-SourceExplanation -Record (Row -DKIM 'pass' -SPF 'fail')
        $e.Verdict      | Should -Be 'fine'
        $e.IsActionable | Should -BeFalse
        $e.WhatHappened | Should -Match 'forwarded'
    }

    It 'does not call a mailing list failure a failure' {
        # A list rewrites the message, authentication breaks, the receiver
        # knows. Reporting this as a problem is why people ignore DMARC.
        $e = Get-SourceExplanation -Record (Row -Override 'mailing_list')
        $e.Verdict      | Should -Be 'fine'
        $e.IsActionable | Should -BeFalse
        $e.WhatToDo     | Should -Match 'Nothing'
    }

    It 'treats a trusted forwarder the same way' {
        (Get-SourceExplanation -Record (Row -Override 'trusted_forwarder')).Verdict | Should -Be 'fine'
    }
}

Describe 'SPF alone, with no DKIM' {

    It 'calls it fragile rather than fine' {
        # It passes today and breaks the first time it is forwarded.
        $e = Get-SourceExplanation -Record (Row -DKIM 'fail' -SPF 'pass')
        $e.Verdict      | Should -Be 'fragile'
        $e.IsActionable | Should -BeTrue
    }

    It 'explains that forwarding will break it' {
        $e = Get-SourceExplanation -Record (Row -DKIM 'fail' -SPF 'pass')
        $e.WhyItMatters | Should -Match 'forwarded'
    }

    It 'tells the operator to enable DKIM' {
        (Get-SourceExplanation -Record (Row -DKIM 'fail' -SPF 'pass')).WhatToDo | Should -Match 'DKIM'
    }
}

Describe 'authenticated, but for the wrong domain' {
    # The case every table-based tool renders as an unexplained contradiction:
    # SPF says pass, DMARC says fail.

    It 'calls it a misconfiguration, not an attack' {
        $e = Get-SourceExplanation -Record (Row -SPFDomain 'bounce.sendgrid.net' -HeaderFrom 'acme.com') -ServiceName 'SendGrid'
        $e.Verdict | Should -Be 'misconfigured'
    }

    It 'names both the domain that authenticated and the one recipients see' {
        $e = Get-SourceExplanation -Record (Row -SPFDomain 'bounce.sendgrid.net' -HeaderFrom 'acme.com') -ServiceName 'SendGrid'
        $e.WhatHappened | Should -Match 'bounce\.sendgrid\.net'
        $e.WhatHappened | Should -Match 'acme\.com'
    }

    It 'explains that the check itself succeeded' {
        # Without this sentence the reader concludes SPF is broken.
        $e = Get-SourceExplanation -Record (Row -SPFDomain 'bounce.sendgrid.net') -ServiceName 'SendGrid'
        $e.WhatHappened | Should -Match 'succeeded|authenticated'
    }

    It 'warns what enforcement will do to this mail' {
        $e = Get-SourceExplanation -Record (Row -SPFDomain 'bounce.sendgrid.net') -ServiceName 'SendGrid'
        $e.WhyItMatters | Should -Match 'junk|refused'
    }

    It 'handles DKIM signing for the wrong domain the same way' {
        $e = Get-SourceExplanation -Record (Row -DKIMDomain 'mailchimp.com' -HeaderFrom 'acme.com') -ServiceName 'Mailchimp'
        $e.Verdict      | Should -Be 'misconfigured'
        $e.WhatHappened | Should -Match 'mailchimp\.com'
    }

    It 'is actionable, because it is the operator who must fix it' {
        (Get-SourceExplanation -Record (Row -SPFDomain 'bounce.sendgrid.net') -ServiceName 'SendGrid').IsActionable | Should -BeTrue
    }
}

Describe 'nothing authenticated at all' {

    It 'calls a recognised service unauthorised rather than suspicious' {
        # Shadow IT, not an attacker. Telling an operator their own invoicing
        # provider is spoofing them is how they enforce and cut off invoices.
        $e = Get-SourceExplanation -Record (Row) -ServiceName 'Zendesk'
        $e.Verdict | Should -Be 'unauthorised'
    }

    It 'asks the operator to confirm ownership before enforcing' {
        $e = Get-SourceExplanation -Record (Row) -ServiceName 'Zendesk'
        $e.WhatToDo | Should -Match 'Confirm'
    }

    It 'calls an unrecognised source suspicious' {
        (Get-SourceExplanation -Record (Row)).Verdict | Should -Be 'suspicious'
    }

    It 'says plainly that nothing was blocked under p=none' {
        $e = Get-SourceExplanation -Record (Row -Policy 'none')
        $e.WhyItMatters | Should -Match 'none of it was blocked'
    }

    It 'says the policy was acted on when enforcing' {
        (Get-SourceExplanation -Record (Row -Policy 'reject')).WhyItMatters | Should -Match 'p=reject'
    }

    It 'distinguishes recognised from unrecognised by verdict, not wording alone' {
        $known   = Get-SourceExplanation -Record (Row) -ServiceName 'Zendesk'
        $unknown = Get-SourceExplanation -Record (Row)
        $known.Verdict | Should -Not -Be $unknown.Verdict
    }
}

Describe 'sampling under pct' {

    It 'reports that no policy was applied at all' {
        $e = Get-SourceExplanation -Record (Row -Override 'sampled_out')
        $e.Verdict      | Should -Be 'not-applied'
        $e.WhatHappened | Should -Match 'pct'
    }

    It 'is actionable, because partial enforcement is a real gap' {
        (Get-SourceExplanation -Record (Row -Override 'sampled_out')).IsActionable | Should -BeTrue
    }
}

Describe 'what the receiver actually did' {
    # "Failed" and "was blocked" are different, and reports say it in one word.

    It 'says refused for a rejection' {
        Get-DispositionExplanation -Disposition 'reject' -Policy 'reject' -MessageCount 50 | Should -Match 'refused'
    }

    It 'says junk for a quarantine' {
        Get-DispositionExplanation -Disposition 'quarantine' -Policy 'quarantine' -MessageCount 50 | Should -Match 'junk'
    }

    It 'says delivered normally under p=none, and explains why' {
        $t = Get-DispositionExplanation -Disposition 'none' -Policy 'none' -MessageCount 50
        $t | Should -Match 'delivered normally'
        $t | Should -Match 'report but not to act'
    }

    It 'explains delivery that happened despite an enforcing policy' {
        Get-DispositionExplanation -Disposition 'none' -Policy 'reject' -MessageCount 50 | Should -Match 'despite the policy'
    }

    It 'gets singular and plural right' {
        Get-DispositionExplanation -Disposition 'reject' -Policy 'reject' -MessageCount 1 | Should -Match '^1 message '
        Get-DispositionExplanation -Disposition 'reject' -Policy 'reject' -MessageCount 2 | Should -Match '^2 messages '
    }

    It 'puts thousands separators in a large count' {
        # "14000 messages" reads as a typo; "14,000" reads as a number.
        Get-DispositionExplanation -Disposition 'reject' -Policy 'reject' -MessageCount 14000 | Should -Match '14,000'
    }
}

Describe 'explaining a whole report' {

    It 'names the reporter, the domain and the window' {
        $r = Get-ReportExplanation -Records @((Row -DKIM 'pass' -SPF 'pass'))
        $r.Summary | Should -Match 'google\.com'
        $r.Summary | Should -Match 'acme\.com'
        $r.Summary | Should -Match '2026-03-01'
    }

    It 'says explicitly that this is one receiver, not the whole picture' {
        # The single most common misreading of a DMARC report.
        $r = Get-ReportExplanation -Records @((Row -DKIM 'pass' -SPF 'pass'))
        $r.Summary | Should -Match "one receiver's view"
    }

    It 'totals messages rather than counting rows' {
        $r = Get-ReportExplanation -Records @((Row -Count 5000 -DKIM 'pass' -SPF 'pass'), (Row -Count 1000))
        $r.TotalMessages | Should -Be 6000
        $r.PassingCount  | Should -Be 5000
        $r.FailingCount  | Should -Be 1000
    }

    It 'orders sources worst first' {
        $r = Get-ReportExplanation -Records @(
            (Row -Count 10 -DKIM 'pass' -SPF 'pass'),
            (Row -Count 10 -IP '198.51.100.1')
        )
        @($r.Sources)[0].Verdict | Should -Be 'suspicious'
    }

    It 'counts only the sources that need action' {
        $r = Get-ReportExplanation -Records @(
            (Row -DKIM 'pass' -SPF 'pass'),
            (Row -Override 'mailing_list'),
            (Row -IP '198.51.100.1')
        )
        $r.ActionCount | Should -Be 1
    }

    It 'says so plainly when nothing needs action' {
        $r = Get-ReportExplanation -Records @((Row -DKIM 'pass' -SPF 'pass'))
        $r.Summary | Should -Match 'Nothing in this report needs action'
    }

    It 'uses a service resolver when given one' {
        $r = Get-ReportExplanation -Records @((Row -SPFDomain 'bounce.sendgrid.net')) -ServiceResolver { param($ip) 'SendGrid' }
        @($r.Sources)[0].Service | Should -Be 'SendGrid'
        @($r.Sources)[0].Headline | Should -Match 'SendGrid'
    }

    It 'survives a resolver that throws' {
        # A catalog lookup failing must not take the explanation down.
        { Get-ReportExplanation -Records @((Row)) -ServiceResolver { throw 'boom' } } | Should -Not -Throw
    }

    It 'explains an empty report rather than producing nothing' {
        $r = Get-ReportExplanation -Records @()
        $r.Summary | Should -Match 'no records'
        $r.TotalMessages | Should -Be 0
    }

    It 'survives null input' {
        { Get-ReportExplanation -Records $null } | Should -Not -Throw
    }

    It 'has passing and failing add up to the total' {
        $r = Get-ReportExplanation -Records @((Row -Count 700 -DKIM 'pass'), (Row -Count 300))
        ($r.PassingCount + $r.FailingCount) | Should -Be $r.TotalMessages
    }
}

Describe 'robustness against real-world reports' {
    # Smaller receivers omit optional elements the big providers always send.

    It 'explains a record with no header_from by falling back to the policy domain' {
        $e = Get-SourceExplanation -Record (Row -HeaderFrom '' -Domain 'acme.com' -DKIM 'pass' -SPF 'pass')
        $e.WhatHappened | Should -Match 'acme\.com'
    }

    It 'survives a record missing every optional field' {
        $bare = [PSCustomObject]@{ MessageCount = 5; SourceIP = '203.0.113.1' }
        { Get-SourceExplanation -Record $bare } | Should -Not -Throw
    }

    It 'survives a null record' {
        { Get-SourceExplanation -Record $null } | Should -Not -Throw
    }

    It 'survives a non-numeric message count' {
        $bad = [PSCustomObject]@{ MessageCount = 'lots'; SourceIP = '203.0.113.1' }
        { Get-SourceExplanation -Record $bad } | Should -Not -Throw
    }

    It 'never leaves an explanation field empty on a real verdict' {
        # A blank "what to do" in a client report is worse than no report.
        foreach ($rec in @(
            (Row -DKIM 'pass' -SPF 'pass'),
            (Row -DKIM 'pass'),
            (Row -SPF 'pass'),
            (Row -SPFDomain 'bounce.sendgrid.net'),
            (Row),
            (Row -Override 'mailing_list'),
            (Row -Override 'sampled_out')
        )) {
            $e = Get-SourceExplanation -Record $rec -ServiceName 'Test Service'
            $e.Headline     | Should -Not -BeNullOrEmpty
            $e.WhatHappened | Should -Not -BeNullOrEmpty
            $e.WhyItMatters | Should -Not -BeNullOrEmpty
            $e.WhatToDo     | Should -Not -BeNullOrEmpty
        }
    }

    It 'gives every verdict a value the caller can rank' {
        $known = @('fine','fragile','misconfigured','unauthorised','suspicious','not-applied')
        foreach ($rec in @((Row -DKIM 'pass' -SPF 'pass'), (Row -SPF 'pass'), (Row), (Row -Override 'sampled_out'))) {
            (Get-SourceExplanation -Record $rec).Verdict | Should -BeIn $known
        }
    }
}
