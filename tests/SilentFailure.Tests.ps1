<#
    Silent-failure detection — configurations that are published, parse fine,
    and do nothing.

    These are not syntax errors. Every case here passes a "does the record
    exist" check, renders correctly in a dashboard, and quietly fails to do
    its job. That is what makes them worth detecting: nothing else reports
    them, including the vendors whose own customers are affected.

    The headline case is taken from a real live record found during
    competitive research, not invented.
#>

BeforeAll {
    $script:RemediationScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-DNSRemediation.ps1'
    . $script:RemediationScript

    # Verifier stubs for RFC 7489 s7.1 external destination authorisation.
    $script:AlwaysAuthorized = { param($policyDomain, $externalDomain) $true }
    $script:NeverAuthorized  = { param($policyDomain, $externalDomain) $false }

    function Get-Codes { param($Findings) return @($Findings | ForEach-Object { $_.Code }) }
}

Describe 'Test-SPFSilentFailure' {

    Context 'redirect= neutered by all (the real-world case)' {
        It 'detects the exact record found live on a commercial vendor customer' {
            # dcdt.gov.za, a Sendmarc customer. RFC 7208 s6.1: a present 'all'
            # means the redirect MUST be ignored, so the vendor's hosted
            # record is never consulted. The customer is paying for managed
            # SPF that does nothing.
            $rec = 'v=spf1 redirect=_sthfx389v.sdmarc.net ip4:41.121.57.146 include:spf.protection.outlook.com -all'
            $f = Test-SPFSilentFailure -Domain 'dcdt.gov.za' -SpfRecords @($rec)

            Get-Codes $f | Should -Contain 'SPF_REDIRECT_NEUTERED_BY_ALL'
            ($f | Where-Object Code -eq 'SPF_REDIRECT_NEUTERED_BY_ALL').Severity | Should -Be 'critical'
        }

        It 'cites the clause that makes it a failure rather than an opinion' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 redirect=a.example -all')
            ($f | Where-Object Code -eq 'SPF_REDIRECT_NEUTERED_BY_ALL').Reference | Should -Match '7208'
        }

        It 'names the redirect target that is being ignored' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 redirect=_spf.vendor.example ~all')
            ($f | Where-Object Code -eq 'SPF_REDIRECT_NEUTERED_BY_ALL').Detail | Should -Match '_spf\.vendor\.example'
        }

        It 'does not fire when redirect is used correctly, with no all' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 redirect=_spf.vendor.example')
            Get-Codes $f | Should -Not -Contain 'SPF_REDIRECT_NEUTERED_BY_ALL'
        }

        It 'fires regardless of which qualifier the all carries' {
            foreach ($a in '-all','~all','?all','+all') {
                $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @("v=spf1 redirect=a.example $a")
                Get-Codes $f | Should -Contain 'SPF_REDIRECT_NEUTERED_BY_ALL' -Because "'$a' still neuters redirect"
            }
        }
    }

    Context 'multiple SPF records' {
        It 'flags two records as a permanent error, not a first-wins' {
            # A second service onboarding by ADDING a record rather than
            # editing is the usual cause. Result is permerror: SPF fails for
            # every message, including legitimate ones.
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @(
                'v=spf1 include:_spf.google.com -all',
                'v=spf1 include:sendgrid.net -all')
            Get-Codes $f | Should -Contain 'SPF_MULTIPLE_RECORDS'
            ($f | Where-Object Code -eq 'SPF_MULTIPLE_RECORDS').Severity | Should -Be 'critical'
        }

        It 'shows both records as evidence so the operator can merge them' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 include:a -all','v=spf1 include:b -all')
            $ev = ($f | Where-Object Code -eq 'SPF_MULTIPLE_RECORDS').Evidence
            $ev | Should -Match 'include:a'
            $ev | Should -Match 'include:b'
        }
    }

    Context 'lookup limit' {
        It 'flags exceeding the cap as critical, because the whole record permerrors' {
            $rec = 'v=spf1 ' + ((1..11 | ForEach-Object { "include:s$_.example" }) -join ' ') + ' -all'
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @($rec)
            Get-Codes $f | Should -Contain 'SPF_LOOKUP_LIMIT_EXCEEDED'
            ($f | Where-Object Code -eq 'SPF_LOOKUP_LIMIT_EXCEEDED').Severity | Should -Be 'critical'
        }

        It 'warns at exactly the cap, where the next sender breaks it' {
            $rec = 'v=spf1 ' + ((1..10 | ForEach-Object { "include:s$_.example" }) -join ' ') + ' -all'
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @($rec)
            Get-Codes $f | Should -Contain 'SPF_LOOKUP_LIMIT_REACHED'
        }

        It 'stays quiet comfortably under the cap' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 include:a.example -all')
            Get-Codes $f | Should -Not -Contain 'SPF_LOOKUP_LIMIT_EXCEEDED'
            Get-Codes $f | Should -Not -Contain 'SPF_LOOKUP_LIMIT_REACHED'
        }
    }

    Context 'mechanisms that defeat the record' {
        It 'flags +all as authorizing the entire internet' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 include:a.example +all')
            Get-Codes $f | Should -Contain 'SPF_PLUS_ALL'
            ($f | Where-Object Code -eq 'SPF_PLUS_ALL').Severity | Should -Be 'critical'
        }

        It 'flags terms after all as unreachable and names them' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 -all include:orphan.example ip4:1.2.3.4')
            Get-Codes $f | Should -Contain 'SPF_TERMS_AFTER_ALL'
            ($f | Where-Object Code -eq 'SPF_TERMS_AFTER_ALL').Detail | Should -Match 'orphan\.example'
        }

        It 'flags a record with neither all nor redirect as neutral, not deny' {
            # Operators routinely read a bare list of includes as default-deny.
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 include:a.example ip4:1.2.3.4')
            Get-Codes $f | Should -Contain 'SPF_NO_TERMINAL'
        }

        It 'flags the deprecated ptr mechanism' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 ptr -all')
            Get-Codes $f | Should -Contain 'SPF_PTR_DEPRECATED'
        }
    }

    Context 'absent and malformed' {
        It 'flags a missing record' {
            Get-Codes (Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @()) | Should -Contain 'SPF_MISSING'
        }

        It 'flags an unparseable record rather than throwing' {
            { Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('not spf at all') } | Should -Not -Throw
            Get-Codes (Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('not spf at all')) | Should -Contain 'SPF_UNPARSEABLE'
        }
    }

    Context 'a correct record produces no findings' {
        It 'stays silent on a clean, enforcing, in-budget record' {
            $f = Test-SPFSilentFailure -Domain 'x.com' -SpfRecords @('v=spf1 include:_spf.google.com include:sendgrid.net -all')
            $f.Count | Should -Be 0 -Because "a correct record must not generate noise: $(Get-Codes $f -join ', ')"
        }
    }
}

Describe 'Test-DMARCSilentFailure' {

    Context 'external reporting destination (RFC 7489 s7.1)' {
        It 'flags reports silently discarded when the destination has not authorised them' {
            # This is the failure mode with no error anywhere: the DMARC record
            # is valid, receivers refuse to send because the authorisation
            # record is missing, and the operator just never gets data.
            $f = Test-DMARCSilentFailure -Domain 'acme.com' `
                    -DmarcRecords @('v=DMARC1; p=reject; rua=mailto:dmarc@msp.example') `
                    -ReportDomainVerifier $script:NeverAuthorized
            Get-Codes $f | Should -Contain 'DMARC_RUA_EXTERNAL_UNAUTHORIZED'
            ($f | Where-Object Code -eq 'DMARC_RUA_EXTERNAL_UNAUTHORIZED').Severity | Should -Be 'critical'
        }

        It 'gives the exact record to publish, in the right zone' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' `
                    -DmarcRecords @('v=DMARC1; p=none; rua=mailto:d@msp.example') `
                    -ReportDomainVerifier $script:NeverAuthorized
            $rem = ($f | Where-Object Code -eq 'DMARC_RUA_EXTERNAL_UNAUTHORIZED').Remediation
            $rem | Should -Match 'acme\.com\._report\._dmarc\.msp\.example'
            $rem | Should -Match 'v=DMARC1'
        }

        It 'stays quiet when the destination HAS authorised reports' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' `
                    -DmarcRecords @('v=DMARC1; p=reject; rua=mailto:d@msp.example') `
                    -ReportDomainVerifier $script:AlwaysAuthorized
            Get-Codes $f | Should -Not -Contain 'DMARC_RUA_EXTERNAL_UNAUTHORIZED'
        }

        It 'does not require authorisation for a same-domain destination' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' `
                    -DmarcRecords @('v=DMARC1; p=reject; rua=mailto:dmarc@acme.com') `
                    -ReportDomainVerifier $script:NeverAuthorized
            Get-Codes $f | Should -Not -Contain 'DMARC_RUA_EXTERNAL_UNAUTHORIZED'
        }

        It 'treats a subdomain destination as internal' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' `
                    -DmarcRecords @('v=DMARC1; p=reject; rua=mailto:d@reports.acme.com') `
                    -ReportDomainVerifier $script:NeverAuthorized
            Get-Codes $f | Should -Not -Contain 'DMARC_RUA_EXTERNAL_UNAUTHORIZED'
        }

        It 'reports the check as unverified rather than skipping it silently' {
            # Absent a verifier the honest answer is "not checked", not "fine".
            $f = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; p=none; rua=mailto:d@msp.example')
            Get-Codes $f | Should -Contain 'DMARC_RUA_EXTERNAL_UNVERIFIED'
        }

        It 'checks every destination when several are listed' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' `
                    -DmarcRecords @('v=DMARC1; p=none; rua=mailto:a@one.example,mailto:b@two.example') `
                    -ReportDomainVerifier $script:NeverAuthorized
            @($f | Where-Object Code -eq 'DMARC_RUA_EXTERNAL_UNAUTHORIZED').Count | Should -Be 2
        }
    }

    Context 'multiple DMARC records' {
        It 'flags that DMARC is not applied AT ALL, rather than first-wins' {
            # RFC 7489 s6.6.3 abandons processing entirely. The domain looks
            # protected and is completely unprotected.
            $f = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @(
                'v=DMARC1; p=reject; rua=mailto:a@acme.com',
                'v=DMARC1; p=none')
            Get-Codes $f | Should -Contain 'DMARC_MULTIPLE_RECORDS'
            ($f | Where-Object Code -eq 'DMARC_MULTIPLE_RECORDS').Severity | Should -Be 'critical'
            ($f | Where-Object Code -eq 'DMARC_MULTIPLE_RECORDS').Detail | Should -Match 'not applied|abandon'
        }
    }

    Context 'policies that look like enforcement and are not' {
        It 'flags pct=0 as applying to no messages' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; p=reject; pct=0; rua=mailto:a@acme.com')
            Get-Codes $f | Should -Contain 'DMARC_PCT_ZERO'
            ($f | Where-Object Code -eq 'DMARC_PCT_ZERO').Detail | Should -Match 'p=none'
        }

        It 'flags a partial pct under an enforcing policy' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; p=reject; pct=25; rua=mailto:a@acme.com')
            Get-Codes $f | Should -Contain 'DMARC_PCT_PARTIAL'
        }

        It 'flags sp=none under an enforcing policy as leaving subdomains open' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; p=reject; sp=none; rua=mailto:a@acme.com')
            Get-Codes $f | Should -Contain 'DMARC_SUBDOMAIN_UNPROTECTED'
            ($f | Where-Object Code -eq 'DMARC_SUBDOMAIN_UNPROTECTED').Severity | Should -Be 'high'
        }

        It 'does not flag sp=none when the parent is only p=none anyway' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; p=none; sp=none; rua=mailto:a@acme.com')
            Get-Codes $f | Should -Not -Contain 'DMARC_SUBDOMAIN_UNPROTECTED'
        }
    }

    Context 'reporting' {
        It 'raises severity for no rua under an enforcing policy' {
            $enforcing = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; p=reject')
            $monitor   = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; p=none')
            ($enforcing | Where-Object Code -eq 'DMARC_NO_RUA').Severity | Should -Be 'high'
            ($monitor   | Where-Object Code -eq 'DMARC_NO_RUA').Severity | Should -Be 'medium'
        }

        It 'flags a rua entry that is not a mailto URI' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; p=none; rua=dmarc@acme.com')
            Get-Codes $f | Should -Contain 'DMARC_RUA_NOT_MAILTO'
        }
    }

    Context 'absent and malformed' {
        It 'flags a missing record' {
            Get-Codes (Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @()) | Should -Contain 'DMARC_MISSING'
        }

        It 'flags a record that does not begin with v=DMARC1' {
            Get-Codes (Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('p=reject; rua=mailto:a@acme.com')) |
                Should -Contain 'DMARC_BAD_VERSION'
        }

        It 'flags a missing p= tag' {
            Get-Codes (Test-DMARCSilentFailure -Domain 'acme.com' -DmarcRecords @('v=DMARC1; rua=mailto:a@acme.com')) |
                Should -Contain 'DMARC_NO_POLICY'
        }
    }

    Context 'a correct record produces no findings' {
        It 'stays silent on a fully-enforcing, self-reporting record' {
            $f = Test-DMARCSilentFailure -Domain 'acme.com' `
                    -DmarcRecords @('v=DMARC1; p=reject; rua=mailto:dmarc@acme.com') `
                    -ReportDomainVerifier $script:AlwaysAuthorized
            $f.Count | Should -Be 0 -Because "a correct record must not generate noise: $(Get-Codes $f -join ', ')"
        }
    }
}

Describe 'Test-AuthenticationSilentFailures' {

    It 'combines SPF and DMARC findings for one domain' {
        $r = Test-AuthenticationSilentFailures -Domain 'acme.com' `
                -SpfRecords @('v=spf1 redirect=a.example -all') `
                -DmarcRecords @('v=DMARC1; p=reject; pct=0') `
                -ReportDomainVerifier $script:AlwaysAuthorized
        Get-Codes $r.Findings | Should -Contain 'SPF_REDIRECT_NEUTERED_BY_ALL'
        Get-Codes $r.Findings | Should -Contain 'DMARC_PCT_ZERO'
    }

    It 'orders findings by severity so the worst is first' {
        $r = Test-AuthenticationSilentFailures -Domain 'acme.com' `
                -SpfRecords @('v=spf1 ptr redirect=a.example -all') `
                -DmarcRecords @('v=DMARC1; p=reject; rua=mailto:a@acme.com') `
                -ReportDomainVerifier $script:AlwaysAuthorized
        $r.Findings[0].Severity | Should -Be 'critical'
    }

    It 'marks a domain silently broken when any critical finding exists' {
        $r = Test-AuthenticationSilentFailures -Domain 'acme.com' `
                -SpfRecords @('v=spf1 redirect=a.example -all') `
                -DmarcRecords @('v=DMARC1; p=reject; rua=mailto:a@acme.com') `
                -ReportDomainVerifier $script:AlwaysAuthorized
        $r.IsSilentlyBroken | Should -BeTrue
        $r.CriticalCount    | Should -BeGreaterThan 0
    }

    It 'reports a correctly configured domain as not broken, with zero findings' {
        $r = Test-AuthenticationSilentFailures -Domain 'acme.com' `
                -SpfRecords @('v=spf1 include:_spf.google.com -all') `
                -DmarcRecords @('v=DMARC1; p=reject; rua=mailto:dmarc@acme.com') `
                -ReportDomainVerifier $script:AlwaysAuthorized
        $r.IsSilentlyBroken | Should -BeFalse
        $r.TotalCount       | Should -Be 0
    }

    It 'runs on a domain that has been onboarded to nothing' {
        # Needs only published DNS, so it works as a pre-sales check against
        # a prospect's domain.
        { Test-AuthenticationSilentFailures -Domain 'stranger.example' } | Should -Not -Throw
        $r = Test-AuthenticationSilentFailures -Domain 'stranger.example'
        $r.TotalCount | Should -BeGreaterThan 0 -Because 'a domain with no SPF and no DMARC has findings'
    }

    It 'gives every finding a severity, code, title, detail and reference' {
        $r = Test-AuthenticationSilentFailures -Domain 'acme.com' `
                -SpfRecords @('v=spf1 redirect=a.example +all') `
                -DmarcRecords @('v=DMARC1; pct=0')
        foreach ($f in $r.Findings) {
            $f.Severity  | Should -Not -BeNullOrEmpty
            $f.Code      | Should -Not -BeNullOrEmpty
            $f.Title     | Should -Not -BeNullOrEmpty
            $f.Detail    | Should -Not -BeNullOrEmpty
            $f.Reference | Should -Not -BeNullOrEmpty -Because "finding $($f.Code) must cite the clause that makes it a failure"
        }
    }
}
