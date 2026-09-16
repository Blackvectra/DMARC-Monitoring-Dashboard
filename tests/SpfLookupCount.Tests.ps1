<#
    Get-SPFLookupCount — RFC 7208 s4.6.4 lookup accounting.

    Exceeding 10 lookups is a PermError: evaluation stops and mail starts
    failing SPF. So the count is not cosmetic - it decides whether a client
    gets warned that their record is about to break, or doesn't.

    Regression cover for two counters that disagreed with each other:
      - the engine's DNS Health check required a colon/equals after the term,
        so bare 'a' and 'mx' were invisible and 'ptr' was missing entirely.
        A consistent UNDERCOUNT, which reports a broken record as healthy.
      - Invoke-SPFInspector's '^(a|mx|exists)' also matched 'all', charging a
        phantom lookup to every record ending -all. An OVERCOUNT, which fires
        "approaching limit" warnings a lookup early.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $enginePath = Get-EngineScriptPath -FileName 'Invoke-DMARCReporter.ps1'
    . (New-EngineStub)
    . (Import-EngineFunction -ScriptPath $enginePath -FunctionName 'Get-SPFLookupCount')
}

Describe 'Get-SPFLookupCount' {

    Context 'terms that cost a lookup' {
        It 'counts <count> for: <record>' -ForEach @(
            @{ record = 'v=spf1 include:_spf.google.com -all';                          count = 1 }
            @{ record = 'v=spf1 include:a.com include:b.com include:c.com -all';        count = 3 }
            @{ record = 'v=spf1 a -all';                                                count = 1 }
            @{ record = 'v=spf1 mx -all';                                               count = 1 }
            @{ record = 'v=spf1 a mx -all';                                             count = 2 }
            @{ record = 'v=spf1 ptr -all';                                              count = 1 }
            @{ record = 'v=spf1 exists:%{i}._spf.example.com -all';                     count = 1 }
            @{ record = 'v=spf1 redirect=spf.example.com';                              count = 1 }
            @{ record = 'v=spf1 a:mail.example.com -all';                               count = 1 }
            @{ record = 'v=spf1 mx:mx.example.com -all';                                count = 1 }
            @{ record = 'v=spf1 a/24 mx/24 -all';                                       count = 2 }
            @{ record = 'v=spf1 a:mail.example.com/24 -all';                            count = 1 }
        ) {
            Get-SPFLookupCount -SpfRecord $record | Should -Be $count
        }
    }

    Context 'terms that are free' {
        It 'counts 0 for: <record>' -ForEach @(
            @{ record = 'v=spf1 -all' }
            @{ record = 'v=spf1 ~all' }
            @{ record = 'v=spf1 ?all' }
            @{ record = 'v=spf1 +all' }
            @{ record = 'v=spf1 ip4:203.0.113.0/24 -all' }
            @{ record = 'v=spf1 ip6:2001:db8::/32 -all' }
            @{ record = 'v=spf1 ip4:1.2.3.4 ip6:2001:db8::1 -all' }
            @{ record = 'v=spf1 exp=explain.example.com -all' }
        ) {
            Get-SPFLookupCount -SpfRecord $record | Should -Be 0
        }
    }

    Context 'the all mechanism is never a lookup (regression: overcount)' {
        It 'does not charge a lookup for <allForm>' -ForEach @(
            @{ allForm = '-all' }
            @{ allForm = '~all' }
            @{ allForm = '?all' }
            @{ allForm = '+all' }
            @{ allForm = 'all'  }
        ) {
            # '^(a|mx|exists)' matched the leading 'a' of 'all'.
            Get-SPFLookupCount -SpfRecord "v=spf1 ip4:1.2.3.4 $allForm" | Should -Be 0
        }

        It 'counts a record with one include and -all as exactly 1' {
            Get-SPFLookupCount -SpfRecord 'v=spf1 include:_spf.google.com -all' | Should -Be 1
        }
    }

    Context 'bare a and mx are counted (regression: undercount)' {
        It 'counts bare a and mx that carry no colon' {
            # '(a|mx|include|exists|redirect)[:=]' required a delimiter, so
            # these were skipped and the record looked cheaper than it is.
            Get-SPFLookupCount -SpfRecord 'v=spf1 a mx include:_spf.google.com -all' | Should -Be 3
        }

        It 'counts ptr, which was absent from the old term list entirely' {
            Get-SPFLookupCount -SpfRecord 'v=spf1 ptr:example.com -all' | Should -Be 1
        }
    }

    Context 'qualified terms' {
        It 'counts a lookup term regardless of its qualifier' {
            foreach ($q in '+','-','~','?') {
                Get-SPFLookupCount -SpfRecord "v=spf1 ${q}include:a.com -all" | Should -Be 1 -Because "qualifier '$q' should not change the cost"
                Get-SPFLookupCount -SpfRecord "v=spf1 ${q}mx -all"            | Should -Be 1 -Because "qualifier '$q' should not change the cost"
            }
        }
    }

    Context 'realistic records' {
        It 'counts a typical Microsoft 365 record' {
            Get-SPFLookupCount -SpfRecord 'v=spf1 include:spf.protection.outlook.com -all' | Should -Be 1
        }

        It 'counts a record that is genuinely at the limit' {
            $r = 'v=spf1 ' + (1..10 | ForEach-Object { "include:s$_.example.com" }) -join ' '
            $r += ' -all'
            Get-SPFLookupCount -SpfRecord $r | Should -Be 10
        }

        It 'counts a sprawling real-world record over the limit' {
            $r = 'v=spf1 a mx ptr include:_spf.google.com include:sendgrid.net ' +
                 'include:servers.mcsv.net include:mktomail.com include:_spf.salesforce.com ' +
                 'exists:%{i}._spf.example.com redirect=backup.example.com -all'
            # a, mx, ptr, 5 includes, exists, redirect = 10
            Get-SPFLookupCount -SpfRecord $r | Should -Be 10
        }
    }

    Context 'degenerate input' {
        It 'returns 0 for empty, whitespace and null without throwing' {
            Get-SPFLookupCount -SpfRecord ''    | Should -Be 0
            Get-SPFLookupCount -SpfRecord '   ' | Should -Be 0
            Get-SPFLookupCount -SpfRecord $null | Should -Be 0
        }

        It 'does not count the version token' {
            Get-SPFLookupCount -SpfRecord 'v=spf1' | Should -Be 0
        }

        It 'does not match a lookup term embedded inside a hostname' {
            # 'mail.example.com' contains 'a' and 'mx'-ish substrings; only
            # whole terms at a boundary should count.
            Get-SPFLookupCount -SpfRecord 'v=spf1 ip4:1.2.3.4 include:mail.amxample.com -all' | Should -Be 1
        }
    }
}
