<#
    Compare-DNSSnapshot — the DNS drift detector.

    Pure data in, pure data out: no DNS, no network. This is the feature that
    catches a client silently breaking their own SPF at 2am, so the summaries
    need to be specific enough to act on ("-include:mailchimp.com", not
    "SPF changed").
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $enginePath = Get-EngineScriptPath -FileName 'Invoke-DMARCReporter.ps1'
    . (New-EngineStub)
    . (Import-EngineFunction -ScriptPath $enginePath -FunctionName 'Compare-DNSSnapshot')

    function New-Snapshot {
        param(
            [string]$Domain = 'acme.com',
            $Spf = $null, $Dmarc = $null, $MtaSts = $null,
            $Bimi = $null, $TlsRpt = $null, $Mx = $null,
            [string]$At = '2026-09-16T12:00:00Z'
        )
        [PSCustomObject]@{
            domain = $Domain; capturedAt = $At
            spf = $Spf; dmarc = $Dmarc; mtaSts = $MtaSts
            bimi = $Bimi; tlsRpt = $TlsRpt; mx = $Mx
        }
    }
}

Describe 'Compare-DNSSnapshot' {

    Context 'no change' {
        It 'emits nothing when both snapshots are identical' {
            $s = New-Snapshot -Spf 'v=spf1 include:_spf.google.com -all' -Dmarc 'v=DMARC1; p=reject'
            (Compare-DNSSnapshot -Old $s -New $s).Count | Should -Be 0
        }

        It 'emits nothing when both snapshots are entirely empty' {
            $s = New-Snapshot
            (Compare-DNSSnapshot -Old $s -New $s).Count | Should -Be 0
        }
    }

    Context 'SPF include tracking' {
        It 'names the specific include that was added' {
            $old = New-Snapshot -Spf 'v=spf1 include:_spf.google.com -all'
            $new = New-Snapshot -Spf 'v=spf1 include:_spf.google.com include:sendgrid.net -all'
            $d = @(Compare-DNSSnapshot -Old $old -New $new)

            $d.Count            | Should -Be 1
            $d[0].recordType    | Should -Be 'spf'
            $d[0].summary       | Should -Match '\+include:sendgrid\.net'
        }

        It 'names the specific include that was removed' {
            $old = New-Snapshot -Spf 'v=spf1 include:_spf.google.com include:mailchimp.com -all'
            $new = New-Snapshot -Spf 'v=spf1 include:_spf.google.com -all'
            $d = @(Compare-DNSSnapshot -Old $old -New $new)

            $d.Count      | Should -Be 1
            $d[0].summary | Should -Match '-include:mailchimp\.com'
        }

        It 'reports both sides when one include is swapped for another' {
            $old = New-Snapshot -Spf 'v=spf1 include:old.example -all'
            $new = New-Snapshot -Spf 'v=spf1 include:new.example -all'
            $d = @(Compare-DNSSnapshot -Old $old -New $new)

            $d[0].summary | Should -Match '-include:old\.example'
            $d[0].summary | Should -Match '\+include:new\.example'
        }

        It 'reports an added record when SPF appears for the first time' {
            $d = @(Compare-DNSSnapshot -Old (New-Snapshot) -New (New-Snapshot -Spf 'v=spf1 -all'))
            $d[0].summary | Should -Be 'SPF added'
        }

        It 'reports a removed record when SPF disappears' {
            # An SPF record vanishing is a mail-delivery emergency, so this one
            # has to be unmissable rather than folded into a generic "changed".
            $d = @(Compare-DNSSnapshot -Old (New-Snapshot -Spf 'v=spf1 -all') -New (New-Snapshot))
            $d[0].summary | Should -Be 'SPF removed'
        }

        It 'still reports a change when the all-mechanism is weakened' {
            $old = New-Snapshot -Spf 'v=spf1 include:a.example -all'
            $new = New-Snapshot -Spf 'v=spf1 include:a.example ~all'
            $d = @(Compare-DNSSnapshot -Old $old -New $new)
            $d.Count         | Should -Be 1
            $d[0].recordType | Should -Be 'spf'
        }
    }

    Context 'DMARC policy tracking' {
        It 'surfaces a policy transition inline' {
            $old = New-Snapshot -Dmarc 'v=DMARC1; p=none; rua=mailto:r@acme.com'
            $new = New-Snapshot -Dmarc 'v=DMARC1; p=quarantine; rua=mailto:r@acme.com'
            $d = @(Compare-DNSSnapshot -Old $old -New $new)

            $d[0].recordType | Should -Be 'dmarc'
            $d[0].summary    | Should -Be 'DMARC policy: none -> quarantine'
        }

        It 'surfaces a policy downgrade, which is the one that matters most' {
            $old = New-Snapshot -Dmarc 'v=DMARC1; p=reject'
            $new = New-Snapshot -Dmarc 'v=DMARC1; p=none'
            (@(Compare-DNSSnapshot -Old $old -New $new))[0].summary | Should -Be 'DMARC policy: reject -> none'
        }

        It 'surfaces a pct rollback when the policy itself is unchanged' {
            $old = New-Snapshot -Dmarc 'v=DMARC1; p=quarantine; rua=mailto:r@acme.com'
            $new = New-Snapshot -Dmarc 'v=DMARC1; p=quarantine; pct=10; rua=mailto:r@acme.com'
            (@(Compare-DNSSnapshot -Old $old -New $new))[0].summary | Should -Match 'pct: 100 -> 10'
        }

        It 'treats an absent pct as 100 rather than as missing' {
            $old = New-Snapshot -Dmarc 'v=DMARC1; p=reject; pct=100'
            $new = New-Snapshot -Dmarc 'v=DMARC1; p=reject'
            # Same effective policy, but the raw text differs, so a change is
            # still reported - just not as a pct transition.
            $d = @(Compare-DNSSnapshot -Old $old -New $new)
            $d[0].summary | Should -Not -Match 'pct: 100 -> 100'
        }

        It 'reports a removed record when DMARC disappears' {
            $d = @(Compare-DNSSnapshot -Old (New-Snapshot -Dmarc 'v=DMARC1; p=reject') -New (New-Snapshot))
            $d[0].summary | Should -Be 'DMARC removed'
        }
    }

    Context 'other record types' {
        It 'detects an <label> change' -ForEach @(
            @{ label = 'MTA-STS'; field = 'MtaSts'; type = 'mta-sts'; old = 'v=STSv1; id=1'; new = 'v=STSv1; id=2' }
            @{ label = 'BIMI';    field = 'Bimi';   type = 'bimi';    old = 'v=BIMI1; l=https://a/l.svg'; new = 'v=BIMI1; l=https://b/l.svg' }
            @{ label = 'TLS-RPT'; field = 'TlsRpt'; type = 'tls-rpt'; old = 'v=TLSRPTv1; rua=mailto:a@x'; new = 'v=TLSRPTv1; rua=mailto:b@x' }
            @{ label = 'MX';      field = 'Mx';     type = 'mx';      old = '10 mx1.acme.com'; new = '10 acme-com.mail.protection.outlook.com' }
        ) {
            $oldArgs = @{ $field = $old }
            $newArgs = @{ $field = $new }
            $d = @(Compare-DNSSnapshot -Old (New-Snapshot @oldArgs) -New (New-Snapshot @newArgs))

            $d.Count         | Should -Be 1
            $d[0].recordType | Should -Be $type
        }

        It 'flags an MX migration to Microsoft 365' {
            $old = New-Snapshot -Mx '10 mx1.acme.com | 20 mx2.acme.com'
            $new = New-Snapshot -Mx '0 acme-com.mail.protection.outlook.com'
            $d = @(Compare-DNSSnapshot -Old $old -New $new)
            $d[0].recordType | Should -Be 'mx'
            $d[0].oldValue   | Should -Match 'mx1\.acme\.com'
            $d[0].newValue   | Should -Match 'protection\.outlook\.com'
        }
    }

    Context 'multiple simultaneous changes' {
        It 'emits one event per changed record type' {
            $old = New-Snapshot -Spf 'v=spf1 -all'      -Dmarc 'v=DMARC1; p=none'  -Mx '10 old.example'
            $new = New-Snapshot -Spf 'v=spf1 ~all'      -Dmarc 'v=DMARC1; p=reject' -Mx '10 new.example'
            $d = @(Compare-DNSSnapshot -Old $old -New $new)

            $d.Count | Should -Be 3
            ($d.recordType | Sort-Object) | Should -Be @('dmarc','mx','spf')
        }
    }

    Context 'event shape' {
        It 'carries domain, type, both values, a timestamp and a summary' {
            $old = New-Snapshot -Domain 'globex.com' -Spf 'v=spf1 -all'
            $new = New-Snapshot -Domain 'globex.com' -Spf 'v=spf1 ~all' -At '2026-09-16T13:00:00Z'
            $e = (@(Compare-DNSSnapshot -Old $old -New $new))[0]

            $e.domain     | Should -Be 'globex.com'
            $e.recordType | Should -Be 'spf'
            $e.oldValue   | Should -Be 'v=spf1 -all'
            $e.newValue   | Should -Be 'v=spf1 ~all'
            $e.detectedAt | Should -Be '2026-09-16T13:00:00Z'
            $e.summary    | Should -Not -BeNullOrEmpty
        }

        It 'takes the timestamp from the new snapshot, not the old one' {
            # The event records when the change was OBSERVED. Using the old
            # snapshot's time would backdate every drift event to the previous
            # successful poll.
            $old = New-Snapshot -Spf 'v=spf1 -all' -At '2026-09-01T00:00:00Z'
            $new = New-Snapshot -Spf 'v=spf1 ~all' -At '2026-09-16T12:00:00Z'
            (@(Compare-DNSSnapshot -Old $old -New $new))[0].detectedAt | Should -Be '2026-09-16T12:00:00Z'
        }
    }
}
