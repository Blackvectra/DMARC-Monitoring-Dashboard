<#
    The figures and findings that go in front of a paying client.

    A wrong number here is worse than a crash. A crash gets noticed; a report
    that quietly overstates how much mail was protected gets sent, believed,
    and eventually contradicted by the client's own mail team.
#>

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-ClientReporting.ps1')

    function Rec {
        param([int]$Count, [string]$Result = 'pass', [string]$IP = '1.2.3.4', [string]$Domain = 'acme.com')
        [PSCustomObject]@{ MessageCount = $Count; DMARCResult = $Result; SourceIP = $IP; Domain = $Domain }
    }

    # Must live here, not at Describe level: a function declared in a Describe
    # body exists at discovery time but not when the test actually runs.
    function AddHealth {
        param([string]$Domain, [hashtable]$Props)
        $key = $Domain -replace '[^a-zA-Z0-9_]', '_'
        $script:Health | Add-Member -NotePropertyName $key -NotePropertyValue ([PSCustomObject]$Props) -Force
    }
}

Describe 'Measure-DMARCRecordSet' {

    It 'sums MessageCount rather than counting rows' {
        # One row routinely stands for thousands of messages. Counting rows
        # would report 2 messages protected instead of 6000.
        $m = Measure-DMARCRecordSet -Records @((Rec 5000), (Rec 1000))
        $m.Messages | Should -Be 6000
    }

    It 'splits passing from failing by DMARC result' {
        $m = Measure-DMARCRecordSet -Records @((Rec 900 'pass'), (Rec 100 'fail'))
        $m.Passing | Should -Be 900
        $m.Failing | Should -Be 100
        $m.PassRate | Should -Be 90.0
    }

    It 'treats anything that is not a pass as a failure' -ForEach @(
        @{ Result = 'fail' }
        @{ Result = 'FAIL' }
        @{ Result = '' }
        @{ Result = 'unknown' }
    ) {
        # Counting a blank or unrecognised result as a pass would inflate the
        # headline figure, which is the number a client repeats back.
        $m = Measure-DMARCRecordSet -Records @((Rec 100 $Result))
        $m.Failing | Should -Be 100
    }

    It 'is case-insensitive about a genuine pass' {
        (Measure-DMARCRecordSet -Records @((Rec 100 'PASS'))).Passing | Should -Be 100
        (Measure-DMARCRecordSet -Records @((Rec 100 ' pass '))).Passing | Should -Be 100
    }

    It 'counts distinct sending sources, not rows' {
        $m = Measure-DMARCRecordSet -Records @((Rec 10 'pass' '1.1.1.1'), (Rec 10 'pass' '1.1.1.1'), (Rec 10 'pass' '2.2.2.2'))
        $m.SourceCount | Should -Be 2
    }

    It 'counts distinct domains' {
        $m = Measure-DMARCRecordSet -Records @((Rec 10 'pass' '1.1.1.1' 'acme.com'), (Rec 10 'pass' '2.2.2.2' 'acme.net'))
        $m.DomainCount | Should -Be 2
    }

    It 'returns zeroes rather than dividing by zero on an empty set' -ForEach @(
        @{ Set = @() }
        @{ Set = $null }
    ) {
        $m = Measure-DMARCRecordSet -Records $Set
        $m.Messages | Should -Be 0
        $m.PassRate | Should -Be 0
    }

    It 'survives a row with a non-numeric count' {
        # A truncated CSV should not take the month's report down.
        $bad = [PSCustomObject]@{ MessageCount = 'many'; DMARCResult = 'pass'; SourceIP = '1.1.1.1'; Domain = 'acme.com' }
        { Measure-DMARCRecordSet -Records @($bad) } | Should -Not -Throw
        (Measure-DMARCRecordSet -Records @($bad, (Rec 100))).Messages | Should -Be 100
    }

    It 'refuses to let a negative count subtract from the total' {
        $neg = [PSCustomObject]@{ MessageCount = -500; DMARCResult = 'pass'; SourceIP = '1.1.1.1'; Domain = 'acme.com' }
        (Measure-DMARCRecordSet -Records @($neg, (Rec 100))).Messages | Should -Be 100
    }

    It 'never reports a pass rate above 100' {
        $m = Measure-DMARCRecordSet -Records @((Rec 1000 'pass'))
        $m.PassRate | Should -BeLessOrEqual 100
    }

    It 'has passing and failing add up to the total' {
        $m = Measure-DMARCRecordSet -Records @((Rec 777 'pass'), (Rec 223 'fail'), (Rec 1 'unknown'))
        ($m.Passing + $m.Failing) | Should -Be $m.Messages
    }
}

Describe 'Get-ChangeDescription' {

    It 'calls a rise in pass rate good' {
        $c = Get-ChangeDescription -Current 95 -Previous 90 -HigherIsBetter
        $c.Direction | Should -Be 'up'
        $c.IsGood    | Should -BeTrue
    }

    It 'calls a rise in failures bad' {
        # The same direction means the opposite thing depending on the metric.
        $c = Get-ChangeDescription -Current 500 -Previous 100
        $c.Direction | Should -Be 'up'
        $c.IsGood    | Should -BeFalse
    }

    It 'calls a fall in failures good' {
        (Get-ChangeDescription -Current 100 -Previous 500).IsGood | Should -BeTrue
    }

    It 'reports no change as flat' {
        $c = Get-ChangeDescription -Current 90 -Previous 90 -HigherIsBetter
        $c.Direction | Should -Be 'flat'
        $c.Text      | Should -Match 'unchanged'
    }

    It 'refuses to quote a percentage change from a zero baseline' {
        # Dividing by a zero previous period is how a report ends up claiming
        # an infinite improvement.
        $c = Get-ChangeDescription -Current 500 -Previous 0
        { $c.Text } | Should -Not -Throw
        $c.PercentText | Should -BeNullOrEmpty
        $c.Text | Should -Match 'none in the previous period'
    }

    It 'handles both sides being zero' {
        $c = Get-ChangeDescription -Current 0 -Previous 0
        $c.Direction | Should -Be 'flat'
    }

    It 'computes the percentage correctly' {
        (Get-ChangeDescription -Current 150 -Previous 100).PercentText | Should -Be '50%'
        (Get-ChangeDescription -Current 50  -Previous 100).PercentText | Should -Be '50%'
    }

    It 'states the absolute change as a positive number in both directions' {
        # "down -400" reads as an increase.
        (Get-ChangeDescription -Current 100 -Previous 500).Text | Should -Not -Match '-\d'
    }
}

Describe 'Get-ClientReportFindings' {

    BeforeEach {
        $script:Health = [PSCustomObject]@{}
        $script:Prog   = [PSCustomObject]@{}
        $script:Inv    = [PSCustomObject]@{}
    }

    It 'returns an empty, countable list when nothing is wrong' {
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='reject'; SPFLookups=3; SilentCriticalCodes=@() }
        $f = Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com')
        { @($f).Count } | Should -Not -Throw
        @($f | Where-Object Severity -in @('critical','high','medium')).Count | Should -Be 0
    }

    It 'leads with a silently-inert record' {
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='reject'; SPFLookups=3; SilentCriticalCodes=@('SPF_REDIRECT_NEUTERED_BY_ALL') }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        $f[0].Severity | Should -Be 'critical'
        $f[0].Title    | Should -Match 'not taking effect'
    }

    It 'explains that a silent failure is found by inspection, not reported' {
        # This is the differentiator; the report should say so plainly.
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='reject'; SPFLookups=3; SilentCriticalCodes=@('SPF_PLUS_ALL') }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        $f[0].Detail | Should -Match 'look healthy in any checker'
    }

    It 'treats an over-limit SPF record as critical' {
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='reject'; SPFLookups=11; SilentCriticalCodes=@() }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        ($f | Where-Object { $_.Title -match 'exceeded its lookup limit' }).Severity | Should -Be 'critical'
    }

    It 'warns before the limit is hit, not after' {
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='reject'; SPFLookups=8; SilentCriticalCodes=@() }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        ($f | Where-Object { $_.Title -match 'close to its lookup limit' }).Severity | Should -Be 'high'
    }

    It 'says nothing about lookups on a comfortable record' {
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='reject'; SPFLookups=4; SilentCriticalCodes=@() }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        @($f | Where-Object { $_.Title -match 'lookup limit' }).Count | Should -Be 0
    }

    It 'flags a missing DMARC policy as critical' {
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='missing'; SPFLookups=2; SilentCriticalCodes=@() }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        ($f | Where-Object { $_.Title -match 'No DMARC policy' }).Severity | Should -Be 'critical'
    }

    It 'frames p=none as monitoring rather than protection' {
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='none'; SPFLookups=2; SilentCriticalCodes=@() }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        ($f | Where-Object { $_.Title -match 'monitoring only' }).Detail | Should -Match 'nothing is being blocked'
    }

    It 'gives the client credit for a fully enforcing domain' {
        # A report that only ever lists problems reads as a bill for failure.
        AddHealth 'acme.com' @{ domain='acme.com'; DMARCPolicy='reject'; SPFLookups=2; SilentCriticalCodes=@() }
        $script:Prog | Add-Member -NotePropertyName 'acme_com' -NotePropertyValue ([PSCustomObject]@{ currentPolicy='reject' }) -Force
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        ($f | Where-Object { $_.Severity -eq 'good' }).Title | Should -Match 'fully enforcing'
    }

    It 'orders findings worst first' {
        AddHealth 'a.com' @{ domain='a.com'; DMARCPolicy='none';    SPFLookups=2;  SilentCriticalCodes=@() }
        AddHealth 'b.com' @{ domain='b.com'; DMARCPolicy='reject';  SPFLookups=11; SilentCriticalCodes=@() }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('a.com','b.com'))
        $f[0].Severity | Should -Be 'critical'
    }

    It 'counts unauthorised senders only for this client' {
        # A finding leaking another client's sources into this report would be
        # a confidentiality incident, not a formatting bug.
        $script:Inv | Add-Member -NotePropertyName 's1' -NotePropertyValue ([PSCustomObject]@{ domain='acme.com';   isApproved=$false }) -Force
        $script:Inv | Add-Member -NotePropertyName 's2' -NotePropertyValue ([PSCustomObject]@{ domain='globex.com'; isApproved=$false }) -Force
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        ($f | Where-Object { $_.Title -match 'not yet authorised' }).Title | Should -Match '^1 sending source'
    }

    It 'says nothing about senders when all are approved' {
        $script:Inv | Add-Member -NotePropertyName 's1' -NotePropertyValue ([PSCustomObject]@{ domain='acme.com'; isApproved=$true }) -Force
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('acme.com'))
        @($f | Where-Object { $_.Title -match 'not yet authorised' }).Count | Should -Be 0
    }

    It 'runs on a client whose domains have no data yet' {
        # A newly onboarded client, before the first reports arrive.
        { Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('brandnew.com') } | Should -Not -Throw
    }

    It 'survives null state files' {
        { Get-ClientReportFindings -DnsHealth $null -Progression $null -SourceInventory $null -Domains @('acme.com') } | Should -Not -Throw
    }

    It 'survives an empty domain list' {
        { Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @() } | Should -Not -Throw
    }

    It 'names the affected domain on every domain-specific finding' {
        # "SPF is broken" is useless to a client with six domains.
        AddHealth 'a.com' @{ domain='a.com'; DMARCPolicy='missing'; SPFLookups=11; SilentCriticalCodes=@('SPF_PLUS_ALL') }
        $f = @(Get-ClientReportFindings -DnsHealth $script:Health -Progression $script:Prog -SourceInventory $script:Inv -Domains @('a.com'))
        foreach ($x in ($f | Where-Object { $_.Domain })) { $x.Detail | Should -Match 'a\.com' }
    }
}
