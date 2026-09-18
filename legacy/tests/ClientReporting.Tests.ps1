<#
    Client registry and reporting periods.

    Period maths is worth this much testing because its failures are quiet: a
    report covering the wrong month still renders, still looks professional,
    and still gets sent to a paying client. Nobody notices until someone
    reconciles it against an invoice.
#>

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-ClientReporting.ps1')

    function NewWorkDir {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ("dmarccli_" + [guid]::NewGuid().ToString('N').Substring(0,10))
        New-Item -Path (Join-Path $d 'State') -ItemType Directory -Force | Out-Null
        return $d
    }
}

Describe 'ConvertTo-ClientId' {

    It 'makes a filesystem-safe id from a display name' {
        ConvertTo-ClientId -Name 'Acme Corporation' | Should -Be 'acme-corporation'
    }

    It 'strips characters that would break a path' -ForEach @(
        @{ Name = 'A/B Ltd';        Bad = '/'  }
        @{ Name = 'A\B Ltd';        Bad = '\'  }
        @{ Name = 'C:  Holdings';   Bad = ':'  }
        @{ Name = 'Smith & Co.';    Bad = '&'  }
        @{ Name = '../../etc';      Bad = '.'  }
    ) {
        $id = ConvertTo-ClientId -Name $Name
        $id | Should -Not -Match ([regex]::Escape($Bad))
        $id | Should -Match '^[a-z0-9-]+$'
    }

    It 'never produces a reserved Windows device name' -ForEach @(
        @{ Name = 'CON' }
        @{ Name = 'PRN' }
        @{ Name = 'NUL' }
        @{ Name = 'aux' }
        @{ Name = 'COM1' }
        @{ Name = 'LPT1' }
    ) {
        # A directory named CON cannot be created on Windows at all, so the
        # client's report folder would silently fail to appear.
        $id = ConvertTo-ClientId -Name $Name
        $id | Should -Not -BeIn @('con','prn','nul','aux','com1','lpt1')
    }

    It 'never ends in a dot or a dash' {
        # Windows silently trims a trailing dot, so two clients could collide.
        (ConvertTo-ClientId -Name 'Acme Inc.')  | Should -Not -Match '[-.]$'
        (ConvertTo-ClientId -Name '  Acme  ')   | Should -Be 'acme'
    }

    It 'falls back to something usable for a name of only punctuation' {
        (ConvertTo-ClientId -Name '!!!') | Should -Not -BeNullOrEmpty
        (ConvertTo-ClientId -Name '!!!') | Should -Match '^[a-z0-9-]+$'
    }

    It 'is stable: the same name always gives the same id' {
        (ConvertTo-ClientId -Name 'Acme Corp') | Should -Be (ConvertTo-ClientId -Name 'Acme Corp')
    }

    It 'caps the length so a long name cannot blow the path limit' {
        (ConvertTo-ClientId -Name ('x' * 400)).Length | Should -BeLessOrEqual 64
    }
}

Describe 'the client registry' {
    BeforeEach { $script:Dir = NewWorkDir }
    AfterEach  { Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'returns an empty registry rather than failing when nothing exists' {
        { Get-ClientRegistry -WorkingDir $script:Dir } | Should -Not -Throw
        @(Get-AllClients -WorkingDir $script:Dir).Count | Should -Be 0
    }

    It 'returns an empty registry rather than failing on a corrupt file' {
        Set-Content -Path (Get-ClientRegistryPath -WorkingDir $script:Dir) -Value '{not json' -Encoding UTF8
        { Get-AllClients -WorkingDir $script:Dir } | Should -Not -Throw
        @(Get-AllClients -WorkingDir $script:Dir).Count | Should -Be 0
    }

    It 'saves and reads back a client' {
        Set-Client -WorkingDir $script:Dir -Name 'Acme Corporation' -Domains @('acme.com','acme.co.uk') | Out-Null
        $c = Get-Client -WorkingDir $script:Dir -ClientId 'acme-corporation'
        $c.name | Should -Be 'Acme Corporation'
        @($c.domains).Count | Should -Be 2
    }

    It 'holds several domains for one client, which is the whole point' {
        $c = Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('acme.com','acme.net','acme.org')
        @($c.domains).Count | Should -Be 3
    }

    It 'de-duplicates domains, because a repeat would double-count messages' {
        $c = Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('acme.com','ACME.com','acme.com')
        @($c.domains).Count | Should -Be 1
    }

    It 'lower-cases domains so matching a report is case-insensitive' {
        $c = Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('ACME.COM')
        @($c.domains)[0] | Should -Be 'acme.com'
    }

    It 'drops blank domains' {
        $c = Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('acme.com','','   ')
        @($c.domains).Count | Should -Be 1
    }

    It 'updates in place without creating a second client' {
        Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('acme.com') | Out-Null
        Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('acme.com','acme.net') | Out-Null
        @(Get-AllClients -WorkingDir $script:Dir).Count | Should -Be 1
        @((Get-Client -WorkingDir $script:Dir -ClientId 'acme').domains).Count | Should -Be 2
    }

    It 'keeps the original onboarding date across updates' {
        # Tenure is a retention argument; resetting it on every edit erases it.
        $a = Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('acme.com')
        $b = Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('acme.com','acme.net')
        $b.onboardedAt | Should -Be $a.onboardedAt
    }

    It 'rejects a nameless client' {
        { Set-Client -WorkingDir $script:Dir -Name '  ' } | Should -Throw
    }

    It 'rejects a cadence it cannot report on' {
        { Set-Client -WorkingDir $script:Dir -Name 'Acme' -Cadence 'fortnightly' } | Should -Throw
    }

    It 'hides inactive clients by default but can list them' {
        Set-Client -WorkingDir $script:Dir -Name 'Gone Ltd' -Domains @('gone.com') -IsActive $false | Out-Null
        @(Get-AllClients -WorkingDir $script:Dir).Count | Should -Be 0
        @(Get-AllClients -WorkingDir $script:Dir -IncludeInactive).Count | Should -Be 1
    }

    It 'removes a client' {
        Set-Client -WorkingDir $script:Dir -Name 'Acme' -Domains @('acme.com') | Out-Null
        Remove-Client -WorkingDir $script:Dir -ClientId 'acme'
        @(Get-AllClients -WorkingDir $script:Dir).Count | Should -Be 0
    }

    It 'is idempotent when removing a client that is not there' {
        { Remove-Client -WorkingDir $script:Dir -ClientId 'nope' } | Should -Not -Throw
    }
}

Describe 'routing a domain to the client who is billed for it' {
    BeforeEach {
        $script:Dir = NewWorkDir
        Set-Client -WorkingDir $script:Dir -Name 'Acme'   -Domains @('acme.com','acme.net') | Out-Null
        Set-Client -WorkingDir $script:Dir -Name 'Globex' -Domains @('globex.com')          | Out-Null
    }
    AfterEach { Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'finds the client for a domain' {
        (Get-ClientForDomain -WorkingDir $script:Dir -Domain 'acme.net').name | Should -Be 'Acme'
    }

    It 'returns null for a domain nobody owns' {
        Get-ClientForDomain -WorkingDir $script:Dir -Domain 'nobody.com' | Should -BeNullOrEmpty
    }

    It 'lists domains that belong to no client, because those are unbilled' {
        $un = Get-UnassignedDomains -WorkingDir $script:Dir -KnownDomains @('acme.com','globex.com','stranger.com')
        $un | Should -Be @('stranger.com')
    }

    It 'reports nothing unassigned when every domain is claimed' {
        @(Get-UnassignedDomains -WorkingDir $script:Dir -KnownDomains @('acme.com','acme.net','globex.com')).Count | Should -Be 0
    }

    It 'still routes a domain belonging to an inactive client' {
        # Otherwise a churned client's domains silently reappear as unbilled.
        Set-Client -WorkingDir $script:Dir -Name 'Gone' -Domains @('gone.com') -IsActive $false | Out-Null
        (Get-ClientForDomain -WorkingDir $script:Dir -Domain 'gone.com').name | Should -Be 'Gone'
        @(Get-UnassignedDomains -WorkingDir $script:Dir -KnownDomains @('gone.com')).Count | Should -Be 0
    }
}

Describe 'monthly reporting periods' {

    It 'reports the calendar month that has ended, not the last 30 days' {
        # Run on 3 March, the client is invoiced for February.
        $p = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-03')
        $p.Start | Should -Be ([datetime]'2026-02-01')
        $p.End   | Should -Be ([datetime]'2026-02-28')
        $p.Label | Should -Be 'February 2026'
    }

    It 'compares against the month before that' {
        $p = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-03')
        $p.PreviousStart | Should -Be ([datetime]'2026-01-01')
        $p.PreviousEnd   | Should -Be ([datetime]'2026-01-31')
        $p.PreviousLabel | Should -Be 'January 2026'
    }

    It 'crosses the year boundary correctly' {
        # The off-by-one that would date a January report as the wrong year.
        $p = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-01-05')
        $p.Start | Should -Be ([datetime]'2025-12-01')
        $p.End   | Should -Be ([datetime]'2025-12-31')
        $p.Label | Should -Be 'December 2025'
        $p.PreviousStart | Should -Be ([datetime]'2025-11-01')
    }

    It 'handles February in a leap year' {
        $p = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2028-03-01')
        $p.End  | Should -Be ([datetime]'2028-02-29')
        $p.Days | Should -Be 29
    }

    It 'handles February in a non-leap year' {
        $p = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-01')
        $p.End  | Should -Be ([datetime]'2026-02-28')
        $p.Days | Should -Be 28
    }

    It 'gives a 31-day period the right length' {
        (Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-02-10')).Days | Should -Be 31
    }

    It 'gives the same period no matter which day of the month it runs' {
        # A report re-run on the 20th must not silently cover something else.
        $a = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-01')
        $b = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-20')
        $c = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-31')
        $a.Start | Should -Be $b.Start; $b.Start | Should -Be $c.Start
        $a.End   | Should -Be $b.End;   $b.End   | Should -Be $c.End
    }

    It 'ignores the time of day' {
        $p = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-03 23:47:11')
        $p.End | Should -Be ([datetime]'2026-02-28')
    }

    It 'never reports a period that has not finished' {
        $p = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-15')
        $p.End | Should -BeLessThan ([datetime]'2026-03-15')
    }
}

Describe 'weekly reporting periods' {

    It 'covers seven days ending yesterday' {
        # Yesterday, not today: a day's aggregate reports arrive throughout
        # the following day, so a window ending today always looks like a dip.
        $p = Get-ReportPeriod -Cadence 'weekly' -AsOf ([datetime]'2026-03-16')
        $p.End   | Should -Be ([datetime]'2026-03-15')
        $p.Start | Should -Be ([datetime]'2026-03-09')
        $p.Days  | Should -Be 7
    }

    It 'compares against the seven days before that, with no gap or overlap' {
        $p = Get-ReportPeriod -Cadence 'weekly' -AsOf ([datetime]'2026-03-16')
        $p.PreviousEnd   | Should -Be ([datetime]'2026-03-08')
        $p.PreviousStart | Should -Be ([datetime]'2026-03-02')
        ($p.Start - $p.PreviousEnd).Days | Should -Be 1
    }

    It 'crosses a month boundary' {
        $p = Get-ReportPeriod -Cadence 'weekly' -AsOf ([datetime]'2026-03-03')
        $p.End   | Should -Be ([datetime]'2026-03-02')
        $p.Start | Should -Be ([datetime]'2026-02-24')
    }

    It 'crosses a year boundary' {
        $p = Get-ReportPeriod -Cadence 'weekly' -AsOf ([datetime]'2026-01-03')
        $p.End   | Should -Be ([datetime]'2026-01-02')
        $p.Start | Should -Be ([datetime]'2025-12-27')
    }
}

Describe 'deciding whether a row belongs in the period' {
    BeforeEach { $script:P = Get-ReportPeriod -Cadence 'monthly' -AsOf ([datetime]'2026-03-03') }

    It 'includes the first and last day' {
        Test-DateInPeriod -Date '2026-02-01' -Period $script:P | Should -BeTrue
        Test-DateInPeriod -Date '2026-02-28' -Period $script:P | Should -BeTrue
    }

    It 'excludes the day either side' {
        Test-DateInPeriod -Date '2026-01-31' -Period $script:P | Should -BeFalse
        Test-DateInPeriod -Date '2026-03-01' -Period $script:P | Should -BeFalse
    }

    It 'includes a row timestamped late on the last day' {
        Test-DateInPeriod -Date '2026-02-28 23:59:59' -Period $script:P | Should -BeTrue
    }

    It 'reads an ISO date the same way regardless of machine locale' {
        # 03/04 is 3 April or 4 March depending on locale. The engine writes
        # yyyy-MM-dd, and it must be read as written on any operator's box.
        $prev = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            foreach ($culture in @('en-US','en-GB','de-DE')) {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]::new($culture)
                Test-DateInPeriod -Date '2026-02-10' -Period $script:P | Should -BeTrue -Because "culture $culture must not shift the date"
                Test-DateInPeriod -Date '2026-03-10' -Period $script:P | Should -BeFalse -Because "culture $culture must not shift the date"
            }
        } finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $prev }
    }

    It 'matches the comparison period when asked' {
        Test-DateInPeriod -Date '2026-01-15' -Period $script:P -Previous | Should -BeTrue
        Test-DateInPeriod -Date '2026-02-15' -Period $script:P -Previous | Should -BeFalse
    }

    It 'accepts a real DateTime as well as a string' {
        Test-DateInPeriod -Date ([datetime]'2026-02-10') -Period $script:P | Should -BeTrue
    }

    It 'returns false rather than throwing on junk' -ForEach @(
        @{ Bad = $null }
        @{ Bad = '' }
        @{ Bad = 'not-a-date' }
        @{ Bad = '2026-13-45' }
    ) {
        { Test-DateInPeriod -Date $Bad -Period $script:P } | Should -Not -Throw
        Test-DateInPeriod -Date $Bad -Period $script:P | Should -BeFalse
    }

    It 'puts every day of the period in exactly one of the two windows' {
        # No gap and no overlap between period and comparison period.
        $d = $script:P.PreviousStart
        while ($d -le $script:P.End) {
            $inCur  = Test-DateInPeriod -Date $d -Period $script:P
            $inPrev = Test-DateInPeriod -Date $d -Period $script:P -Previous
            ($inCur -and $inPrev) | Should -BeFalse -Because "$($d.ToString('yyyy-MM-dd')) must not be in both windows"
            ($inCur -or  $inPrev) | Should -BeTrue  -Because "$($d.ToString('yyyy-MM-dd')) must be in one of them"
            $d = $d.AddDays(1)
        }
    }
}
