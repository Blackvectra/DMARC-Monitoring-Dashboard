<#
    Get-DaysAtCurrentPolicy + Get-EnforcementDecision — the engine that decides
    whether a domain is safe to advance toward p=reject.

    This is the highest-consequence judgement the product makes. quarantine
    sends failing mail to junk, where a user can still find it. reject tells
    the receiver to discard it. Advancing a domain that still has unidentified
    legitimate senders means their mail disappears, and the operator finds out
    from an angry client rather than from the tool.

    So the tests care most about the gates REFUSING when they should.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $enginePath = Get-EngineScriptPath -FileName 'Invoke-DMARCReporter.ps1'
    . (New-EngineStub)
    . (Import-EngineFunction -ScriptPath $enginePath `
        -FunctionName 'Get-DaysAtCurrentPolicy', 'Get-EnforcementDecision')

    function New-Progression {
        param(
            [string]$CurrentPolicy = 'quarantine',
            [string]$FirstSeen,
            [array]$History,
            [int]$Pct = 100,
            [string]$Adkim = 'r',
            [string]$Aspf = 'r'
        )
        $o = [ordered]@{
            domain        = 'acme.com'
            currentPolicy = $CurrentPolicy
            pct           = $Pct
            adkim         = $Adkim
            aspf          = $Aspf
        }
        if ($FirstSeen) { $o['firstSeen'] = $FirstSeen }
        if ($History)   { $o['policyHistory'] = $History }
        return [PSCustomObject]$o
    }

    function New-HistoryEntry {
        param([string]$Date, [string]$Policy)
        return [PSCustomObject]@{ date = $Date; policy = $Policy }
    }

    # A domain that comfortably clears every gate, so individual tests can
    # vary one input at a time.
    function Get-HealthyArgs {
        return @{
            Domain                 = 'acme.com'
            CurrentPolicy          = 'quarantine'
            PassRate               = 99.0
            TotalMessages          = 5000
            UnknownFailingMessages = 0
            DaysAtCurrentPolicy    = 30
        }
    }
}

Describe 'Get-DaysAtCurrentPolicy' {

    Context 'the regression that green-lit reject after one day' {
        It 'measures from the move to quarantine, not from when the domain was first seen' {
            # The exact shape of the bug: monitored for ~6 months, moved to
            # quarantine yesterday. The old (lastUpdated - firstSeen) maths
            # returned ~180 and sailed through a gate meant to hold for 14.
            $prog = New-Progression -CurrentPolicy 'quarantine' `
                -FirstSeen ((Get-Date).AddDays(-180).ToString('yyyy-MM-dd')) `
                -History @(
                    (New-HistoryEntry ((Get-Date).AddDays(-180).ToString('yyyy-MM-dd')) 'none'),
                    (New-HistoryEntry ((Get-Date).AddDays(-1).ToString('yyyy-MM-dd'))   'quarantine')
                )
            $days = Get-DaysAtCurrentPolicy -Progression $prog
            $days | Should -Be 1 -Because 'it has been at quarantine for one day, whatever the domain age'
            $days | Should -BeLessThan 14 -Because 'the reject gate must still hold'
        }

        It 'reports the full duration for a domain that has genuinely been at quarantine a long time' {
            $prog = New-Progression -CurrentPolicy 'quarantine' `
                -FirstSeen ((Get-Date).AddDays(-200).ToString('yyyy-MM-dd')) `
                -History @(
                    (New-HistoryEntry ((Get-Date).AddDays(-200).ToString('yyyy-MM-dd')) 'none'),
                    (New-HistoryEntry ((Get-Date).AddDays(-60).ToString('yyyy-MM-dd'))  'quarantine')
                )
            Get-DaysAtCurrentPolicy -Progression $prog | Should -Be 60
        }
    }

    Context 'policy that was relaxed and re-applied' {
        It 'measures the current run, not the first time the policy was ever set' {
            # none -> quarantine -> none -> quarantine. The clock restarts on
            # the most recent entry into quarantine; counting from the first
            # would credit time when the policy was not in force.
            $prog = New-Progression -CurrentPolicy 'quarantine' `
                -FirstSeen ((Get-Date).AddDays(-300).ToString('yyyy-MM-dd')) `
                -History @(
                    (New-HistoryEntry ((Get-Date).AddDays(-300).ToString('yyyy-MM-dd')) 'none'),
                    (New-HistoryEntry ((Get-Date).AddDays(-200).ToString('yyyy-MM-dd')) 'quarantine'),
                    (New-HistoryEntry ((Get-Date).AddDays(-100).ToString('yyyy-MM-dd')) 'none'),
                    (New-HistoryEntry ((Get-Date).AddDays(-5).ToString('yyyy-MM-dd'))   'quarantine')
                )
            Get-DaysAtCurrentPolicy -Progression $prog | Should -Be 5
        }

        It 'counts consecutive same-policy entries as one continuous run' {
            # Repeated entries for the same policy are noise, not transitions.
            $prog = New-Progression -CurrentPolicy 'reject' `
                -History @(
                    (New-HistoryEntry ((Get-Date).AddDays(-90).ToString('yyyy-MM-dd')) 'quarantine'),
                    (New-HistoryEntry ((Get-Date).AddDays(-40).ToString('yyyy-MM-dd')) 'reject'),
                    (New-HistoryEntry ((Get-Date).AddDays(-20).ToString('yyyy-MM-dd')) 'reject')
                )
            Get-DaysAtCurrentPolicy -Progression $prog | Should -Be 40
        }
    }

    Context 'degraded input' {
        It 'falls back to firstSeen when no history exists' {
            # Domains recorded before policyHistory was written have no entries.
            $prog = New-Progression -CurrentPolicy 'quarantine' -FirstSeen ((Get-Date).AddDays(-30).ToString('yyyy-MM-dd'))
            Get-DaysAtCurrentPolicy -Progression $prog | Should -Be 30
        }

        It 'returns 0 rather than throwing for null progression' {
            Get-DaysAtCurrentPolicy -Progression $null | Should -Be 0
        }

        It 'returns 0 when there is no policy and no dates' {
            Get-DaysAtCurrentPolicy -Progression (New-Progression -CurrentPolicy '') | Should -Be 0
        }

        It 'never returns a negative number for a future-dated entry' {
            # Clock skew between the engine host and whatever wrote the state
            # should not produce a negative age that trivially passes a gate.
            $prog = New-Progression -CurrentPolicy 'quarantine' `
                -History @((New-HistoryEntry ((Get-Date).AddDays(5).ToString('yyyy-MM-dd')) 'quarantine'))
            Get-DaysAtCurrentPolicy -Progression $prog | Should -BeGreaterOrEqual 0
        }

        It 'survives an unparseable date' {
            $prog = New-Progression -CurrentPolicy 'quarantine' -History @((New-HistoryEntry 'not-a-date' 'quarantine'))
            { Get-DaysAtCurrentPolicy -Progression $prog } | Should -Not -Throw
        }
    }
}

Describe 'Get-EnforcementDecision' {

    Context 'none -> quarantine' {
        It 'advances when pass rate, volume and sender identification all clear' {
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'none' `
                    -PassRate 95 -TotalMessages 1000 -UnknownFailingMessages 0
            $r.ReadyToAdvance | Should -BeTrue
            $r.Recommendation | Should -Be 'advance-to-quarantine'
        }

        It 'refuses below a 90% pass rate' {
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'none' `
                    -PassRate 85 -TotalMessages 1000 -UnknownFailingMessages 0
            $r.ReadyToAdvance | Should -BeFalse
            $r.Blockers | Should -Match '90%'
        }

        It 'refuses while unidentified senders are still failing' {
            # These are the senders that break when enforcement turns on, so
            # this gate matters more than the pass rate.
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'none' `
                    -PassRate 99 -TotalMessages 1000 -UnknownFailingMessages 12
            $r.ReadyToAdvance | Should -BeFalse
            $r.Blockers | Should -Match 'unidentified senders'
        }

        It 'refuses on too little volume for the pass rate to mean anything' {
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'none' `
                    -PassRate 100 -TotalMessages 5 -UnknownFailingMessages 0
            $r.ReadyToAdvance | Should -BeFalse
            $r.Blockers | Should -Match 'need 100'
        }
    }

    Context 'quarantine -> reject, the transition that cannot be undone' {
        It 'advances when every gate clears' {
            $ha = Get-HealthyArgs
            $r = Get-EnforcementDecision @ha
            $r.ReadyToAdvance | Should -BeTrue
            $r.Recommendation | Should -Be 'advance-to-reject'
        }

        It 'refuses below a 95% pass rate, which is stricter than the quarantine gate' {
            $a = Get-HealthyArgs; $a.PassRate = 92
            $r = Get-EnforcementDecision @a
            $r.ReadyToAdvance | Should -BeFalse
            $r.Blockers | Should -Match '95%'
        }

        It 'refuses before the minimum time at quarantine has elapsed' {
            $a = Get-HealthyArgs; $a.DaysAtCurrentPolicy = 3
            $r = Get-EnforcementDecision @a
            $r.ReadyToAdvance | Should -BeFalse
            $r.Blockers | Should -Match 'days at quarantine'
        }

        It 'applies a volume floor to this advance too' {
            # Previously only none -> quarantine had one, so the MORE dangerous
            # advance could be green-lit on a handful of messages.
            $a = Get-HealthyArgs; $a.TotalMessages = 12
            $r = Get-EnforcementDecision @a
            $r.ReadyToAdvance | Should -BeFalse
            $r.Blockers | Should -Match 'before moving to reject'
        }

        It 'refuses while unidentified senders are still failing' {
            $a = Get-HealthyArgs; $a.UnknownFailingMessages = 1
            $r = Get-EnforcementDecision @a
            $r.ReadyToAdvance | Should -BeFalse
        }

        It 'reports every unmet gate at once, not just the first' {
            # An operator fixing one blocker at a time across weekly reports is
            # a bad experience; show the whole list.
            $a = Get-HealthyArgs
            $a.PassRate = 50; $a.TotalMessages = 10; $a.DaysAtCurrentPolicy = 1; $a.UnknownFailingMessages = 99
            $r = Get-EnforcementDecision @a
            @($r.Blockers -split '\|').Count | Should -BeGreaterOrEqual 4
        }
    }

    Context 'at reject: advice is not a blocker' {
        It 'reports fully-optimized at pct=100 even with relaxed alignment' {
            # Relaxed alignment is the RFC default and correct for most
            # domains. Treating it as a blocker left every fully-enforced
            # domain stuck on a permanent red "NOT READY".
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'reject' -Pct 100 -Adkim 'r' -Aspf 'r'
            $r.Recommendation | Should -Be 'fully-optimized'
            $r.Blockers       | Should -BeNullOrEmpty
        }

        It 'still surfaces strict alignment as optional advice' {
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'reject' -Pct 100 -Adkim 'r' -Aspf 'r'
            $r.Advice | Should -Match 'adkim=s'
            $r.Advice | Should -Match 'aspf=s'
        }

        It 'reports no advice at all when alignment is already strict' {
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'reject' -Pct 100 -Adkim 's' -Aspf 's'
            $r.Recommendation | Should -Be 'fully-optimized'
            $r.Advice         | Should -BeNullOrEmpty
        }

        It 'treats a pct below 100 as a genuine blocker' {
            # pct<100 means the policy is only applied to a sample, so the
            # domain is not actually protected. That is a real gap.
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'reject' -Pct 25
            $r.Recommendation | Should -Be 'not-ready'
            $r.Blockers       | Should -Match 'pct=25'
        }
    }

    Context 'unknown or missing policy' {
        It 'says so plainly instead of reporting zero blockers' {
            # The old code fell through to "NOT READY - resolve 0 blocker(s)",
            # which reads like a bug rather than a state.
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy ''
            $r.Recommendation | Should -Be 'insufficient-data'
            $r.Summary        | Should -Not -Match '0 blocker'
        }

        It 'handles an unrecognised policy value' {
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'banana'
            $r.Recommendation  | Should -Be 'insufficient-data'
            $r.ReadyToAdvance  | Should -BeFalse
        }
    }

    Context 'output shape' {
        It 'always carries the fields the dashboard and digest render' {
            $ha = Get-HealthyArgs
            $r = Get-EnforcementDecision @ha
            foreach ($f in 'Domain','CurrentPolicy','TargetPolicy','PassRate','TotalMessages',
                           'UnknownFailing','DaysAtCurrentPolicy','Recommendation','Summary',
                           'ReadyToAdvance','Reasons','Blockers','Advice') {
                $r.PSObject.Properties.Name | Should -Contain $f
            }
        }

        It 'normalises the policy to lower case' {
            $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'QUARANTINE' `
                    -PassRate 99 -TotalMessages 5000 -DaysAtCurrentPolicy 30
            $r.CurrentPolicy | Should -Be 'quarantine'
        }

        It 'never claims ready while any blocker is present' {
            # The invariant the whole feature rests on.
            foreach ($pr in 0, 50, 89, 94, 99) {
                foreach ($days in 0, 5, 13, 30) {
                    foreach ($vol in 5, 99, 5000) {
                        $r = Get-EnforcementDecision -Domain 'acme.com' -CurrentPolicy 'quarantine' `
                                -PassRate $pr -TotalMessages $vol -DaysAtCurrentPolicy $days
                        if ($r.Blockers) { $r.ReadyToAdvance | Should -BeFalse -Because "blockers present: $($r.Blockers)" }
                    }
                }
            }
        }
    }

    Context 'threshold boundaries' {
        It 'treats the threshold itself as passing, not failing' {
            (Get-EnforcementDecision -Domain 'a' -CurrentPolicy 'none' -PassRate 90 -TotalMessages 100).ReadyToAdvance | Should -BeTrue
            (Get-EnforcementDecision -Domain 'a' -CurrentPolicy 'quarantine' -PassRate 95 -TotalMessages 100 -DaysAtCurrentPolicy 14).ReadyToAdvance | Should -BeTrue
        }

        It 'fails just below each threshold' {
            (Get-EnforcementDecision -Domain 'a' -CurrentPolicy 'none' -PassRate 89.9 -TotalMessages 100).ReadyToAdvance | Should -BeFalse
            (Get-EnforcementDecision -Domain 'a' -CurrentPolicy 'quarantine' -PassRate 94.9 -TotalMessages 100 -DaysAtCurrentPolicy 14).ReadyToAdvance | Should -BeFalse
            (Get-EnforcementDecision -Domain 'a' -CurrentPolicy 'quarantine' -PassRate 99 -TotalMessages 99 -DaysAtCurrentPolicy 14).ReadyToAdvance | Should -BeFalse
            (Get-EnforcementDecision -Domain 'a' -CurrentPolicy 'quarantine' -PassRate 99 -TotalMessages 100 -DaysAtCurrentPolicy 13).ReadyToAdvance | Should -BeFalse
        }
    }
}
