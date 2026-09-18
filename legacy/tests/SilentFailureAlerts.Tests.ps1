<#
    Alert suppression for silent-failure findings.

    Getting this wrong in either direction ruins the feature. Alert every run
    and an MSP watching hundreds of domains stops reading the alerts, so the
    one that matters is missed. Suppress too eagerly and a genuine new break is
    never announced.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $script:Reporter = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-DMARCReporter.ps1'
    . (Import-EngineFunction -ScriptPath $script:Reporter -FunctionName 'Get-NewSilentFailures')

    function F { param([string]$Code, [string]$Title = 'x') [PSCustomObject]@{ Code = $Code; Title = $Title; Reference = 'RFC' } }
    function Codes { param($r) return @(@($r) | ForEach-Object { $_.Code }) }
}

Describe 'Get-NewSilentFailures' {

    Context 'the first time a domain is seen' {
        It 'treats every finding as new when there is no previous state' {
            $r = Get-NewSilentFailures -Current @((F 'SPF_REDIRECT_NEUTERED_BY_ALL'), (F 'DMARC_MULTIPLE_RECORDS')) -PreviousCodes @()
            (Codes $r) | Should -Be @('SPF_REDIRECT_NEUTERED_BY_ALL', 'DMARC_MULTIPLE_RECORDS')
        }

        It 'handles a null previous list the same as an empty one' {
            $r = Get-NewSilentFailures -Current @((F 'SPF_PLUS_ALL')) -PreviousCodes $null
            (Codes $r) | Should -Be @('SPF_PLUS_ALL')
        }
    }

    Context 'a finding that has already been alerted' {
        It 'stays silent when nothing has changed' {
            $r = Get-NewSilentFailures -Current @((F 'SPF_PLUS_ALL')) -PreviousCodes @('SPF_PLUS_ALL')
            @($r).Count | Should -Be 0
        }

        It 'stays silent across many runs of the same unfixed problem' {
            $codes = @('SPF_PLUS_ALL', 'DMARC_PCT_ZERO')
            foreach ($i in 1..10) {
                $r = Get-NewSilentFailures -Current @((F 'SPF_PLUS_ALL'), (F 'DMARC_PCT_ZERO')) -PreviousCodes $codes
                @($r).Count | Should -Be 0 -Because "run $i must not re-alert an unchanged finding"
            }
        }
    }

    Context 'a new problem on an already-failing domain' {
        It 'alerts on the new code and only the new code' {
            # This is the case that makes suppression by code rather than by
            # domain necessary: the domain was already broken, so a per-domain
            # check would swallow the new break entirely.
            $r = Get-NewSilentFailures `
                -Current @((F 'SPF_PLUS_ALL'), (F 'DMARC_MULTIPLE_RECORDS')) `
                -PreviousCodes @('SPF_PLUS_ALL')
            (Codes $r) | Should -Be @('DMARC_MULTIPLE_RECORDS')
        }
    }

    Context 'a problem that was fixed and came back' {
        It 'alerts again, because a regression is news' {
            $r = Get-NewSilentFailures -Current @((F 'SPF_PLUS_ALL')) -PreviousCodes @()
            (Codes $r) | Should -Be @('SPF_PLUS_ALL')
        }
    }

    Context 'a domain that has been fixed' {
        It 'returns nothing when there is nothing wrong any more' {
            $r = Get-NewSilentFailures -Current @() -PreviousCodes @('SPF_PLUS_ALL')
            @($r).Count | Should -Be 0
        }

        It 'returns a countable empty collection, not null' {
            # The caller foreaches over this. Returning $null under StrictMode
            # is the same trap that made clean domains crash the analysis.
            $r = Get-NewSilentFailures -Current @() -PreviousCodes @()
            { @($r).Count } | Should -Not -Throw
            @($r).Count | Should -Be 0
        }
    }

    Context 'defensive handling of ragged state' {
        It 'ignores empty entries in the previous list' {
            # ConvertFrom-Json on a stored empty array can yield oddities.
            $r = Get-NewSilentFailures -Current @((F 'SPF_PLUS_ALL')) -PreviousCodes @('', $null, 'SPF_PLUS_ALL')
            @($r).Count | Should -Be 0
        }

        It 'ignores null entries in the current list' {
            $r = Get-NewSilentFailures -Current @($null, (F 'DMARC_PCT_ZERO')) -PreviousCodes @()
            (Codes $r) | Should -Be @('DMARC_PCT_ZERO')
        }

        It 'accepts a single finding that is not wrapped in an array' {
            $r = Get-NewSilentFailures -Current (F 'SPF_NO_TERMINAL') -PreviousCodes @()
            (Codes $r) | Should -Be @('SPF_NO_TERMINAL')
        }

        It 'accepts a single previous code that is not wrapped in an array' {
            $r = Get-NewSilentFailures -Current @((F 'SPF_NO_TERMINAL')) -PreviousCodes 'SPF_NO_TERMINAL'
            @($r).Count | Should -Be 0
        }
    }
}

Describe 'collection-time wiring' {
    BeforeAll { $script:Text = Get-Content $script:Reporter -Raw }

    It 'runs the analysis on every collection, not only on demand' {
        $script:Text | Should -Match 'Test-AuthenticationSilentFailures -Domain \$domain'
    }

    It 'carries previous codes forward so a failed analysis does not re-alert' {
        # If the try block throws, writing an empty code list to state would
        # make a still-broken domain look newly broken next run.
        $script:Text | Should -Match '(?s)\$silentCodes\s*=\s*\$prevCrit.*?try \{'
    }

    It 'persists the critical codes for the next run to compare against' {
        $script:Text | Should -Match 'SilentCriticalCodes=\$silentCodes'
    }

    It 'sends silent failures as their own card rather than folding them in' {
        # A silently-inert record is a different class of problem from "pct is
        # below 100" and must not be buried in the amber advisory card.
        $script:Text | Should -Match 'Silent Failure — \$\(\$silentAlerts\.Count\)'
        $script:Text | Should -Match '\$silentAlerts\.Count -gt 0 -and \$EnableAlerts'
    }

    It 'colours that card as critical, not advisory' {
        $script:Text | Should -Match 'Silent Failure[^\r\n]*-Color "F85149"'
    }

    It 'loads the detection engine lazily and survives its absence' {
        $script:Text | Should -Match '(?m)^function Import-SilentFailureEngine'
        $script:Text | Should -Match 'silent-failure analysis skipped'
    }

    It 'supplies a real DNS verifier for the RFC 7489 s7.1 check' {
        $script:Text | Should -Match '(?m)^function Test-ReportDestinationAuthorized'
        $script:Text | Should -Match '\$PolicyDomain\._report\._dmarc\.\$ExternalDomain'
    }
}
