<#
    The dashboard's XAML-to-code contract.

    A real XamlReader.Load (which CI runs on Windows) proves the markup is
    valid. It does NOT prove the script can drive it: Load succeeds, FindName
    returns $null for a name that is not there, and the failure surfaces later
    as a NullReferenceException on the first property set or Add_Click. That is
    how a broken build reached a user before - the markup was fine.

    These tests check the contract instead of the markup, and run on any
    platform because they never construct a WPF object.
#>

BeforeAll {
    $script:DashboardPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Start-DMARCDashboard.ps1'
    $script:Text = Get-Content $script:DashboardPath -Raw

    $m = [regex]::Match($script:Text, "(?s)\[xml\]\`$mainXaml\s*=\s*@'\s*(.*?)\s*'@")
    if (-not $m.Success) { throw 'Could not locate the main window XAML here-string.' }
    $script:MainXaml = $m.Groups[1].Value

    $script:XamlDoc = [xml]$script:MainXaml
    $nsm = New-Object System.Xml.XmlNamespaceManager $script:XamlDoc.NameTable
    $nsm.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
    $script:XamlNs = 'http://schemas.microsoft.com/winfx/2006/xaml'
    $script:Declared = @($script:XamlDoc.SelectNodes('//*[@x:Name]', $nsm) |
        ForEach-Object { $_.GetAttribute('Name', $script:XamlNs) })

    # The single foreach that resolves every control through FindName.
    $bm = [regex]::Match($script:Text, "(?s)foreach \(\`$n in @\((.*?)\)\) \{")
    if (-not $bm.Success) { throw 'Could not locate the FindName bind list.' }
    $script:Bound = @([regex]::Matches($bm.Groups[1].Value, "'([^']+)'") |
        ForEach-Object { $_.Groups[1].Value })
}

Describe 'main window XAML' {

    It 'is well-formed XML' {
        { [xml]$script:MainXaml } | Should -Not -Throw
    }

    It 'declares at least one named control' {
        @($script:Declared).Count | Should -BeGreaterThan 0
    }

    It 'gives every named control a unique name' {
        $dupes = @($script:Declared | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
        $dupes | Should -BeNullOrEmpty -Because "duplicate x:Name values make FindName ambiguous: $($dupes -join ', ')"
    }
}

Describe 'XAML to code binding contract' {

    It 'resolves every bound name to a control that exists in the XAML' {
        $missing = @($script:Bound | Where-Object { $_ -notin $script:Declared })
        $missing | Should -BeNullOrEmpty -Because "FindName returns null for these, so the first use crashes at startup: $($missing -join ', ')"
    }

    It 'binds no name twice' {
        $dupes = @($script:Bound | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
        $dupes | Should -BeNullOrEmpty -Because "redundant binds: $($dupes -join ', ')"
    }
}

Describe 'event handlers' {

    It 'attaches every Click handler to a control the script actually bound' {
        $handlers = @([regex]::Matches($script:Text, '\$(\w+)\.Add_Click\(') |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        @($handlers).Count | Should -BeGreaterThan 0
        $bad = @($handlers | Where-Object { $_ -notin $script:Bound })
        $bad | Should -BeNullOrEmpty -Because "Add_Click on an unbound control throws at startup: $($bad -join ', ')"
    }

    It 'calls a function that exists for every Click handler body' {
        # Handlers are one-liners delegating to a named function. A typo there
        # is silent until the button is pressed.
        $defined = @([regex]::Matches($script:Text, '(?m)^function\s+([\w-]+)') |
            ForEach-Object { $_.Groups[1].Value })
        $called = @([regex]::Matches($script:Text, '\$\w+\.Add_Click\(\{\s*([\w-]+)[\s\}]') |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $missing = @($called | Where-Object { $_ -notin $defined -and -not (Get-Command $_ -EA SilentlyContinue) })
        $missing | Should -BeNullOrEmpty -Because "handler targets an undefined function: $($missing -join ', ')"
    }
}

Describe 'silent-failure check is reachable from the UI' {
    # The detection engine is only worth anything if a user can run it.

    It 'declares the button in the XAML' {
        $script:Declared | Should -Contain 'btnSilentCheck'
    }

    It 'binds the button in code' {
        $script:Bound | Should -Contain 'btnSilentCheck'
    }

    It 'wires the button to the analysis function' {
        $script:Text | Should -Match '\$btnSilentCheck\.Add_Click\(\{\s*Invoke-SilentFailureCheck'
    }

    It 'defines the analysis function' {
        $script:Text | Should -Match '(?m)^function\s+Invoke-SilentFailureCheck'
    }

    It 'passes an RFC 7489 s7.1 verifier rather than leaving the check unverified' {
        $script:Text | Should -Match 'ReportDomainVerifier\s+\$verifier'
        $script:Text | Should -Match '(?m)^function\s+Test-ReportDestinationAuthorized'
    }

    It 'probes the correct authorisation record shape' {
        # <policy-domain>._report._dmarc.<destination>, in that order.
        $script:Text | Should -Match '\$PolicyDomain\._report\._dmarc\.\$ExternalDomain'
    }

    It 'does not treat pre-upgrade stored data as "publishes nothing"' {
        # dns-health.json written before raw-record capture has no SPFRecords.
        # Passing empty arrays would manufacture SPF_MISSING/DMARC_MISSING for
        # domains that are fine, which is worse than reporting nothing.
        $script:Text | Should -Match "PSObject\.Properties\['SPFRecords'\]"
        $script:Text | Should -Match 'Refresh Needed|predates raw-record capture'
    }
}

Describe 'DNS health collection keeps every published record' {
    BeforeAll {
        $script:Reporter = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-DMARCReporter.ps1') -Raw
    }

    It 'no longer takes only the first SPF record' {
        # RFC 7208 s4.5 makes a second record a permerror, so the second record
        # IS the finding. Select-Object -First 1 threw the evidence away.
        $script:Reporter | Should -Not -Match "v=spf1.*\|\s*Select-Object -First 1"
    }

    It 'no longer takes only the first DMARC record' {
        $script:Reporter | Should -Not -Match "v=DMARC1.*\|\s*Select-Object -First 1"
    }

    It 'persists the raw records for later analysis' {
        $script:Reporter | Should -Match 'SPFRecords=\$r\.SPFRecords'
        $script:Reporter | Should -Match 'DMARCRecords=\$r\.DMARCRecords'
    }

    It 'joins strings within a record but not across records' {
        # A TXT record over 255 bytes arrives as several strings that must be
        # concatenated; two separate records must never be merged into one.
        $script:Reporter | Should -Match 'ForEach-Object \{ \(\$_\.Strings -join ''''\)\.Trim\(\) \}'
    }

    It 'raises an issue when more than one record of either kind is published' {
        $script:Reporter | Should -Match 'DMARC records — DMARC is not applied at all'
        $script:Reporter | Should -Match 'SPF records — permanent error'
    }
}
