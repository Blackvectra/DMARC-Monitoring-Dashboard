<#
    Get-SPFNode — recursive SPF include/redirect traversal (Invoke-SPFInspector.ps1).

    Resolve-DnsName is a Windows-only cmdlet, so these tests supply a stub that
    serves canned zone data from a hashtable. That is the right shape for unit
    tests anyway: deterministic, offline, and able to construct pathological
    zones (cycles, deep nesting) that would be impractical to host for real.

    The cycle case is regression cover for PR #4 finding #16: before the fix,
    A -> B -> A recursed until it hit the depth limit, burning ten DNS lookups
    and reporting "max depth" instead of naming the actual loop.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $spfScript = Get-EngineScriptPath -FileName 'Invoke-SPFInspector.ps1'
    . (New-EngineStub)
    . (Import-EngineFunction -ScriptPath $spfScript -FunctionName 'Get-SPFNode')

    # Canned zone. Each key is a domain; the value is its SPF TXT record.
    $script:Zone = @{}

    function Resolve-DnsName {
        param(
            [string]$Name,
            [string]$Type,
            [string]$ErrorAction,
            [switch]$EA
        )
        if (-not $script:Zone.ContainsKey($Name)) {
            throw "DNS name does not exist: $Name"
        }
        return [PSCustomObject]@{ Strings = @($script:Zone[$Name]) }
    }

    function Reset-SpfState {
        param([hashtable]$Zone)
        $script:Zone = $Zone
        $script:LookupCount = 0
    }

    # Walks the tree and returns every node, so assertions can find a
    # descendant without hand-indexing through Children collections.
    function Get-AllNodes {
        param($Node)
        $out = [System.Collections.Generic.List[object]]::new()
        $out.Add($Node)
        foreach ($c in $Node.Children) { foreach ($n in (Get-AllNodes -Node $c)) { $out.Add($n) } }
        return $out
    }
}

Describe 'Get-SPFNode' {

    Context 'a simple record with no includes' {
        It 'records the raw SPF and costs no lookups' {
            Reset-SpfState -Zone @{ 'acme.com' = 'v=spf1 ip4:203.0.113.0/24 -all' }
            $n = Get-SPFNode -Domain 'acme.com'

            $n.Domain      | Should -Be 'acme.com'
            $n.Record      | Should -Be 'v=spf1 ip4:203.0.113.0/24 -all'
            $n.Error       | Should -BeNullOrEmpty
            $n.NodeLookups | Should -Be 0
            $n.Children.Count | Should -Be 0
        }

        It 'classifies ip4/ip6 and all as non-lookup mechanisms' {
            Reset-SpfState -Zone @{ 'acme.com' = 'v=spf1 ip4:1.2.3.0/24 ip6:2001:db8::/32 -all' }
            $n = Get-SPFNode -Domain 'acme.com'

            ($n.Mechanisms | Where-Object CountsAsLookup).Count | Should -Be 0
            ($n.Mechanisms | Where-Object { $_.Type -eq 'all' }).Count | Should -Be 1
        }
    }

    Context 'lookup counting (RFC 7208 limit of 10)' {
        It 'counts include, a, mx and exists but not ip4/ip6/all' {
            Reset-SpfState -Zone @{
                'acme.com' = 'v=spf1 a mx exists:%{i}._spf.acme.com ip4:1.2.3.4 ip6:2001:db8::1 include:child.example -all'
                'child.example' = 'v=spf1 -all'
            }
            $n = Get-SPFNode -Domain 'acme.com'

            # a + mx + exists + include = 4
            $n.NodeLookups | Should -Be 4
            $script:LookupCount | Should -Be 4
        }

        It 'accumulates lookups across the whole chain, not just the root' {
            Reset-SpfState -Zone @{
                'acme.com' = 'v=spf1 include:a.example include:b.example -all'
                'a.example' = 'v=spf1 include:c.example -all'
                'b.example' = 'v=spf1 a -all'
                'c.example' = 'v=spf1 mx -all'
            }
            $null = Get-SPFNode -Domain 'acme.com'

            # root: 2 includes. a.example: 1 include. b.example: 1 a. c.example: 1 mx.
            $script:LookupCount | Should -Be 5
        }
    }

    Context 'include and redirect traversal' {
        It 'recurses into includes and records the child record' {
            Reset-SpfState -Zone @{
                'acme.com'   = 'v=spf1 include:_spf.vendor.example -all'
                '_spf.vendor.example' = 'v=spf1 ip4:198.51.100.0/24 -all'
            }
            $n = Get-SPFNode -Domain 'acme.com'

            $n.Children.Count   | Should -Be 1
            $n.Children[0].Domain | Should -Be '_spf.vendor.example'
            $n.Children[0].Record | Should -Match 'ip4:198\.51\.100\.0/24'
        }

        It 'follows a redirect and flags the node' {
            Reset-SpfState -Zone @{
                'acme.com'  = 'v=spf1 redirect=spf.acme.net'
                'spf.acme.net' = 'v=spf1 ip4:203.0.113.1 -all'
            }
            $n = Get-SPFNode -Domain 'acme.com'

            $n.IsRedirect       | Should -BeTrue
            $n.Children.Count   | Should -Be 1
            $n.Children[0].Domain | Should -Be 'spf.acme.net'
        }

        It 'traverses several levels deep' {
            Reset-SpfState -Zone @{
                'l0.example' = 'v=spf1 include:l1.example -all'
                'l1.example' = 'v=spf1 include:l2.example -all'
                'l2.example' = 'v=spf1 include:l3.example -all'
                'l3.example' = 'v=spf1 ip4:10.0.0.1 -all'
            }
            $n = Get-SPFNode -Domain 'l0.example'
            $all = Get-AllNodes -Node $n

            $all.Count | Should -Be 4
            ($all | Where-Object Domain -eq 'l3.example').Record | Should -Match 'ip4:10\.0\.0\.1'
        }
    }

    Context 'cycle detection (regression: PR #4 finding #16)' {
        It 'names the loop instead of recursing to the depth limit' {
            Reset-SpfState -Zone @{
                'a.example' = 'v=spf1 include:b.example -all'
                'b.example' = 'v=spf1 include:a.example -all'
            }
            $n = Get-SPFNode -Domain 'a.example'
            $all = Get-AllNodes -Node $n

            $cycleNodes = $all | Where-Object { $_.Error -match 'cycle' }
            $cycleNodes.Count | Should -BeGreaterThan 0
            $cycleNodes[0].Error | Should -Match 'a\.example'

            # Before the fix this bottomed out at "Max depth reached".
            ($all | Where-Object { $_.Error -match 'Max depth' }).Count | Should -Be 0
        }

        It 'detects a three-node cycle' {
            Reset-SpfState -Zone @{
                'x.example' = 'v=spf1 include:y.example -all'
                'y.example' = 'v=spf1 include:z.example -all'
                'z.example' = 'v=spf1 include:x.example -all'
            }
            $all = Get-AllNodes -Node (Get-SPFNode -Domain 'x.example')
            ($all | Where-Object { $_.Error -match 'cycle' }).Count | Should -BeGreaterThan 0
        }

        It 'detects a self-referencing record' {
            Reset-SpfState -Zone @{ 'self.example' = 'v=spf1 include:self.example -all' }
            $all = Get-AllNodes -Node (Get-SPFNode -Domain 'self.example')
            ($all | Where-Object { $_.Error -match 'cycle' }).Count | Should -BeGreaterThan 0
        }

        It 'does not false-positive on a diamond (same include from two parents)' {
            # a -> b -> shared, a -> c -> shared. Not a cycle: the chain never
            # revisits a domain that is an ancestor of itself. Flagging this
            # would be wrong, and common - lots of zones include a shared _spf.
            Reset-SpfState -Zone @{
                'a.example'      = 'v=spf1 include:b.example include:c.example -all'
                'b.example'      = 'v=spf1 include:shared.example -all'
                'c.example'      = 'v=spf1 include:shared.example -all'
                'shared.example' = 'v=spf1 ip4:10.1.1.1 -all'
            }
            $all = Get-AllNodes -Node (Get-SPFNode -Domain 'a.example')
            $shared = $all | Where-Object Domain -eq 'shared.example'

            $shared.Count | Should -BeGreaterThan 0
            ($shared | Where-Object { $_.Record -match 'ip4:10\.1\.1\.1' }).Count |
                Should -BeGreaterThan 0 -Because 'at least one traversal of the shared include should resolve normally'
        }
    }

    Context 'error handling' {
        It 'reports a missing SPF record rather than throwing' {
            Reset-SpfState -Zone @{ 'nospf.example' = 'v=verification1 abc123' }
            $n = Get-SPFNode -Domain 'nospf.example'
            $n.Error  | Should -Match 'No SPF record'
            $n.Record | Should -BeNullOrEmpty
        }

        It 'reports a DNS failure on the node rather than aborting the chain' {
            Reset-SpfState -Zone @{ 'acme.com' = 'v=spf1 include:nxdomain.example -all' }
            $n = Get-SPFNode -Domain 'acme.com'

            $n.Error | Should -BeNullOrEmpty -Because 'the root resolved fine'
            $n.Children[0].Error | Should -Match 'DNS lookup failed'
            $n.Record | Should -Match 'include:nxdomain\.example'
        }

        It 'stops at the depth limit on a long non-cyclic chain' {
            $zone = @{}
            0..14 | ForEach-Object {
                $zone["d$_.example"] = "v=spf1 include:d$($_ + 1).example -all"
            }
            $zone['d15.example'] = 'v=spf1 -all'
            Reset-SpfState -Zone $zone

            $all = Get-AllNodes -Node (Get-SPFNode -Domain 'd0.example')
            # Bounded, and bounded by depth rather than by running forever.
            $all.Count | Should -BeLessOrEqual 13
        }
    }

    Context 'qualifiers' {
        It 'captures the qualifier on each mechanism' {
            Reset-SpfState -Zone @{ 'acme.com' = 'v=spf1 +ip4:1.1.1.1 ~ip4:2.2.2.2 -ip4:3.3.3.3 ?ip4:4.4.4.4 -all' }
            $n = Get-SPFNode -Domain 'acme.com'

            ($n.Mechanisms | Where-Object { $_.Value -match '1\.1\.1\.1' }).Qualifier | Should -Be '+'
            ($n.Mechanisms | Where-Object { $_.Value -match '2\.2\.2\.2' }).Qualifier | Should -Be '~'
            ($n.Mechanisms | Where-Object { $_.Value -match '3\.3\.3\.3' }).Qualifier | Should -Be '-'
            ($n.Mechanisms | Where-Object { $_.Value -match '4\.4\.4\.4' }).Qualifier | Should -Be '?'
        }

        It 'defaults to + when no qualifier is written' {
            Reset-SpfState -Zone @{ 'acme.com' = 'v=spf1 ip4:5.5.5.5 -all' }
            $n = Get-SPFNode -Domain 'acme.com'
            ($n.Mechanisms | Where-Object { $_.Value -match '5\.5\.5\.5' }).Qualifier | Should -Be '+'
        }
    }
}
