<#
    Invoke-DNSRemediation.ps1 — the DNS remediation engine.

    This code publishes DNS for a client's production mail. A wrong record
    here does not produce a bad chart, it stops their email. So the emphasis
    is less on "does it build the right string" and more on "does it refuse
    to build a dangerous one", and on the apply path never writing when it
    was not told to.

    Everything runs against an in-memory provider and canned resolvers, so
    no test touches real DNS or a real registrar.
#>

BeforeAll {
    $script:RemediationScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-DNSRemediation.ps1'
    . $script:RemediationScript

    # A small canned zone used by the flattening tests.
    $script:TestZone = @{
        '_spf.google.com'       = 'v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 include:_netblocks.google.com -all'
        '_netblocks.google.com' = 'v=spf1 ip4:35.191.0.0/16 -all'
        'sendgrid.net'          = 'v=spf1 ip4:167.89.0.0/17 ip4:168.245.0.0/17 -all'
        'loop-a.example'        = 'v=spf1 include:loop-b.example -all'
        'loop-b.example'        = 'v=spf1 include:loop-a.example -all'
        'has-mx.example'        = 'v=spf1 mx ip4:10.0.0.1 -all'
    }
    $script:TestResolver = {
        param($d)
        if ($script:TestZone.ContainsKey($d)) { return $script:TestZone[$d] }
        return $null
    }

    function New-AtCapRecord {
        param([int]$Count = 10)
        return 'v=spf1 ' + ((1..$Count | ForEach-Object { "include:s$_.example" }) -join ' ') + ' -all'
    }
}

Describe 'ConvertFrom-SPFRecord' {

    It 'classifies every mechanism kind' {
        $p = ConvertFrom-SPFRecord -Record 'v=spf1 include:a.com redirect=b.com exists:%{i}.c.com ip4:1.2.3.4 ip6:2001:db8::1 a mx ptr -all'
        $p.IsValid | Should -BeTrue
        ($p.Terms | Where-Object Kind -eq 'include').Count  | Should -Be 1
        ($p.Terms | Where-Object Kind -eq 'redirect').Count | Should -Be 1
        ($p.Terms | Where-Object Kind -eq 'ip4').Count      | Should -Be 1
        ($p.Terms | Where-Object Kind -eq 'all').Count      | Should -Be 1
    }

    It 'marks exactly the lookup-costing mechanisms' {
        $p = ConvertFrom-SPFRecord -Record 'v=spf1 include:a.com a mx ptr exists:x.com redirect=y.com ip4:1.2.3.4 -all'
        # include, a, mx, ptr, exists, redirect = 6. ip4 and all are free.
        (Get-SPFRecordLookupCount -Parsed $p) | Should -Be 6
    }

    It 'never counts all as a lookup whatever its qualifier' {
        foreach ($a in '-all','~all','?all','+all') {
            $p = ConvertFrom-SPFRecord -Record "v=spf1 ip4:1.2.3.4 $a"
            (Get-SPFRecordLookupCount -Parsed $p) | Should -Be 0 -Because "'$a' is not a DNS lookup"
        }
    }

    It 'captures qualifiers' {
        $p = ConvertFrom-SPFRecord -Record 'v=spf1 ~include:a.com -all'
        ($p.Terms | Where-Object Kind -eq 'include').Qualifier | Should -Be '~'
    }

    It 'rejects a record that is not SPF' {
        (ConvertFrom-SPFRecord -Record 'v=DMARC1; p=reject').IsValid | Should -BeFalse
        (ConvertFrom-SPFRecord -Record '').IsValid                   | Should -BeFalse
    }

    It 'round-trips a record through parse and render' {
        $orig = 'v=spf1 include:a.com ip4:1.2.3.4 -all'
        $p = ConvertFrom-SPFRecord -Record $orig
        ConvertTo-SPFRecord -Parsed $p | Should -Be $orig
    }

    It 'always renders all last even if it was not last in the input' {
        # An 'all' in the middle makes everything after it unreachable, so the
        # renderer has to move it rather than preserve a broken order.
        $p = ConvertFrom-SPFRecord -Record 'v=spf1 -all include:a.com'
        ConvertTo-SPFRecord -Parsed $p | Should -Be 'v=spf1 include:a.com -all'
    }
}

Describe 'New-SPFIncludePlan' {

    Context 'the ordinary case' {
        It 'adds the include before the all term' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:_spf.google.com -all' -IncludeDomain 'sendgrid.net'
            $p.NewValue | Should -Be 'v=spf1 include:_spf.google.com include:sendgrid.net -all'
            $p.IsSafe   | Should -BeTrue
            $p.Action   | Should -Be 'update'
        }

        It 'reports the lookup cost before and after' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:a.com -all' -IncludeDomain 'b.com'
            $p.LookupsBefore | Should -Be 1
            $p.LookupsAfter  | Should -Be 2
        }

        It 'creates a record when the domain has none' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord '' -IncludeDomain 'sendgrid.net'
            $p.Action   | Should -Be 'create'
            $p.NewValue | Should -Be 'v=spf1 include:sendgrid.net ~all'
            $p.IsSafe   | Should -BeTrue
        }

        It 'honours a requested default all mechanism when creating' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord '' -IncludeDomain 'x.com' -DefaultAll '-all'
            $p.NewValue | Should -Be 'v=spf1 include:x.com -all'
        }
    }

    Context 'idempotence' {
        It 'is a no-op when the include is already present' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:sendgrid.net -all' -IncludeDomain 'sendgrid.net'
            $p.IsNoOp   | Should -BeTrue
            $p.IsSafe   | Should -BeTrue
            $p.NewValue | Should -Be 'v=spf1 include:sendgrid.net -all'
        }

        It 'matches an existing include case-insensitively' {
            # DNS names are case-insensitive, so SendGrid.NET and sendgrid.net
            # are the same include. Adding both would waste a lookup.
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:SendGrid.NET -all' -IncludeDomain 'sendgrid.net'
            $p.IsNoOp | Should -BeTrue
        }
    }

    Context 'the lookup cap is a hard refusal, not a warning' {
        It 'refuses a change that would reach 11 lookups' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord (New-AtCapRecord 10) -IncludeDomain 'one.too.many'
            $p.IsSafe         | Should -BeFalse
            $p.LookupsAfter   | Should -Be 11
            ($p.Blockers -join ' ') | Should -Match 'PermError'
        }

        It 'points the operator at flattening rather than just refusing' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord (New-AtCapRecord 10) -IncludeDomain 'x.com'
            ($p.Blockers -join ' ') | Should -Match 'Flatten'
        }

        It 'allows a change that lands exactly on the cap, but warns' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord (New-AtCapRecord 9) -IncludeDomain 'tenth.example'
            $p.IsSafe       | Should -BeTrue
            $p.LookupsAfter | Should -Be 10
            ($p.Warnings -join ' ') | Should -Match 'last available DNS lookup'
        }

        It 'warns when approaching the cap' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord (New-AtCapRecord 7) -IncludeDomain 'eighth.example'
            $p.IsSafe | Should -BeTrue
            ($p.Warnings -join ' ') | Should -Match 'approaching the limit'
        }
    }

    Context 'refusing to touch what it does not understand' {
        It 'refuses an unparseable current record rather than overwriting it' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'this is not an spf record' -IncludeDomain 'x.com'
            $p.IsSafe | Should -BeFalse
            $p.Action | Should -Be 'none'
        }

        It 'refuses when no include domain is supplied' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 -all' -IncludeDomain ''
            $p.IsSafe | Should -BeFalse
        }
    }

    Context 'record length' {
        It 'refuses a result over the practical TXT limit' {
            $long = 'v=spf1 ' + ((1..40 | ForEach-Object { "ip4:10.$_.0.0/16" }) -join ' ') + ' -all'
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord $long -IncludeDomain 'x.example.com'
            if ($p.NewValue.Length -gt 512) {
                $p.IsSafe | Should -BeFalse
                ($p.Blockers -join ' ') | Should -Match 'characters'
            }
        }
    }

    Context 'records without a terminal all' {
        It 'allows the change but flags the missing all' {
            $p = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:a.com' -IncludeDomain 'b.com'
            $p.IsSafe | Should -BeTrue
            ($p.Warnings -join ' ') | Should -Match "no terminal 'all'"
        }
    }
}

Describe 'New-SPFRemovePlan' {

    It 'removes the named include and recovers its lookup' {
        $p = New-SPFRemovePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:a.com include:b.com -all' -IncludeDomain 'b.com'
        $p.NewValue      | Should -Be 'v=spf1 include:a.com -all'
        $p.LookupsBefore | Should -Be 2
        $p.LookupsAfter  | Should -Be 1
        $p.IsSafe        | Should -BeTrue
    }

    It 'is a no-op when the include is not present' {
        $p = New-SPFRemovePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:a.com -all' -IncludeDomain 'nothere.com'
        $p.IsNoOp | Should -BeTrue
    }

    It 'warns that senders relying on the include will start failing' {
        $p = New-SPFRemovePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:a.com -all' -IncludeDomain 'a.com'
        ($p.Warnings -join ' ') | Should -Match 'begin failing SPF'
    }
}

Describe 'New-DMARCPolicyPlan' {

    Context 'advancing one rung at a time' {
        It 'advances none to quarantine' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=none; rua=mailto:d@acme.com' -TargetPolicy 'quarantine'
            $p.IsSafe   | Should -BeTrue
            $p.NewValue | Should -Match 'p=quarantine'
        }

        It 'advances quarantine to reject' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=quarantine; rua=mailto:d@acme.com' -TargetPolicy 'reject'
            $p.IsSafe | Should -BeTrue
        }

        It 'preserves every other tag the operator had set' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' `
                 -CurrentRecord 'v=DMARC1; p=none; rua=mailto:d@acme.com; ruf=mailto:f@acme.com; adkim=s; aspf=s; fo=1' `
                 -TargetPolicy 'quarantine'
            $p.NewValue | Should -Match 'rua=mailto:d@acme\.com'
            $p.NewValue | Should -Match 'ruf=mailto:f@acme\.com'
            $p.NewValue | Should -Match 'adkim=s'
            $p.NewValue | Should -Match 'fo=1'
        }

        It 'puts v= first and p= second as the RFC requires' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; rua=mailto:d@acme.com; p=none' -TargetPolicy 'quarantine'
            $p.NewValue | Should -Match '^v=DMARC1; p=quarantine'
        }
    }

    Context 'refusing to skip a rung' {
        It 'refuses none straight to reject' {
            # quarantine is recoverable, reject is not. Skipping the middle
            # rung is how an unknown legitimate sender gets silently dropped.
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=none' -TargetPolicy 'reject'
            $p.IsSafe | Should -BeFalse
            ($p.Blockers -join ' ') | Should -Match 'quarantine first'
        }

        It 'allows the skip when explicitly overridden' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=none' -TargetPolicy 'reject' -AllowPolicySkip
            $p.IsSafe | Should -BeTrue
        }

        It 'refuses to enforce on a domain with no DMARC record at all' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord '' -TargetPolicy 'reject'
            $p.IsSafe | Should -BeFalse
            ($p.Blockers -join ' ') | Should -Match 'p=none first'
        }

        It 'allows creating a p=none record from nothing' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord '' -TargetPolicy 'none'
            $p.IsSafe | Should -BeTrue
            $p.Action | Should -Be 'create'
        }
    }

    Context 'pct ramp' {
        It 'emits pct when below 100' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=quarantine' -TargetPolicy 'reject' -TargetPct 25
            $p.NewValue | Should -Match 'pct=25'
        }

        It 'omits pct entirely at 100 rather than writing pct=100' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=quarantine; pct=25' -TargetPolicy 'reject' -TargetPct 100
            $p.NewValue | Should -Not -Match 'pct='
        }
    }

    Context 'weakening and no-ops' {
        It 'warns loudly when enforcement is reduced' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=reject' -TargetPolicy 'none'
            ($p.Warnings -join ' ') | Should -Match 'WEAKENS'
        }

        It 'is a no-op when already at the target' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=reject' -TargetPolicy 'reject'
            $p.IsNoOp | Should -BeTrue
        }

        It 'warns when enforcing without a rua tag' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=DMARC1; p=none' -TargetPolicy 'quarantine'
            ($p.Warnings -join ' ') | Should -Match 'flying blind'
        }

        It 'refuses a record that is not DMARC' {
            $p = New-DMARCPolicyPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 -all' -TargetPolicy 'quarantine'
            $p.IsSafe | Should -BeFalse
        }
    }
}

Describe 'SPF flattening' {

    It 'inlines the ranges behind an include' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:sendgrid.net -all' -Resolver $script:TestResolver
        $p.NewValue | Should -Match 'ip4:167\.89\.0\.0/17'
        $p.NewValue | Should -Match 'ip4:168\.245\.0\.0/17'
        $p.NewValue | Should -Not -Match 'include:'
    }

    It 'recurses into nested includes' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:_spf.google.com -all' -Resolver $script:TestResolver
        # _netblocks.google.com is only reachable through _spf.google.com
        $p.NewValue | Should -Match 'ip4:35\.191\.0\.0/16'
    }

    It 'reduces the lookup count' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:_spf.google.com include:sendgrid.net -all' -Resolver $script:TestResolver
        $p.LookupsBefore | Should -Be 2
        $p.LookupsAfter  | Should -Be 0
        $p.IsSafe        | Should -BeTrue
    }

    It 'preserves mechanisms that cannot be flattened without narrowing the authorized set' {
        # a/mx/ptr/exists resolve against the SENDING host at evaluation time.
        # Replacing them with today's answer would silently change meaning.
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:sendgrid.net a mx -all' -Resolver $script:TestResolver
        $p.NewValue     | Should -Match '\ba\b'
        $p.NewValue     | Should -Match '\bmx\b'
        $p.LookupsAfter | Should -Be 2
    }

    It 'keeps the all mechanism last' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:sendgrid.net -all' -Resolver $script:TestResolver
        $p.NewValue | Should -Match '\-all$'
    }

    It 'deduplicates ranges reached by more than one path' {
        $script:TestZone['dup-a.example'] = 'v=spf1 ip4:10.0.0.0/8 -all'
        $script:TestZone['dup-b.example'] = 'v=spf1 ip4:10.0.0.0/8 -all'
        try {
            $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:dup-a.example include:dup-b.example -all' -Resolver $script:TestResolver
            ([regex]::Matches($p.NewValue, 'ip4:10\.0\.0\.0/8')).Count | Should -Be 1
        } finally {
            $script:TestZone.Remove('dup-a.example'); $script:TestZone.Remove('dup-b.example')
        }
    }

    It 'sets a refresh-by date because a flattened record goes stale' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:sendgrid.net -all' -Resolver $script:TestResolver -RefreshDays 30
        $p.RefreshBy | Should -Match '^\d{4}-\d{2}-\d{2}$'
        ($p.Warnings -join ' ') | Should -Match 'point-in-time snapshot'
    }

    It 'refuses when an include cannot be resolved' {
        # A partial flatten drops authorized senders, which is worse than not
        # flattening: legitimate mail starts failing with no obvious cause.
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:nonexistent.example -all' -Resolver $script:TestResolver
        $p.IsSafe | Should -BeFalse
        ($p.Blockers -join ' ') | Should -Match 'No SPF record found'
    }

    It 'survives a cyclic include chain' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:loop-a.example -all' -Resolver $script:TestResolver
        # Must terminate. Whether it can produce a useful record is secondary.
        $p | Should -Not -BeNullOrEmpty
    }

    It 'reports nothing to do when there are no includes' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 ip4:1.2.3.4 -all' -Resolver $script:TestResolver
        $p.Action  | Should -Be 'none'
        $p.Summary | Should -Match 'no include'
    }

    It 'refuses when flattening would not reduce the lookup count' {
        # Flattening carries a permanent maintenance burden. Taking it on for
        # no gain is a bad trade, so the planner declines.
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:has-mx.example -all' -Resolver $script:TestResolver
        if ($p.LookupsAfter -ge $p.LookupsBefore) {
            $p.IsSafe | Should -BeFalse
            ($p.Blockers -join ' ') | Should -Match 'not reduce'
        }
    }
}

Describe 'Invoke-DNSChangePlan' {

    BeforeEach {
        $script:provider = New-InMemoryDNSProvider -InitialZone @{ 'TXT|acme.com' = 'v=spf1 include:a.com -all' }
        $script:plan = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:a.com -all' -IncludeDomain 'b.com'
    }

    Context 'nothing is written without confirmation' {
        It 'defaults to a dry run' {
            $r = Invoke-DNSChangePlan -Plan $script:plan -Provider $script:provider
            $r.DryRun  | Should -BeTrue
            $r.Applied | Should -BeFalse
        }

        It 'leaves the zone untouched on a dry run' {
            $null = Invoke-DNSChangePlan -Plan $script:plan -Provider $script:provider
            (& $script:provider.GetRecords 'acme.com' 'TXT')[0].Value | Should -Be 'v=spf1 include:a.com -all'
        }

        It 'still reports what would change, so the caller can show a diff' {
            $r = Invoke-DNSChangePlan -Plan $script:plan -Provider $script:provider
            $r.Snapshot | Should -Be 'v=spf1 include:a.com -all'
            $r.NewValue | Should -Be 'v=spf1 include:a.com include:b.com -all'
        }
    }

    Context 'applying' {
        It 'writes when confirmed' {
            $r = Invoke-DNSChangePlan -Plan $script:plan -Provider $script:provider -Confirm
            $r.Applied | Should -BeTrue
            (& $script:provider.GetRecords 'acme.com' 'TXT')[0].Value | Should -Be 'v=spf1 include:a.com include:b.com -all'
        }

        It 'snapshots the live value, not the value the plan was built from' {
            # The zone changed after the plan was made. Rollback has to restore
            # what was actually there, or it clobbers someone else's edit.
            $null = & $script:provider.SetRecord 'acme.com' 'TXT' 'v=spf1 include:changed-underneath.com -all' 300
            $r = Invoke-DNSChangePlan -Plan $script:plan -Provider $script:provider -Confirm
            $r.Snapshot | Should -Be 'v=spf1 include:changed-underneath.com -all'
        }

        It 'records who applied it and why' {
            $r = Invoke-DNSChangePlan -Plan $script:plan -Provider $script:provider -Confirm -AppliedBy 'alex' -Reason 'ticket 42'
            $r.AppliedBy | Should -Be 'alex'
            $r.Reason    | Should -Be 'ticket 42'
            $r.AppliedAt | Should -Not -BeNullOrEmpty
        }
    }

    Context 'refusing an unsafe plan' {
        It 'will not apply a blocked plan even with confirmation' {
            $unsafe = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord (New-AtCapRecord 10) -IncludeDomain 'x.com'
            $r = Invoke-DNSChangePlan -Plan $unsafe -Provider $script:provider -Confirm
            $r.Applied | Should -BeFalse
            $r.Error   | Should -Match 'not safe'
        }

        It 'leaves the zone untouched when it refuses' {
            $unsafe = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord (New-AtCapRecord 10) -IncludeDomain 'x.com'
            $null = Invoke-DNSChangePlan -Plan $unsafe -Provider $script:provider -Confirm
            (& $script:provider.GetRecords 'acme.com' 'TXT')[0].Value | Should -Be 'v=spf1 include:a.com -all'
        }
    }

    Context 'no-op plans' {
        It 'writes nothing when the change is already in place' {
            $noop = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:a.com -all' -IncludeDomain 'a.com'
            $r = Invoke-DNSChangePlan -Plan $noop -Provider $script:provider -Confirm
            $r.Applied | Should -BeFalse
            $r.Error   | Should -BeNullOrEmpty
        }
    }
}

Describe 'Undo-DNSChangePlan' {

    BeforeEach {
        $script:provider = New-InMemoryDNSProvider -InitialZone @{ 'TXT|acme.com' = 'v=spf1 include:original.com -all' }
        $plan = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:original.com -all' -IncludeDomain 'new.com'
        $script:applied = Invoke-DNSChangePlan -Plan $plan -Provider $script:provider -Confirm
    }

    It 'restores the snapshot' {
        $u = Undo-DNSChangePlan -AppliedResult $script:applied -Provider $script:provider -Confirm
        $u.Restored | Should -BeTrue
        (& $script:provider.GetRecords 'acme.com' 'TXT')[0].Value | Should -Be 'v=spf1 include:original.com -all'
    }

    It 'defaults to a dry run' {
        $u = Undo-DNSChangePlan -AppliedResult $script:applied -Provider $script:provider
        $u.DryRun   | Should -BeTrue
        $u.Restored | Should -BeFalse
        (& $script:provider.GetRecords 'acme.com' 'TXT')[0].Value | Should -Match 'new\.com'
    }

    It 'refuses to roll back something that was never applied' {
        $dry = Invoke-DNSChangePlan -Plan (New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 -all' -IncludeDomain 'z.com') -Provider $script:provider
        $u = Undo-DNSChangePlan -AppliedResult $dry -Provider $script:provider -Confirm
        $u.Restored | Should -BeFalse
        $u.Error    | Should -Match 'never applied'
    }
}

Describe 'Test-DNSChangePropagation' {

    It 'reports success when the expected value is visible' {
        $resolver = { param($n, $t) 'v=spf1 include:published.com -all' }
        $r = Test-DNSChangePropagation -Name 'acme.com' -ExpectedValue 'include:published.com' -Resolver $resolver -TimeoutSeconds 2 -PollSeconds 1
        $r.IsPropagated | Should -BeTrue
    }

    It 'times out when the old value is still being served' {
        $resolver = { param($n, $t) 'v=spf1 include:old.com -all' }
        $r = Test-DNSChangePropagation -Name 'acme.com' -ExpectedValue 'include:new.com' -Resolver $resolver -TimeoutSeconds 2 -PollSeconds 1
        $r.IsPropagated | Should -BeFalse
        $r.Error        | Should -Match 'TTL'
    }
}

Describe 'DNS providers' {

    Context 'the in-memory test double' {
        It 'round-trips a record' {
            $p = New-InMemoryDNSProvider
            $null = & $p.SetRecord 'x.com' 'TXT' 'hello' 300
            (& $p.GetRecords 'x.com' 'TXT')[0].Value | Should -Be 'hello'
        }

        It 'returns nothing for an absent record' {
            # @() wrapping matters: PowerShell unwraps an empty array to $null,
            # so .Count on the bare call throws rather than reporting 0.
            $p = New-InMemoryDNSProvider
            @(& $p.GetRecords 'absent.com' 'TXT').Count | Should -Be 0
        }
    }

    Context 'the manual fallback' {
        It 'reports itself as not automatic so callers render instructions' {
            (New-ManualDNSProvider).IsAutomatic | Should -BeFalse
        }

        It 'records what it was asked to publish instead of failing' {
            # An unsupported registrar degrades to copy-paste, not to an error.
            $p = New-ManualDNSProvider
            $r = & $p.SetRecord 'acme.com' 'TXT' 'v=spf1 -all' 300
            $r.Success       | Should -BeTrue
            $p.Emitted.Count | Should -Be 1
            $p.Emitted[0].Value | Should -Be 'v=spf1 -all'
        }
    }

    Context 'provider contract' {
        It '<name> exposes the three required operations' -ForEach @(
            @{ name = 'InMemory' }
            @{ name = 'Manual'   }
        ) {
            $p = if ($name -eq 'InMemory') { New-InMemoryDNSProvider } else { New-ManualDNSProvider }
            $p.PSObject.Properties.Name | Should -Contain 'GetRecords'
            $p.PSObject.Properties.Name | Should -Contain 'SetRecord'
            $p.PSObject.Properties.Name | Should -Contain 'RemoveRecord'
            $p.PSObject.Properties.Name | Should -Contain 'IsAutomatic'
        }
    }
}

Describe 'Write-RemediationAudit' {

    BeforeEach {
        $script:stateDir = Join-Path ([System.IO.Path]::GetTempPath()) ("remaudit_" + [guid]::NewGuid().ToString('N'))
        $script:provider = New-InMemoryDNSProvider -InitialZone @{ 'TXT|acme.com' = 'v=spf1 include:a.com -all' }
        $plan = New-SPFIncludePlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:a.com -all' -IncludeDomain 'b.com'
        $script:applied = Invoke-DNSChangePlan -Plan $plan -Provider $script:provider -Confirm -AppliedBy 'alex' -Reason 'ticket 42'
    }
    AfterEach {
        if (Test-Path $script:stateDir) { Remove-Item $script:stateDir -Recurse -Force -EA SilentlyContinue }
    }

    It 'records both the previous and the new value' {
        $e = Write-RemediationAudit -StateDir $script:stateDir -AppliedResult $script:applied -ClientId 'c-acme'
        $e.previousValue | Should -Be 'v=spf1 include:a.com -all'
        $e.newValue      | Should -Be 'v=spf1 include:a.com include:b.com -all'
    }

    It 'records who, when and why - the evidence behind an invoice' {
        $e = Write-RemediationAudit -StateDir $script:stateDir -AppliedResult $script:applied -ClientId 'c-acme'
        $e.appliedBy | Should -Be 'alex'
        $e.reason    | Should -Be 'ticket 42'
        $e.clientId  | Should -Be 'c-acme'
        $e.appliedAt | Should -Not -BeNullOrEmpty
    }

    It 'appends rather than overwriting, so history survives' {
        $null = Write-RemediationAudit -StateDir $script:stateDir -AppliedResult $script:applied -ClientId 'c-acme'
        $null = Write-RemediationAudit -StateDir $script:stateDir -AppliedResult $script:applied -ClientId 'c-acme'
        $saved = Get-Content (Join-Path $script:stateDir 'remediation-audit.json') -Raw | ConvertFrom-Json
        @($saved.changes).Count | Should -Be 2
    }

    It 'creates the state directory if it does not exist' {
        Test-Path $script:stateDir | Should -BeFalse
        $null = Write-RemediationAudit -StateDir $script:stateDir -AppliedResult $script:applied
        Test-Path (Join-Path $script:stateDir 'remediation-audit.json') | Should -BeTrue
    }

    It 'gives every entry a unique id' {
        $a = Write-RemediationAudit -StateDir $script:stateDir -AppliedResult $script:applied
        $b = Write-RemediationAudit -StateDir $script:stateDir -AppliedResult $script:applied
        $a.id | Should -Not -Be $b.id
    }
}

Describe 'New-DKIMPlan' {

    BeforeAll {
        $catalogPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'sender-catalog.json'
        $script:catalog = Get-Content $catalogPath -Raw -Encoding UTF8 | ConvertFrom-Json
        function Get-Service { param($id) $script:catalog.services | Where-Object id -eq $id | Select-Object -First 1 }
    }

    It 'substitutes the customer domain into a CNAME template' {
        $svc = Get-Service 'sendgrid'
        $p = New-DKIMPlan -Domain 'acme.com' -CatalogService $svc
        ($p.Records | ForEach-Object { "$($_.Name) $($_.Value)" }) -join ' ' | Should -Match 'acme\.com'
    }

    It 'substitutes the hyphenated domain form used by Microsoft 365' {
        $svc = Get-Service 'm365'
        $p = New-DKIMPlan -Domain 'acme.com' -CatalogService $svc
        ($p.Records | ForEach-Object { $_.Value }) -join ' ' | Should -Match 'acme-com'
    }

    It 'reports tokens it cannot resolve instead of emitting a broken record' {
        # A record containing a literal {account-id} would publish and then
        # silently fail to resolve, which is worse than not publishing.
        $svc = Get-Service 'sendgrid'
        $p = New-DKIMPlan -Domain 'acme.com' -CatalogService $svc
        $p.UnresolvedTokens.Count | Should -BeGreaterThan 0
        $p.Summary | Should -Match 'admin console'
    }

    It 'accepts caller-supplied placeholder values' {
        $svc = Get-Service 'sendgrid'
        $p = New-DKIMPlan -Domain 'acme.com' -CatalogService $svc -Placeholders @{ 'account-id' = '12345' }
        ($p.Records | ForEach-Object { $_.Value }) -join ' ' | Should -Match '12345'
        $p.UnresolvedTokens | Should -Not -Contain 'account-id'
    }

    It 'explains rather than fabricating when a service has no custom DKIM' {
        $svc = Get-Service 'notion'
        $p = New-DKIMPlan -Domain 'acme.com' -CatalogService $svc
        $p.IsActionable | Should -BeFalse
        $p.Summary      | Should -Not -BeNullOrEmpty
    }

    It 'carries the vendor instructions through' {
        $svc = Get-Service 'm365'
        $p = New-DKIMPlan -Domain 'acme.com' -CatalogService $svc
        $p.Instructions | Should -Match 'DKIM'
    }
}
