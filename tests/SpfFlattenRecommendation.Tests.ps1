<#
    Whether flattening is worth doing, as distinct from whether it is safe.

    Flattening copies a third party's IP list into the customer's own zone. It
    buys lookup headroom and takes on a standing obligation: when that provider
    adds ranges, mail from them fails SPF until the record is re-flattened.

    So "safe" and "worth doing" are genuinely different questions, and the
    engine answers them separately. Folding the second into IsSafe would refuse
    a change that will not break anything, which is the same advice-as-blockers
    mistake the enforcement engine already had to have fixed.
#>

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-DNSRemediation.ps1')

    # A zone with enough distinct includes to build records of any lookup cost.
    $script:Zone = @{}
    foreach ($i in 1..12) { $script:Zone["inc$i.example"] = "v=spf1 ip4:10.$i.0.0/16 -all" }

    $script:Resolver = {
        param($Name, $Type)
        if ($script:Zone.ContainsKey($Name)) { return @($script:Zone[$Name]) }
        return @()
    }

    function RecordWith {
        # An SPF record costing exactly N lookups.
        param([int]$Lookups)
        $inc = (1..$Lookups | ForEach-Object { "include:inc$_.example" }) -join ' '
        return "v=spf1 $inc -all"
    }
    function PlanFor {
        param([int]$Lookups, [int]$Threshold = 8)
        New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord (RecordWith $Lookups) `
            -Resolver $script:Resolver -RecommendAtLookups $Threshold
    }
}

Describe 'safe and recommended are separate judgements' {

    It 'reports a low-lookup record as safe but not recommended' {
        $p = PlanFor 2
        $p.IsSafe        | Should -BeTrue  -Because 'publishing it would not break mail'
        $p.IsRecommended | Should -BeFalse -Because 'it gains headroom the record is not short of'
    }

    It 'recommends a record at the threshold' {
        $p = PlanFor 8
        $p.IsSafe        | Should -BeTrue
        $p.IsRecommended | Should -BeTrue
    }

    It 'recommends a record above the threshold' {
        (PlanFor 9).IsRecommended | Should -BeTrue
    }

    It 'does not recommend one lookup below the threshold' {
        (PlanFor 7).IsRecommended | Should -BeFalse
    }

    It 'honours a caller-supplied threshold' {
        # An operator who knows five senders are coming has a real reason.
        (PlanFor -Lookups 3 -Threshold 3).IsRecommended | Should -BeTrue
        (PlanFor -Lookups 3 -Threshold 9).IsRecommended | Should -BeFalse
    }

    It 'never recommends a plan it refused' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:nonexistent.example -all' -Resolver $script:Resolver
        $p.IsSafe        | Should -BeFalse
        $p.IsRecommended | Should -BeFalse
    }

    It 'explains itself either way' -ForEach @(
        @{ Lookups = 2 }
        @{ Lookups = 9 }
    ) {
        $p = PlanFor $Lookups
        $p.Recommendation | Should -Not -BeNullOrEmpty
        $p.Recommendation | Should -Match '\d'   # cites the actual count
    }

    It 'names the staleness obligation when not recommending' {
        $p = PlanFor 2
        $p.Recommendation | Should -Match "another provider's IP list|re-running"
    }
}

Describe 'the staleness warning is never silent' {
    # The whole risk of flattening. It must appear on every plan that produces
    # a record, recommended or not.

    It 'warns on a recommended plan' {
        @((PlanFor 9).Warnings) -join ' ' | Should -Match 'point-in-time snapshot'
    }

    It 'warns on an unrecommended plan too' {
        @((PlanFor 2).Warnings) -join ' ' | Should -Match 'point-in-time snapshot'
    }

    It 'gives a concrete date to re-flatten by' {
        $p = PlanFor 9
        $p.RefreshBy | Should -Match '^\d{4}-\d{2}-\d{2}$'
        @($p.Warnings) -join ' ' | Should -Match ([regex]::Escape($p.RefreshBy))
    }
}

Describe 'the existing safety guarantees still hold' {
    # Guarding against the recommendation split having weakened anything.

    It 'still refuses when an include cannot be resolved' {
        # Flattening a partial set silently drops authorized senders.
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 include:inc1.example include:missing.example -all' -Resolver $script:Resolver
        $p.IsSafe | Should -BeFalse
        @($p.Blockers).Count | Should -BeGreaterThan 0
        @($p.Blockers) -join ' ' | Should -Match 'missing\.example' -Because 'the blocker must name which include failed'
        $p.Summary | Should -Match 'REFUSED'
    }

    It 'still refuses when flattening would not reduce lookups' {
        $p = New-SPFFlattenPlan -Domain 'acme.com' -CurrentRecord 'v=spf1 a mx -all' -Resolver $script:Resolver
        $p.IsSafe | Should -BeFalse
    }

    It 'still reduces the lookup count on a record it accepts' {
        $p = PlanFor 9
        $p.LookupsAfter | Should -BeLessThan $p.LookupsBefore
    }

    It 'still preserves the all mechanism' {
        (PlanFor 9).NewValue | Should -Match '\-all$'
    }
}
