<#
    DNS provider configuration: where a domain's zone lives, and the bridge
    from a stored credential to a provider that can write to it.

    The invariants worth pinning down are about what must NOT happen: a
    credential must never land in the config file, a half-saved config must
    never look configured, deleting a config must not orphan its secret, and
    an unusable provider must degrade to copy-paste rather than to nothing.
#>

BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $root 'Invoke-DNSRemediation.ps1')   # dot-sources the secret store itself

    $script:Vault = @{}
    $script:StubAvailable = $true
    Register-SecretBackend -Name 'stub' -Description 'test backend' `
        -Test        { $script:StubAvailable } `
        -SetSecret   { param($Ref, $Value) $script:Vault[$Ref] = $Value } `
        -GetSecret   { param($Ref) if ($script:Vault.ContainsKey($Ref)) { $script:Vault[$Ref] } else { $null } } `
        -RemoveSecret{ param($Ref) $script:Vault.Remove($Ref) | Out-Null }

    function NewWorkDir {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ("dmarcprov_" + [guid]::NewGuid().ToString('N').Substring(0,10))
        New-Item -Path (Join-Path $d 'State') -ItemType Directory -Force | Out-Null
        return $d
    }
    function ConfigText { param($Dir) Get-Content (Get-DNSProviderConfigPath -WorkingDir $Dir) -Raw -Encoding UTF8 }
}

Describe 'saving a provider config' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true; $script:Dir = NewWorkDir }
    AfterEach  { Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'stores the coordinates and a ref, never the secret' {
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId = 'zone-abc' } -Secret 'cf-super-secret' -Backend 'stub' | Out-Null

        $text = ConfigText $script:Dir
        $text | Should -Not -Match 'cf-super-secret' -Because 'the credential must never touch the config file'
        $text | Should -Match 'zone-abc'
        $text | Should -Match 'dmarc\.local\.cloudflare\.'
    }

    It 'puts the secret in the backend, reachable through the saved ref' {
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId = 'z' } -Secret 'tok-1' -Backend 'stub'
        Get-StoredSecret -Ref $e.credential_ref -Backend 'stub' | Should -Be 'tok-1'
    }

    It 'reuses the ref on rotation so the audit trail stays continuous' {
        $a = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId = 'z' } -Secret 'old' -Backend 'stub'
        $b = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId = 'z' } -Secret 'new' -Backend 'stub'
        $b.credential_ref | Should -Be $a.credential_ref
        Get-StoredSecret -Ref $b.credential_ref -Backend 'stub' | Should -Be 'new'
    }

    It 'writes nothing at all when the secret cannot be stored' {
        # A config row pointing at a secret that was never stored reads as
        # "configured" and fails at the provider on every single apply.
        $script:StubAvailable = $false
        { Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId = 'z' } -Secret 'tok' -Backend 'stub' } | Should -Throw '*not available*'
        Test-Path (Get-DNSProviderConfigPath -WorkingDir $script:Dir) | Should -BeFalse
    }

    It 'stores no credential for the manual provider' {
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'manual' -Backend 'stub'
        $e.credential_ref | Should -BeNullOrEmpty
        $script:Vault.Count | Should -Be 0
    }

    It 'rejects a provider it cannot drive' {
        { Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'route53' -Backend 'stub' } | Should -Throw
    }

    It 'keeps two domains independent' {
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'a.com' -Provider 'cloudflare' -Coordinates @{ zoneId='za' } -Secret 'ta' -Backend 'stub' | Out-Null
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'b.com' -Provider 'cloudflare' -Coordinates @{ zoneId='zb' } -Secret 'tb' -Backend 'stub' | Out-Null
        (Get-DNSProviderConfig -WorkingDir $script:Dir -Domain 'a.com').config_json | Should -Match 'za'
        (Get-DNSProviderConfig -WorkingDir $script:Dir -Domain 'b.com').config_json | Should -Match 'zb'
    }
}

Describe 'reading a provider config' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true; $script:Dir = NewWorkDir }
    AfterEach  { Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'returns null when nothing is configured' {
        Get-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' | Should -BeNullOrEmpty
    }

    It 'returns null rather than throwing on a corrupt config file' {
        Set-Content -Path (Get-DNSProviderConfigPath -WorkingDir $script:Dir) -Value '{not json' -Encoding UTF8
        { Get-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' } | Should -Not -Throw
        Get-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' | Should -BeNullOrEmpty
    }

    It 'derives the same key on write and read for the wildcard' {
        # Naive sanitising maps '*' to '_', which then never matches a lookup
        # for '*'. The wildcard entry silently exists and is never found.
        ConvertTo-ProviderKey -Domain '*' | Should -Be (ConvertTo-ProviderKey -Domain '*')
        ConvertTo-ProviderKey -Domain '*' | Should -Not -Be (ConvertTo-ProviderKey -Domain '_')
    }

    It 'falls back to the wildcard entry for an unlisted domain' {
        # An MSP with one Cloudflare account configures it once, not per domain.
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain '*' -Provider 'cloudflare' -Coordinates @{ zoneId='shared' } -Secret 'tok' -Backend 'stub' | Out-Null
        (Get-DNSProviderConfig -WorkingDir $script:Dir -Domain 'anything.com').config_json | Should -Match 'shared'
    }

    It 'prefers a domain-specific entry over the wildcard' {
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain '*' -Provider 'cloudflare' -Coordinates @{ zoneId='shared' } -Secret 'tok' -Backend 'stub' | Out-Null
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'special.com' -Provider 'cloudflare' -Coordinates @{ zoneId='own' } -Secret 'tok2' -Backend 'stub' | Out-Null
        (Get-DNSProviderConfig -WorkingDir $script:Dir -Domain 'special.com').config_json | Should -Match 'own'
    }

    It 'lists every configured provider' {
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'a.com' -Provider 'manual' -Backend 'stub' | Out-Null
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'b.com' -Provider 'manual' -Backend 'stub' | Out-Null
        @(Get-AllDNSProviderConfigs -WorkingDir $script:Dir).Count | Should -Be 2
    }

    It 'returns an empty list, not null, when nothing is configured' {
        { @(Get-AllDNSProviderConfigs -WorkingDir $script:Dir).Count } | Should -Not -Throw
        @(Get-AllDNSProviderConfigs -WorkingDir $script:Dir).Count | Should -Be 0
    }
}

Describe 'removing a provider config' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true; $script:Dir = NewWorkDir }
    AfterEach  { Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'deletes the stored credential too, leaving no orphan' {
        # A credential outliving the row explaining what it was for is one
        # nobody will ever rotate or revoke.
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId='z' } -Secret 'tok' -Backend 'stub'
        Remove-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Backend 'stub'
        $script:Vault.ContainsKey($e.credential_ref) | Should -BeFalse
        Get-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' | Should -BeNullOrEmpty
    }

    It 'leaves other domains and their credentials alone' {
        Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'a.com' -Provider 'cloudflare' -Coordinates @{zoneId='za'} -Secret 'ta' -Backend 'stub' | Out-Null
        $b = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'b.com' -Provider 'cloudflare' -Coordinates @{zoneId='zb'} -Secret 'tb' -Backend 'stub'
        Remove-DNSProviderConfig -WorkingDir $script:Dir -Domain 'a.com' -Backend 'stub'
        Get-StoredSecret -Ref $b.credential_ref -Backend 'stub' | Should -Be 'tb'
    }

    It 'is idempotent on a domain that was never configured' {
        { Remove-DNSProviderConfig -WorkingDir $script:Dir -Domain 'nope.com' -Backend 'stub' } | Should -Not -Throw
    }
}

Describe 'New-DNSProviderFromConfig' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true; $script:Dir = NewWorkDir }
    AfterEach  { Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'falls back to Manual, never to nothing, when unconfigured' {
        # Degrading to copy-paste is the right failure mode for a tool that
        # edits production mail routing.
        $r = New-DNSProviderFromConfig -ProviderConfig $null -Backend 'stub'
        $r.Provider | Should -Not -BeNullOrEmpty
        $r.Provider.Name | Should -Be 'Manual'
        $r.IsAutomatic | Should -BeFalse
    }

    It 'explains why it fell back' {
        (New-DNSProviderFromConfig -ProviderConfig $null -Backend 'stub').Reason | Should -Match 'No DNS provider is configured'
    }

    It 'builds an automatic Cloudflare provider from a complete config' {
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId = 'zone-1' } -Secret 'cf-tok' -Backend 'stub'
        $r = New-DNSProviderFromConfig -ProviderConfig $e -Backend 'stub'
        $r.IsAutomatic | Should -BeTrue
        $r.Provider.Name | Should -Be 'Cloudflare'
    }

    It 'builds an automatic Azure DNS provider from a complete config' {
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'azuredns' `
            -Coordinates @{ subscriptionId='s'; resourceGroup='rg'; zoneName='example.com' } -Secret 'az-tok' -Backend 'stub'
        $r = New-DNSProviderFromConfig -ProviderConfig $e -Backend 'stub'
        $r.IsAutomatic | Should -BeTrue
    }

    It 'treats manual as configured but not automatic' {
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'manual' -Backend 'stub'
        $r = New-DNSProviderFromConfig -ProviderConfig $e -Backend 'stub'
        $r.IsAutomatic | Should -BeFalse
        $r.Provider.Name | Should -Be 'Manual'
    }

    It 'falls back to Manual when the credential is gone' {
        # Revoked or wiped out of band. Must not crash the plan dialog.
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId='z' } -Secret 'tok' -Backend 'stub'
        $script:Vault.Clear()
        $r = New-DNSProviderFromConfig -ProviderConfig $e -Backend 'stub'
        $r.IsAutomatic | Should -BeFalse
        $r.Provider.Name | Should -Be 'Manual'
        $r.Reason | Should -Match 'No credential has been saved'
    }

    It 'falls back to Manual when the backend is unavailable' {
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{ zoneId='z' } -Secret 'tok' -Backend 'stub'
        $script:StubAvailable = $false
        $r = New-DNSProviderFromConfig -ProviderConfig $e -Backend 'stub'
        $r.IsAutomatic | Should -BeFalse
        $r.Reason | Should -Match 'not available'
    }

    It 'falls back to Manual when coordinates are incomplete' {
        $e = Set-DNSProviderConfig -WorkingDir $script:Dir -Domain 'example.com' -Provider 'cloudflare' `
            -Coordinates @{} -Secret 'tok' -Backend 'stub'
        $r = New-DNSProviderFromConfig -ProviderConfig $e -Backend 'stub'
        $r.IsAutomatic | Should -BeFalse
        $r.Reason | Should -Match 'zoneId'
    }

    It 'never returns a provider that cannot be called' {
        # Whatever the failure, the caller gets something with the provider
        # contract on it.
        foreach ($cfg in @(
            $null,
            [PSCustomObject]@{ provider = 'cloudflare'; credential_ref = 'garbage'; config_json = '{}' },
            [PSCustomObject]@{ provider = 'route53';    credential_ref = '';        config_json = '{}' }
        )) {
            $r = New-DNSProviderFromConfig -ProviderConfig $cfg -Backend 'stub'
            $r.Provider | Should -Not -BeNullOrEmpty
            $r.Provider.SetRecord | Should -Not -BeNullOrEmpty
        }
    }
}
