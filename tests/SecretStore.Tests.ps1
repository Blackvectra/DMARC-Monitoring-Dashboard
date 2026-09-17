<#
    Secret storage.

    The database holds a pointer, never a credential. These tests exist mostly
    to pin down the failure behaviour, because the dangerous failures here are
    the quiet ones: a backend that is unavailable and silently stores plaintext
    anyway, or a decrypt failure reported as "not configured" so an operator
    re-enters a credential that was already correct.

    A stub backend stands in for DPAPI so the contract is testable off Windows.
    The DPAPI backend's own availability check is tested directly.
#>

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-SecretStore.ps1')

    # In-memory backend. Mirrors the DPAPI backend's contract exactly: missing
    # ref returns $null, a stored-but-undecryptable value throws.
    $script:Vault = @{}
    $script:StubAvailable = $true
    Register-SecretBackend -Name 'stub' -Description 'test backend' `
        -Test        { $script:StubAvailable } `
        -SetSecret   { param($Ref, $Value) $script:Vault[$Ref] = $Value } `
        -GetSecret   { param($Ref)
                        if (-not $script:Vault.ContainsKey($Ref)) { return $null }
                        if ($script:Vault[$Ref] -eq '<<CORRUPT>>') { throw 'A secret is stored but could not be decrypted.' }
                        return $script:Vault[$Ref] } `
        -RemoveSecret{ param($Ref) $script:Vault.Remove($Ref) | Out-Null }

    function NewRef { param([string]$Purpose = 'cloudflare') New-CredentialRef -TenantId 't-nls' -Purpose $Purpose }
}

Describe 'New-CredentialRef' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'mints a ref that passes its own shape check' {
        Test-CredentialRefShape -Ref (NewRef) | Should -BeTrue
    }

    It 'never returns the same ref twice' {
        $refs = 1..200 | ForEach-Object { NewRef }
        (@($refs | Sort-Object -Unique)).Count | Should -Be 200
    }

    It 'namespaces by tenant so two tenants cannot collide' {
        $a = New-CredentialRef -TenantId 't-nls'   -Purpose 'cloudflare'
        $b = New-CredentialRef -TenantId 't-rival' -Purpose 'cloudflare'
        $a | Should -Match '\.t-nls\.'
        $b | Should -Match '\.t-rival\.'
    }

    It 'carries the purpose so an audit trail is readable' {
        (New-CredentialRef -TenantId 't-nls' -Purpose 'azuredns') | Should -Match '\.azuredns\.'
    }

    It 'rejects a tenant id carrying a path separator' {
        # A ref becomes a registry value name, so this is the check that keeps
        # a crafted row inside its own storage namespace.
        { New-CredentialRef -TenantId '../../etc' -Purpose 'cloudflare' } | Should -Throw
    }

    It 'rejects a purpose carrying a wildcard' {
        { New-CredentialRef -TenantId 't-nls' -Purpose '*' } | Should -Throw
    }
}

Describe 'Test-CredentialRefShape' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'rejects a hand-written ref' {
        Test-CredentialRefShape -Ref 'cloudflare-token' | Should -BeFalse
    }

    It 'rejects null, empty and whitespace' -ForEach @(
        @{ Ref = $null }
        @{ Ref = '' }
        @{ Ref = '   ' }
    ) {
        Test-CredentialRefShape -Ref $Ref | Should -BeFalse
    }

    It 'rejects a ref containing a path traversal' {
        Test-CredentialRefShape -Ref 'dmarc.t-nls.cloudflare.../../../secret' | Should -BeFalse
    }

    It 'rejects a ref whose random component is the wrong length' {
        Test-CredentialRefShape -Ref 'dmarc.t-nls.cloudflare.abc' | Should -BeFalse
    }
}

Describe 'storing and reading a secret' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'returns exactly what was stored' {
        $r = NewRef
        Set-StoredSecret -Ref $r -Value 'cf-token-abc123' -Backend 'stub'
        Get-StoredSecret -Ref $r -Backend 'stub' | Should -Be 'cf-token-abc123'
    }

    It 'returns null for a ref that was never stored' {
        # Ordinary "not configured yet", not an error.
        Get-StoredSecret -Ref (NewRef) -Backend 'stub' | Should -BeNullOrEmpty
    }

    It 'replaces the value on rotation, keeping the same ref' {
        $r = NewRef
        Set-StoredSecret -Ref $r -Value 'old-token' -Backend 'stub'
        Set-StoredSecret -Ref $r -Value 'new-token' -Backend 'stub'
        Get-StoredSecret -Ref $r -Backend 'stub' | Should -Be 'new-token'
    }

    It 'keeps two refs independent' {
        $a = NewRef; $b = NewRef
        Set-StoredSecret -Ref $a -Value 'token-a' -Backend 'stub'
        Set-StoredSecret -Ref $b -Value 'token-b' -Backend 'stub'
        Get-StoredSecret -Ref $a -Backend 'stub' | Should -Be 'token-a'
        Get-StoredSecret -Ref $b -Backend 'stub' | Should -Be 'token-b'
    }

    It 'refuses to store an empty secret' {
        # Stored-empty looks configured and fails at the provider every time.
        { Set-StoredSecret -Ref (NewRef) -Value '' -Backend 'stub' } | Should -Throw '*empty secret*'
    }

    It 'refuses a hand-written ref on write' {
        { Set-StoredSecret -Ref 'my-token' -Value 'x' -Backend 'stub' } | Should -Throw '*Malformed credential reference*'
    }

    It 'refuses a hand-written ref on read' {
        { Get-StoredSecret -Ref 'my-token' -Backend 'stub' } | Should -Throw '*Malformed credential reference*'
    }
}

Describe 'the ref never carries the secret' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'does not contain the secret value' {
        $r = NewRef
        Set-StoredSecret -Ref $r -Value 'super-secret-token' -Backend 'stub'
        $r | Should -Not -Match 'super-secret-token'
    }

    It 'is not reversible to the secret by any part of the ref' {
        # Every component of the ref is either a caller-supplied non-secret or
        # random. Storing a different secret under a ref minted from identical
        # inputs must not change the ref's shape or content in a way that
        # depends on the secret.
        $r1 = New-CredentialRef -TenantId 't-nls' -Purpose 'cloudflare'
        $r2 = New-CredentialRef -TenantId 't-nls' -Purpose 'cloudflare'
        Set-StoredSecret -Ref $r1 -Value 'aaaa' -Backend 'stub'
        Set-StoredSecret -Ref $r2 -Value 'zzzzzzzzzzzzzzzzzzzz' -Backend 'stub'
        # Same length regardless of secret length: nothing about the secret leaks.
        $r1.Length | Should -Be $r2.Length
    }
}

Describe 'an unavailable backend never degrades quietly' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }

    # The single most important behaviour in this file. A store that keeps
    # appearing to work while not protecting anything is worse than one that
    # refuses, because nothing surfaces the downgrade.

    It 'throws rather than storing when the backend is unavailable' {
        $script:StubAvailable = $false
        { Set-StoredSecret -Ref (NewRef) -Value 'x' -Backend 'stub' } | Should -Throw '*not available*'
    }

    It 'stores nothing at all when it refuses' {
        $r = NewRef
        $script:StubAvailable = $false
        { Set-StoredSecret -Ref $r -Value 'x' -Backend 'stub' } | Should -Throw
        $script:Vault.ContainsKey($r) | Should -BeFalse -Because 'a refused write must not leave a plaintext value behind'
    }

    It 'throws rather than returning null when the backend is unavailable' {
        # Returning null here would read as "not configured" and send the
        # operator to re-enter a credential that is already stored correctly.
        $r = NewRef
        Set-StoredSecret -Ref $r -Value 'x' -Backend 'stub'
        $script:StubAvailable = $false
        { Get-StoredSecret -Ref $r -Backend 'stub' } | Should -Throw '*not available*'
    }

    It 'throws on an unknown backend name rather than picking a default' {
        { Set-StoredSecret -Ref (NewRef) -Value 'x' -Backend 'no-such-backend' } | Should -Throw '*Unknown secret backend*'
    }

    It 'names the registered backends when one is not found' {
        { Get-SecretBackend -Name 'nope' } | Should -Throw '*dpapi*'
    }
}

Describe 'a stored secret that cannot be decrypted' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'throws instead of reporting "not configured"' {
        # A DPAPI blob written by another user or on another machine. The
        # distinction matters: one means "set it", the other means "you set it
        # somewhere else".
        $r = NewRef
        $script:Vault[$r] = '<<CORRUPT>>'
        { Get-StoredSecret -Ref $r -Backend 'stub' } | Should -Throw '*could not be decrypted*'
    }

    It 'reports not-configured from Test-StoredSecret rather than throwing' {
        # UI asking "is this set up?" must not crash on a broken blob.
        $r = NewRef
        $script:Vault[$r] = '<<CORRUPT>>'
        { Test-StoredSecret -Ref $r -Backend 'stub' } | Should -Not -Throw
        Test-StoredSecret -Ref $r -Backend 'stub' | Should -BeFalse
    }
}

Describe 'Remove-StoredSecret' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'deletes the secret' {
        $r = NewRef
        Set-StoredSecret -Ref $r -Value 'x' -Backend 'stub'
        Remove-StoredSecret -Ref $r -Backend 'stub'
        Get-StoredSecret -Ref $r -Backend 'stub' | Should -BeNullOrEmpty
    }

    It 'is idempotent on a ref that was never stored' {
        # Deleting a provider config twice must not error.
        { Remove-StoredSecret -Ref (NewRef) -Backend 'stub' } | Should -Not -Throw
    }

    It 'leaves other secrets alone' {
        $a = NewRef; $b = NewRef
        Set-StoredSecret -Ref $a -Value 'token-a' -Backend 'stub'
        Set-StoredSecret -Ref $b -Value 'token-b' -Backend 'stub'
        Remove-StoredSecret -Ref $a -Backend 'stub'
        Get-StoredSecret -Ref $b -Backend 'stub' | Should -Be 'token-b'
    }
}

Describe 'Test-StoredSecret' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'is true when a secret is stored' {
        $r = NewRef
        Set-StoredSecret -Ref $r -Value 'x' -Backend 'stub'
        Test-StoredSecret -Ref $r -Backend 'stub' | Should -BeTrue
    }

    It 'is false when nothing is stored' {
        Test-StoredSecret -Ref (NewRef) -Backend 'stub' | Should -BeFalse
    }

    It 'is false rather than throwing on a malformed ref' {
        Test-StoredSecret -Ref 'garbage' -Backend 'stub' | Should -BeFalse
    }
}

Describe 'the DPAPI backend' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'is registered by default' {
        Get-SecretBackendNames | Should -Contain 'dpapi'
    }

    It 'reports itself unavailable on non-Windows rather than throwing' {
        # This suite runs on Linux in CI. The check must answer, not explode.
        { Test-SecretBackendAvailable -Name 'dpapi' } | Should -Not -Throw
        if ($IsWindows) {
            Test-SecretBackendAvailable -Name 'dpapi' | Should -BeTrue
        } else {
            Test-SecretBackendAvailable -Name 'dpapi' | Should -BeFalse
        }
    }

    It 'explains why it is unavailable, so hosted mode is not a mystery' {
        (Get-SecretBackend -Name 'dpapi').Description | Should -Match 'Windows'
    }

    It 'refuses to store off Windows instead of writing plaintext to the registry' -Skip:($IsWindows) {
        { Set-StoredSecret -Ref (NewRef) -Value 'x' -Backend 'dpapi' } | Should -Throw '*not available*'
    }
}

Describe 'Resolve-ProviderCredential' {
    BeforeEach { $script:Vault = @{}; $script:StubAvailable = $true }


    It 'reports not-configured for a null config without throwing' {
        $r = Resolve-ProviderCredential -ProviderConfig $null -Backend 'stub'
        $r.IsConfigured | Should -BeFalse
        $r.Reason | Should -Match 'No DNS provider is configured'
    }

    It 'treats manual as configured, because publishing by hand is a real choice' {
        $r = Resolve-ProviderCredential -ProviderConfig ([PSCustomObject]@{ provider = 'manual' }) -Backend 'stub'
        $r.IsConfigured | Should -BeTrue
        $r.Arguments.Count | Should -Be 0
    }

    It 'reports not-configured when no credential has been saved yet' {
        $cfg = [PSCustomObject]@{ provider = 'cloudflare'; credential_ref = ''; config_json = '{"zoneId":"z1"}' }
        $r = Resolve-ProviderCredential -ProviderConfig $cfg -Backend 'stub'
        $r.IsConfigured | Should -BeFalse
        $r.Reason | Should -Match 'No credential has been saved'
    }

    It 'refuses a malformed credential_ref rather than passing it to the backend' {
        $cfg = [PSCustomObject]@{ provider = 'cloudflare'; credential_ref = '../../etc/passwd'; config_json = '{"zoneId":"z1"}' }
        $r = Resolve-ProviderCredential -ProviderConfig $cfg -Backend 'stub'
        $r.IsConfigured | Should -BeFalse
        $r.Reason | Should -Match 'malformed'
    }

    It 'builds Cloudflare arguments from the stored secret and coordinates' {
        $ref = NewRef
        Set-StoredSecret -Ref $ref -Value 'cf-token' -Backend 'stub'
        $cfg = [PSCustomObject]@{ provider = 'cloudflare'; credential_ref = $ref; config_json = '{"zoneId":"zone-123"}' }
        $r = Resolve-ProviderCredential -ProviderConfig $cfg -Backend 'stub'
        $r.IsConfigured | Should -BeTrue
        $r.Arguments['ApiToken'] | Should -Be 'cf-token'
        $r.Arguments['ZoneId']   | Should -Be 'zone-123'
    }

    It 'builds Azure DNS arguments from the stored secret and coordinates' {
        $ref = NewRef 'azuredns'
        Set-StoredSecret -Ref $ref -Value 'az-token' -Backend 'stub'
        $cfg = [PSCustomObject]@{
            provider = 'azuredns'; credential_ref = $ref
            config_json = '{"subscriptionId":"sub-1","resourceGroup":"rg-1","zoneName":"example.com"}'
        }
        $r = Resolve-ProviderCredential -ProviderConfig $cfg -Backend 'stub'
        $r.IsConfigured | Should -BeTrue
        $r.Arguments['AccessToken']    | Should -Be 'az-token'
        $r.Arguments['SubscriptionId'] | Should -Be 'sub-1'
        $r.Arguments['ResourceGroup']  | Should -Be 'rg-1'
        $r.Arguments['ZoneName']       | Should -Be 'example.com'
    }

    It 'names the missing coordinate instead of failing at the API' -ForEach @(
        @{ Provider = 'cloudflare'; Json = '{}'; Expect = 'zoneId' }
        @{ Provider = 'azuredns';   Json = '{"subscriptionId":"s"}'; Expect = 'resourceGroup' }
    ) {
        $ref = NewRef
        Set-StoredSecret -Ref $ref -Value 'tok' -Backend 'stub'
        $cfg = [PSCustomObject]@{ provider = $Provider; credential_ref = $ref; config_json = $Json }
        $r = Resolve-ProviderCredential -ProviderConfig $cfg -Backend 'stub'
        $r.IsConfigured | Should -BeFalse
        $r.Reason | Should -Match $Expect
    }

    It 'reports unparseable coordinates rather than throwing' {
        $ref = NewRef
        Set-StoredSecret -Ref $ref -Value 'tok' -Backend 'stub'
        $cfg = [PSCustomObject]@{ provider = 'cloudflare'; credential_ref = $ref; config_json = '{not json' }
        $r = Resolve-ProviderCredential -ProviderConfig $cfg -Backend 'stub'
        $r.IsConfigured | Should -BeFalse
        $r.Reason | Should -Match 'could not be parsed'
    }

    It 'surfaces a backend failure as a reason instead of throwing' {
        $ref = NewRef
        Set-StoredSecret -Ref $ref -Value 'tok' -Backend 'stub'
        $script:StubAvailable = $false
        $cfg = [PSCustomObject]@{ provider = 'cloudflare'; credential_ref = $ref; config_json = '{"zoneId":"z"}' }
        $r = Resolve-ProviderCredential -ProviderConfig $cfg -Backend 'stub'
        $r.IsConfigured | Should -BeFalse
        $r.Reason | Should -Match 'not available'
    }

    It 'refuses a provider it has no mapping for' {
        $ref = NewRef
        Set-StoredSecret -Ref $ref -Value 'tok' -Backend 'stub'
        $cfg = [PSCustomObject]@{ provider = 'route53'; credential_ref = $ref; config_json = '{}' }
        $r = Resolve-ProviderCredential -ProviderConfig $cfg -Backend 'stub'
        $r.IsConfigured | Should -BeFalse
        $r.Reason | Should -Match 'No credential mapping'
    }
}

