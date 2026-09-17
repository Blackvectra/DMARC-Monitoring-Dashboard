<#
.SYNOPSIS
    Pluggable secret storage. Holds the DNS provider tokens that turn a
    planned DNS change into an applied one.

.DESCRIPTION
    The database never holds a secret. It holds a credential_ref, which is an
    opaque pointer, and the secret itself lives in a backend chosen per tenant.
    A database file that leaks must not hand over write access to a client's
    DNS zone.

    Self-hosted uses DPAPI, which encrypts to the operator's Windows profile on
    one machine and therefore cannot work server-side: a hosted deployment has
    no operator profile to encrypt to. Hosted mode needs envelope encryption
    via a KMS, which is a different backend behind this same interface rather
    than a different codebase. tenants.secret_backend already names which.

    THE RULE THAT MATTERS: when a backend is unavailable, every operation in
    here fails loudly. Nothing falls back to plaintext, and nothing returns a
    value it could not decrypt. A silent downgrade to plaintext is how
    credential stores leak, and it would be invisible precisely because the
    tool would appear to keep working.
#>

Set-StrictMode -Version Latest

#region Backend registry
# Backends register themselves rather than being hard-coded, so hosted mode
# adds a KMS backend without touching any caller, and tests substitute an
# in-memory backend without touching the registry or needing Windows.
$script:SecretBackends = @{}

function Register-SecretBackend {
    <#
    .SYNOPSIS
        Registers a named secret backend.

    .PARAMETER Test
        Returns $true when this backend can actually be used here. DPAPI
        returns $false off Windows. Callers use this to fail early with a
        useful message instead of at the first write.
    #>
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [scriptblock]$SetSecret,
        [Parameter(Mandatory)] [scriptblock]$GetSecret,
        [Parameter(Mandatory)] [scriptblock]$RemoveSecret,
        [Parameter(Mandatory)] [scriptblock]$Test,
        [string]$Description = ''
    )
    $script:SecretBackends[$Name] = [PSCustomObject]@{
        Name         = $Name
        SetSecret    = $SetSecret
        GetSecret    = $GetSecret
        RemoveSecret = $RemoveSecret
        Test         = $Test
        Description  = $Description
    }
}

function Get-SecretBackend {
    param([Parameter(Mandatory)] [string]$Name)
    if (-not $script:SecretBackends.ContainsKey($Name)) {
        throw "Unknown secret backend '$Name'. Registered: $(($script:SecretBackends.Keys | Sort-Object) -join ', ')"
    }
    return $script:SecretBackends[$Name]
}

function Get-SecretBackendNames {
    return @($script:SecretBackends.Keys | Sort-Object)
}

function Test-SecretBackendAvailable {
    <#
    .SYNOPSIS
        Whether a backend can be used on this machine, without throwing.
    #>
    param([Parameter(Mandatory)] [string]$Name)
    if (-not $script:SecretBackends.ContainsKey($Name)) { return $false }
    try { return [bool](& $script:SecretBackends[$Name].Test) } catch { return $false }
}

function Unregister-SecretBackend {
    # Exists for tests and for a hosted process that must not keep a
    # local-disk backend reachable after startup.
    param([Parameter(Mandatory)] [string]$Name)
    $script:SecretBackends.Remove($Name) | Out-Null
}
#endregion

#region Credential references
function New-CredentialRef {
    <#
    .SYNOPSIS
        Mints an opaque pointer to a secret.

    .DESCRIPTION
        The ref is stored in the database and appears in logs, plans and audit
        rows. It therefore must not be, contain, or be reversible to the
        secret. It is namespaced by tenant so that two tenants cannot collide,
        and carries a random component so rotating to a fresh ref is always
        possible without a name clash.

        Purpose is a human-readable hint for the operator reading an audit
        trail ("cloudflare", "azuredns"), never anything sensitive.
    #>
    param(
        [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')] [string]$TenantId,
        [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9_.-]{1,32}$')] [string]$Purpose
    )
    $rand = [guid]::NewGuid().ToString('N').Substring(0, 16)
    return "dmarc.$TenantId.$Purpose.$rand"
}

function Test-CredentialRefShape {
    <#
    .SYNOPSIS
        Rejects a ref that does not look like one we minted.

    .DESCRIPTION
        A ref becomes a registry value name and is interpolated into backend
        paths, so it must never carry a path separator, a wildcard or
        whitespace. This is the check that stops a crafted config row from
        reaching outside its own storage namespace.
    #>
    param([AllowNull()] [AllowEmptyString()] [string]$Ref)
    if ([string]::IsNullOrWhiteSpace($Ref)) { return $false }
    return [bool]($Ref -match '^dmarc\.[A-Za-z0-9_.-]{1,64}\.[A-Za-z0-9_.-]{1,32}\.[a-f0-9]{16}$')
}

function Assert-CredentialRef {
    param([AllowNull()] [AllowEmptyString()] [string]$Ref)
    if (-not (Test-CredentialRefShape -Ref $Ref)) {
        throw "Malformed credential reference. Refs are minted by New-CredentialRef and must not be hand-written."
    }
}
#endregion

#region Public API
function Set-StoredSecret {
    <#
    .SYNOPSIS
        Stores or replaces the secret behind a ref.

    .DESCRIPTION
        Writing to an existing ref is rotation and is intentionally allowed:
        an operator replacing a revoked API token keeps the same config row.
    #>
    param(
        [Parameter(Mandatory)] [string]$Ref,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$Value,
        [Parameter(Mandatory)] [string]$Backend
    )
    Assert-CredentialRef -Ref $Ref
    if ([string]::IsNullOrEmpty($Value)) {
        # An empty secret stored successfully is worse than a refusal: the
        # config looks configured and every apply fails at the provider.
        throw "Refusing to store an empty secret for $Ref."
    }
    $b = Get-SecretBackend -Name $Backend
    if (-not (Test-SecretBackendAvailable -Name $Backend)) {
        throw "Secret backend '$Backend' is not available here, so the secret was NOT stored. $($b.Description)"
    }
    & $b.SetSecret $Ref $Value
}

function Get-StoredSecret {
    <#
    .SYNOPSIS
        Returns the secret behind a ref, or $null if there is none.

    .DESCRIPTION
        Returns $null for a ref that was never stored, which is an ordinary
        "not configured yet" state. It THROWS when the backend exists but
        cannot decrypt, because that is not the same thing: a DPAPI blob
        written by another user or on another machine is a real failure, and
        treating it as "not configured" would send an operator hunting for a
        setting they already set.
    #>
    param(
        [Parameter(Mandatory)] [string]$Ref,
        [Parameter(Mandatory)] [string]$Backend
    )
    Assert-CredentialRef -Ref $Ref
    $b = Get-SecretBackend -Name $Backend
    if (-not (Test-SecretBackendAvailable -Name $Backend)) {
        throw "Secret backend '$Backend' is not available here, so the secret could not be read. $($b.Description)"
    }
    return (& $b.GetSecret $Ref)
}

function Remove-StoredSecret {
    <#
    .SYNOPSIS
        Deletes the secret behind a ref. Idempotent.

    .DESCRIPTION
        Deleting a provider config must delete its secret too. An orphaned
        credential outliving the config row that explained what it was for is
        a credential nobody will ever rotate.
    #>
    param(
        [Parameter(Mandatory)] [string]$Ref,
        [Parameter(Mandatory)] [string]$Backend
    )
    Assert-CredentialRef -Ref $Ref
    $b = Get-SecretBackend -Name $Backend
    if (-not (Test-SecretBackendAvailable -Name $Backend)) {
        throw "Secret backend '$Backend' is not available here, so the secret could not be removed. $($b.Description)"
    }
    & $b.RemoveSecret $Ref
}

function Test-StoredSecret {
    <#
    .SYNOPSIS
        Whether a usable secret exists behind a ref, without returning it.

    .DESCRIPTION
        For UI that needs to show "configured" without pulling the token into
        a variable it might later log.
    #>
    param(
        [Parameter(Mandatory)] [string]$Ref,
        [Parameter(Mandatory)] [string]$Backend
    )
    try {
        $v = Get-StoredSecret -Ref $Ref -Backend $Backend
        return (-not [string]::IsNullOrEmpty($v))
    } catch { return $false }
}
#endregion

#region DPAPI backend (self-hosted)
# ConvertFrom-SecureString with no key uses DPAPI, scoped to the current user
# on the current machine. That scoping is the security property for a
# self-hosted install and the reason it cannot serve hosted mode: there is no
# operator profile on a shared server to encrypt to, and a service account
# holding every tenant's DNS credentials is exactly the blast radius the
# hosted design has to avoid.
$script:DpapiRegRoot = 'HKCU:\Software\DMARCMonitor\Secrets'

function Get-DpapiRegRoot { return $script:DpapiRegRoot }
function Set-DpapiRegRoot {
    # Lets an installer place secrets under a service account's own hive.
    param([Parameter(Mandatory)] [string]$Path)
    $script:DpapiRegRoot = $Path
}

Register-SecretBackend -Name 'dpapi' `
    -Description 'DPAPI is Windows-only and encrypts to the current user on this machine.' `
    -Test {
        if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') { return $false }
        return [bool](Get-Command ConvertFrom-SecureString -ErrorAction SilentlyContinue)
    } `
    -SetSecret {
        param($Ref, $Value)
        $root = Get-DpapiRegRoot
        if (-not (Test-Path $root)) { New-Item -Path $root -Force | Out-Null }
        $enc = (ConvertTo-SecureString -String $Value -AsPlainText -Force) | ConvertFrom-SecureString
        Set-ItemProperty -Path $root -Name $Ref -Value $enc -Force
    } `
    -GetSecret {
        param($Ref)
        $root = Get-DpapiRegRoot
        $enc = $null
        try { $enc = (Get-ItemProperty -Path $root -Name $Ref -ErrorAction Stop).$Ref }
        catch { return $null }   # never stored: ordinary "not configured"
        if ([string]::IsNullOrWhiteSpace($enc)) { return $null }
        # Past this point the value EXISTS. A decrypt failure is a real error
        # and must not be flattened into "not configured".
        try {
            $ss  = $enc | ConvertTo-SecureString -ErrorAction Stop
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
            try { return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr) }
            finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        } catch {
            throw "A secret is stored for $Ref but could not be decrypted. DPAPI blobs are bound to the user and machine that wrote them, so this usually means the secret was saved by a different account or on a different computer. Re-enter it as the account that runs the tool."
        }
    } `
    -RemoveSecret {
        param($Ref)
        $root = Get-DpapiRegRoot
        if (-not (Test-Path $root)) { return }
        Remove-ItemProperty -Path $root -Name $Ref -ErrorAction SilentlyContinue
    }
#endregion

#region Provider credential resolution
function Resolve-ProviderCredential {
    <#
    .SYNOPSIS
        Turns a stored provider config into the arguments its API call needs.

    .DESCRIPTION
        The one place a secret is pulled into memory. Callers get a hashtable
        to splat and should not hold onto it: everything else in the
        remediation path works from the config row and the plan, neither of
        which contains a credential.

        Returns a result object rather than throwing on "not configured",
        because an unconfigured provider is the normal state for a client the
        operator has not onboarded yet, and the UI needs to say so calmly.
    #>
    param(
        # AllowNull because "this domain has no provider row" is an ordinary
        # state, and Mandatory alone would throw before the guard below can
        # turn it into a readable reason.
        [Parameter(Mandatory)] [AllowNull()] $ProviderConfig,
        [string]$Backend = 'dpapi'
    )

    $result = [PSCustomObject]@{
        Provider     = $null
        IsConfigured = $false
        Reason       = ''
        Arguments    = @{}
    }

    if ($null -eq $ProviderConfig) { $result.Reason = 'No DNS provider is configured for this domain.'; return $result }

    $provider = $null
    if ($ProviderConfig.PSObject.Properties['provider']) { $provider = $ProviderConfig.provider }
    $result.Provider = $provider
    if ([string]::IsNullOrWhiteSpace($provider)) { $result.Reason = 'The provider row has no provider type.'; return $result }

    # Manual is a real choice, not a missing one: the operator applies the
    # change by hand and the tool verifies it afterwards.
    if ($provider -eq 'manual') { $result.IsConfigured = $true; $result.Reason = 'Manual provider: changes are published by hand.'; return $result }

    $ref = $null
    if ($ProviderConfig.PSObject.Properties['credential_ref']) { $ref = $ProviderConfig.credential_ref }
    if ([string]::IsNullOrWhiteSpace($ref)) { $result.Reason = "No credential has been saved for the $provider provider yet."; return $result }
    if (-not (Test-CredentialRefShape -Ref $ref)) { $result.Reason = 'The stored credential reference is malformed and was not used.'; return $result }

    $secret = $null
    try { $secret = Get-StoredSecret -Ref $ref -Backend $Backend }
    catch { $result.Reason = $_.Exception.Message; return $result }
    if ([string]::IsNullOrEmpty($secret)) { $result.Reason = "No credential has been saved for the $provider provider yet."; return $result }

    $cfg = @{}
    if ($ProviderConfig.PSObject.Properties['config_json'] -and $ProviderConfig.config_json) {
        try { (ConvertFrom-Json $ProviderConfig.config_json).PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value } }
        catch { $result.Reason = 'The provider coordinates (config_json) could not be parsed.'; return $result }
    }

    switch ($provider) {
        'cloudflare' {
            if (-not $cfg.ContainsKey('zoneId')) { $result.Reason = 'Cloudflare needs a zoneId in its coordinates.'; return $result }
            $result.Arguments = @{ ApiToken = $secret; ZoneId = $cfg['zoneId'] }
        }
        'azuredns' {
            foreach ($k in @('subscriptionId','resourceGroup','zoneName')) {
                if (-not $cfg.ContainsKey($k)) { $result.Reason = "Azure DNS needs $k in its coordinates."; return $result }
            }
            $result.Arguments = @{
                AccessToken    = $secret
                SubscriptionId = $cfg['subscriptionId']
                ResourceGroup  = $cfg['resourceGroup']
                ZoneName       = $cfg['zoneName']
            }
        }
        default { $result.Reason = "No credential mapping is implemented for provider '$provider'."; return $result }
    }

    $result.IsConfigured = $true
    return $result
}
#endregion
