#Requires -Version 5.1
<#
.SYNOPSIS
    DMARC Monitor — automated installer

.DESCRIPTION
    End-to-end setup. Run this once and it does everything:
        1. Installs required PowerShell modules
        2. Generates the certificate (SHA-512, RSA-2048, NonExportable, 2-year)
        3. Connects to Microsoft Graph interactively
        4. Creates the Entra app registration (or reuses existing)
        5. Uploads the certificate as app credential
        6. Adds Mail.ReadWrite + Mail.Send application permissions
        7. Grants admin consent
        8. Connects to Exchange Online
        9. Applies New-ApplicationAccessPolicy to restrict mailbox scope
       10. Writes all settings to the registry (DPAPI-encrypted where appropriate)
       11. Tests certificate authentication end-to-end
       12. Launches the dashboard

    Idempotent. Re-running detects existing app + cert + policy and updates rather than duplicating.

.PARAMETER MailboxAddress
    The shared mailbox that receives DMARC reports (e.g. dmarc@yourdomain.com).
    Prompted if not provided.

.PARAMETER WorkingDir
    Local directory for logs, CSVs, state files. Created if it doesn't exist.
    Prompted if not provided.

.PARAMETER CertStore
    LocalMachine (requires admin, survives logout — recommended) or CurrentUser.
    Default: LocalMachine

.PARAMETER AppDisplayName
    Entra app registration display name. Default: DMARCMonitor

.PARAMETER SkipLaunch
    Don't launch the dashboard after install completes.

.EXAMPLE
    .\Install-DMARCMonitor.ps1
    Fully interactive — prompts for everything.

.EXAMPLE
    .\Install-DMARCMonitor.ps1 -MailboxAddress "dmarc@yourdomain.com" -WorkingDir "D:\DMARC"
    Skip the first two prompts.

.NOTES
    Engineer: DMARC Monitoring Dashboard
    Requires Application Administrator or Global Admin role in Entra to grant consent.
    Requires Exchange Administrator role to apply the access policy.
#>

[CmdletBinding()]
Param(
    [string]$MailboxAddress,
    [string]$WorkingDir,
    [ValidateSet("LocalMachine","CurrentUser")] [string]$CertStore = "LocalMachine",
    [string]$AppDisplayName = "DMARCMonitor",
    [int]$RetentionDays = 7,
    [string]$SourceFolder = "Inbox",
    [switch]$SkipLaunch
)

$ErrorActionPreference = "Stop"
$script:RegPath = "HKCU:\Software\DMARCMonitor"

# Microsoft Graph permission GUIDs (well-known, stable)
$script:GraphAppId             = "00000003-0000-0000-c000-000000000000"
$script:Perm_MailReadWrite_App = "e2a3a72e-5f79-4c64-b1b1-878b674786c9"
$script:Perm_MailSend_App      = "b633e1c5-b582-4048-a93e-9f11b44c7e96"

#region Output helpers
function Write-Step  { param([string]$Msg) Write-Host ""; Write-Host "==> $Msg" -ForegroundColor Cyan }
function Write-Info  { param([string]$Msg) Write-Host "    $Msg" -ForegroundColor Gray }
function Write-OK    { param([string]$Msg) Write-Host "    [OK] $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "    [!!] $Msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$Msg) Write-Host "    [XX] $Msg" -ForegroundColor Red }
#endregion

#region Banner
Clear-Host
Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "  DMARC Monitor — Automated Installer"                             -ForegroundColor Cyan
Write-Host "  Sets up Entra app, certificate, mailbox policy, and registry."        -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""
#endregion

#region Pre-flight
Write-Step "Pre-flight checks"

# PS7 check
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $pwsh7 = Get-Command pwsh -EA SilentlyContinue
    if ($pwsh7) {
        Write-Warn "Currently running PowerShell $($PSVersionTable.PSVersion). Relaunching in PS7..."
        $argList = @("-ExecutionPolicy","Bypass","-File",("`"$($MyInvocation.MyCommand.Path)`""))
        foreach ($k in $PSBoundParameters.Keys) {
            $v = $PSBoundParameters[$k]
            if ($v -is [switch]) { if ($v) { $argList += "-$k" } }
            else { $argList += "-$k"; $argList += "`"$v`"" }
        }
        & pwsh @argList
        exit $LASTEXITCODE
    } else {
        Write-Warn "PowerShell 7 not installed. The dashboard requires PS7 for best results."
        Write-Warn "Install via: winget install Microsoft.PowerShell"
        Write-Warn "Continuing on PS 5.1 — engine + auth will work but launch dashboard manually after."
    }
}
Write-OK "PowerShell version: $($PSVersionTable.PSVersion)"

# Admin check (for LocalMachine cert store)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($CertStore -eq "LocalMachine" -and -not $isAdmin) {
    Write-Fail "LocalMachine cert store requires admin. Re-run as administrator or pass -CertStore CurrentUser."
    exit 1
}
Write-OK ("Admin: $isAdmin | Cert store: $CertStore")
#endregion

#region User input
Write-Step "Configuration"

if (-not $MailboxAddress) {
    $MailboxAddress = Read-Host "Mailbox address for DMARC reports (e.g. dmarc@yourdomain.com)"
}
if ([string]::IsNullOrWhiteSpace($MailboxAddress) -or $MailboxAddress -notmatch '@') {
    Write-Fail "Invalid mailbox address"; exit 1
}

if (-not $WorkingDir) {
    $defaultDir = "C:\ProgramData\DMARCMonitor\DMARC"
    $WorkingDir = Read-Host "Working directory (logs, CSVs, state) [$defaultDir]"
    if ([string]::IsNullOrWhiteSpace($WorkingDir)) { $WorkingDir = $defaultDir }
}

if (-not (Test-Path $WorkingDir)) {
    try { New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null; Write-OK "Created $WorkingDir" }
    catch { Write-Fail "Cannot create $WorkingDir`: $_"; exit 1 }
}

Write-Info "Mailbox      : $MailboxAddress"
Write-Info "Working dir  : $WorkingDir"
Write-Info "Cert store   : $CertStore"
Write-Info "App name     : $AppDisplayName"
Write-Info "Retention    : $RetentionDays days"
Write-Info "Source folder: $SourceFolder"
Write-Host ""
$confirm = Read-Host "Proceed? (Y/n)"
if ($confirm -and $confirm -notmatch '^[Yy]') { Write-Warn "Aborted by user."; exit 0 }
#endregion

#region Module install
Write-Step "Installing required PowerShell modules"

$modules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Identity.SignIns",
    "ExchangeOnlineManagement"
)

foreach ($mod in $modules) {
    if (Get-Module -ListAvailable -Name $mod) {
        Write-OK "$mod already installed"
    } else {
        Write-Info "Installing $mod..."
        try {
            Install-Module $mod -Scope CurrentUser -Force -AllowClobber -EA Stop
            Write-OK "$mod installed"
        } catch {
            Write-Fail "$mod install failed: $_"
            exit 1
        }
    }
}
Import-Module Microsoft.Graph.Authentication -EA Stop
Import-Module Microsoft.Graph.Applications -EA Stop
Import-Module Microsoft.Graph.Identity.SignIns -EA Stop
Import-Module ExchangeOnlineManagement -EA Stop
#endregion

#region Certificate generation
Write-Step "Generating certificate"

$certSubject = "CN=DMARCMonitor-$($env:COMPUTERNAME)"
$existingCerts = Get-ChildItem "Cert:\$CertStore\My" -EA SilentlyContinue | Where-Object { $_.Subject -eq $certSubject }

if ($existingCerts -and $existingCerts.Count -gt 0) {
    $newest = $existingCerts | Sort-Object NotAfter -Descending | Select-Object -First 1
    $daysLeft = ($newest.NotAfter - (Get-Date)).Days
    if ($daysLeft -gt 60) {
        Write-Warn "Existing cert found (thumb: $($newest.Thumbprint.Substring(0,8))..., expires in $daysLeft days)"
        $reuse = Read-Host "Reuse this cert? (Y/n)"
        if (-not $reuse -or $reuse -match '^[Yy]') {
            $cert = $newest
            Write-OK "Reusing existing certificate"
        }
    }
}

if (-not $cert) {
    try {
        $cert = New-SelfSignedCertificate `
            -Subject $certSubject `
            -CertStoreLocation "Cert:\$CertStore\My" `
            -KeyExportPolicy "NonExportable" `
            -KeySpec "Signature" `
            -KeyLength 2048 `
            -HashAlgorithm "SHA512" `
            -NotAfter (Get-Date).AddYears(2) `
            -KeyUsage "DigitalSignature" `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
            -EA Stop
        Write-OK ("Certificate created: $($cert.Thumbprint)")
        Write-Info ("Subject     : $($cert.Subject)")
        Write-Info ("Algorithm   : SHA-512 / RSA-2048")
        Write-Info ("Not after   : $($cert.NotAfter.ToString('yyyy-MM-dd'))")
        Write-Info "Private key : NonExportable (stays on this machine)"
    } catch {
        Write-Fail "Cert creation failed: $_"
        exit 1
    }
}

# Export .cer (public key) to temp location for Graph upload
$cerPath = Join-Path $env:TEMP "DMARCMonitor-$($env:COMPUTERNAME).cer"
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT -Force | Out-Null
Write-OK ".cer exported to $cerPath"
#endregion

#region Graph connect
Write-Step "Connecting to Microsoft Graph (interactive)"
Write-Info "You'll be prompted to sign in. Use an Application Administrator or Global Admin account."
Write-Host ""

try {
    $requiredScopes = @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "Directory.ReadWrite.All"
    )
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome -EA Stop
    $ctx = Get-MgContext
    Write-OK "Connected to tenant $($ctx.TenantId)"
    Write-Info "Account: $($ctx.Account)"
    $tenantId = $ctx.TenantId
} catch {
    Write-Fail "Graph connection failed: $_"
    exit 1
}
#endregion

#region App registration
Write-Step "Entra app registration"

# Check for existing app
$existingApp = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" -EA SilentlyContinue
if ($existingApp) {
    Write-Warn "Existing app found: $($existingApp.DisplayName) (AppId: $($existingApp.AppId))"
    $reuseApp = Read-Host "Reuse this app registration? (Y/n)"
    if ($reuseApp -and $reuseApp -notmatch '^[Yy]') {
        Write-Fail "Aborted to avoid duplicate app."
        exit 1
    }
    $app = $existingApp
    Write-OK "Reusing app: $($app.AppId)"
} else {
    # Build the requiredResourceAccess for Microsoft Graph
    $requiredResourceAccess = @(
        @{
            resourceAppId = $script:GraphAppId
            resourceAccess = @(
                @{ id = $script:Perm_MailReadWrite_App; type = "Role" },
                @{ id = $script:Perm_MailSend_App;      type = "Role" }
            )
        }
    )
    try {
        $app = New-MgApplication -DisplayName $AppDisplayName `
            -SignInAudience "AzureADMyOrg" `
            -RequiredResourceAccess $requiredResourceAccess `
            -EA Stop
        Write-OK "App registration created: $($app.AppId)"
        # Apps need a moment to be queryable
        Start-Sleep -Seconds 3
    } catch {
        Write-Fail "App creation failed: $_"
        exit 1
    }
}

$clientId = $app.AppId

# Update app with required permissions if it's the existing app (might be incomplete)
$needsPermUpdate = $true
if ($app.RequiredResourceAccess) {
    $graphRes = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $script:GraphAppId }
    if ($graphRes -and $graphRes.ResourceAccess) {
        $hasReadWrite = $graphRes.ResourceAccess | Where-Object { $_.Id -eq $script:Perm_MailReadWrite_App }
        $hasSend      = $graphRes.ResourceAccess | Where-Object { $_.Id -eq $script:Perm_MailSend_App }
        if ($hasReadWrite -and $hasSend) { $needsPermUpdate = $false }
    }
}

if ($needsPermUpdate) {
    Write-Info "Updating app with required Graph permissions..."
    $requiredResourceAccess = @(
        @{
            resourceAppId = $script:GraphAppId
            resourceAccess = @(
                @{ id = $script:Perm_MailReadWrite_App; type = "Role" },
                @{ id = $script:Perm_MailSend_App;      type = "Role" }
            )
        }
    )
    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredResourceAccess
    Write-OK "Permissions added: Mail.ReadWrite + Mail.Send (Application)"
}
#endregion

#region Cert upload to app
Write-Step "Uploading certificate to app registration"

$cerBytes = [System.IO.File]::ReadAllBytes($cerPath)

# Check existing key credentials, dedupe by thumbprint
$existingKeys = $app.KeyCredentials
$thumbBytes = $cert.GetCertHash()
$alreadyUploaded = $false
if ($existingKeys) {
    foreach ($k in $existingKeys) {
        if ($k.CustomKeyIdentifier -and ([Convert]::ToBase64String($k.CustomKeyIdentifier) -eq [Convert]::ToBase64String($thumbBytes))) {
            $alreadyUploaded = $true; break
        }
    }
}

if ($alreadyUploaded) {
    Write-OK "Certificate already attached to app"
} else {
    $newKeyCred = @{
        Type        = "AsymmetricX509Cert"
        Usage       = "Verify"
        Key         = $cerBytes
        DisplayName = "DMARCMonitor-$($env:COMPUTERNAME) ($(Get-Date -Format 'yyyy-MM-dd'))"
    }
    # Append to existing
    $allKeys = @()
    if ($existingKeys) {
        foreach ($k in $existingKeys) {
            $allKeys += @{
                Type        = $k.Type
                Usage       = $k.Usage
                Key         = $k.Key
                DisplayName = $k.DisplayName
                StartDateTime = $k.StartDateTime
                EndDateTime   = $k.EndDateTime
                CustomKeyIdentifier = $k.CustomKeyIdentifier
                KeyId = $k.KeyId
            }
        }
    }
    $allKeys += $newKeyCred
    try {
        Update-MgApplication -ApplicationId $app.Id -KeyCredentials $allKeys -EA Stop
        Write-OK "Certificate uploaded to app"
    } catch {
        Write-Fail "Cert upload failed: $_"
        exit 1
    }
}

# Remove the temp .cer
Remove-Item $cerPath -Force -EA SilentlyContinue
#endregion

#region Service principal + admin consent
Write-Step "Granting admin consent"

# Ensure the app has a service principal in this tenant
$sp = Get-MgServicePrincipal -Filter "appId eq '$clientId'" -EA SilentlyContinue
if (-not $sp) {
    Write-Info "Creating service principal for app..."
    $sp = New-MgServicePrincipal -AppId $clientId
    Start-Sleep -Seconds 3
    Write-OK "Service principal created: $($sp.Id)"
} else {
    Write-OK "Service principal exists: $($sp.Id)"
}

# Get Microsoft Graph service principal (needed to grant consent against)
$graphSP = Get-MgServicePrincipal -Filter "appId eq '$script:GraphAppId'"
if (-not $graphSP) { Write-Fail "Microsoft Graph service principal not found in tenant — unusual."; exit 1 }

# Grant each permission via AppRoleAssignment
function Grant-AppRole {
    param([string]$PermissionId, [string]$PermissionName)
    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -EA SilentlyContinue |
        Where-Object { $_.AppRoleId -eq $PermissionId -and $_.ResourceId -eq $graphSP.Id }
    if ($existing) {
        Write-OK "$PermissionName already granted"
    } else {
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $sp.Id `
                -PrincipalId $sp.Id `
                -ResourceId $graphSP.Id `
                -AppRoleId $PermissionId | Out-Null
            Write-OK "$PermissionName granted"
        } catch {
            Write-Fail "Failed to grant $PermissionName`: $_"
            Write-Warn "Your account may lack permissions to grant admin consent."
            Write-Warn "Workaround: open Entra portal → App registrations → $AppDisplayName → API permissions → Grant admin consent"
        }
    }
}

Grant-AppRole -PermissionId $script:Perm_MailReadWrite_App -PermissionName "Mail.ReadWrite"
Grant-AppRole -PermissionId $script:Perm_MailSend_App      -PermissionName "Mail.Send"

Disconnect-MgGraph -EA SilentlyContinue | Out-Null
#endregion

#region Exchange Online — Application Access Policy
Write-Step "Applying mailbox access policy (Exchange Online)"
Write-Info "Restricts the app to only the DMARC mailbox — without this, the app has tenant-wide Mail.ReadWrite."
Write-Info "You'll be prompted to sign in to Exchange Online. Use an Exchange Admin or Global Admin account."
Write-Host ""

try {
    Connect-ExchangeOnline -ShowBanner:$false -EA Stop
    Write-OK "Connected to Exchange Online"
} catch {
    Write-Fail "EXO connect failed: $_"
    Write-Warn "You'll need to run this manually:"
    Write-Warn "  Connect-ExchangeOnline"
    Write-Warn "  New-ApplicationAccessPolicy -AppId '$clientId' -PolicyScopeGroupId '$MailboxAddress' -AccessRight RestrictAccess -Description 'DMARC Monitor'"
    $proceed = Read-Host "Skip EXO policy and continue? (y/N)"
    if ($proceed -notmatch '^[Yy]') { exit 1 }
}

if (Get-Command New-ApplicationAccessPolicy -EA SilentlyContinue) {
    # Check for existing policy on this app
    $existingPolicies = Get-ApplicationAccessPolicy -EA SilentlyContinue | Where-Object { $_.AppId -contains $clientId }
    if ($existingPolicies) {
        Write-OK "Existing access policy found for app — leaving as-is"
        $existingPolicies | ForEach-Object { Write-Info "  Policy: $($_.Identity) → $($_.ScopeName) ($($_.AccessRight))" }
    } else {
        try {
            New-ApplicationAccessPolicy `
                -AppId $clientId `
                -PolicyScopeGroupId $MailboxAddress `
                -AccessRight RestrictAccess `
                -Description "DMARC Monitor — restrict to $MailboxAddress" -EA Stop | Out-Null
            Write-OK "Application Access Policy applied — scope: $MailboxAddress"

            # Test it
            $testResult = Test-ApplicationAccessPolicy -AppId $clientId -Identity $MailboxAddress -EA SilentlyContinue
            if ($testResult.AccessCheckResult -eq 'Granted') {
                Write-OK "Policy verified — access granted to $MailboxAddress"
            }
        } catch {
            Write-Fail "Policy creation failed: $_"
            Write-Warn "Mail.ReadWrite is currently tenant-wide for this app. Restrict manually:"
            Write-Warn "  New-ApplicationAccessPolicy -AppId '$clientId' -PolicyScopeGroupId '$MailboxAddress' -AccessRight RestrictAccess"
        }
    }

    Disconnect-ExchangeOnline -Confirm:$false -EA SilentlyContinue | Out-Null
}
#endregion

#region Write registry settings
Write-Step "Writing settings to registry (HKCU:\Software\DMARCMonitor)"

if (-not (Test-Path $script:RegPath)) { New-Item -Path $script:RegPath -Force | Out-Null }

function Set-RegEncrypted { param([string]$Name,[string]$Value)
    $enc = (ConvertTo-SecureString -String $Value -AsPlainText -Force) | ConvertFrom-SecureString
    Set-ItemProperty -Path $script:RegPath -Name $Name -Value $enc
}
function Set-RegPlain { param([string]$Name,$Value)
    Set-ItemProperty -Path $script:RegPath -Name $Name -Value $Value
}

Set-RegEncrypted "TenantId"       $tenantId
Set-RegEncrypted "ClientId"       $clientId
Set-RegEncrypted "MailboxAddress" $MailboxAddress
Set-RegPlain     "CertThumbprint" $cert.Thumbprint
Set-RegPlain     "CertStore"      $CertStore
Set-RegPlain     "WorkingDir"     $WorkingDir
Set-RegPlain     "RetentionDays"  $RetentionDays
Set-RegPlain     "SourceFolder"   $SourceFolder

# Sensible defaults for Phase 2-5 — user can toggle later in Settings
Set-RegPlain "EnableGeoLookup"             1
Set-RegPlain "EnableAlerts"                1
Set-RegPlain "AlertThresholdPct"           10
Set-RegPlain "EnableNewSenderAlerts"       1
Set-RegPlain "EnableVolumeAnomalyAlerts"   1
Set-RegPlain "VolumeMultiplier"            "3.0"
Set-RegPlain "EnableDNSHealthCheck"        1
Set-RegPlain "EnableCousinDomainDetection" 1
Set-RegPlain "EnableReportingCoverage"     1
Set-RegPlain "EnableMTASTSCheck"           1
Set-RegPlain "EnableBIMI"                  1
Set-RegPlain "EnableDKIMTracking"          1
Set-RegPlain "EnableDailyDigest"           0
Set-RegPlain "DigestHour"                  7

Write-OK "Registry settings written (sensitive values DPAPI-encrypted)"
Write-Info "All Phase 2-5 monitoring features enabled by default."
Write-Info "Daily digest disabled — configure email in dashboard Settings."
#endregion

#region Verify cert auth
Write-Step "Verifying certificate authentication"
Write-Info "Waiting 15 seconds for admin consent propagation..."
Start-Sleep -Seconds 15

try {
    Connect-MgGraph -TenantId $tenantId -ClientId $clientId -Certificate $cert -NoWelcome -EA Stop
    $testMailbox = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$MailboxAddress" -Method GET -EA Stop
    if ($testMailbox.id) {
        Write-OK "Cert auth verified — mailbox $MailboxAddress is accessible via Graph"
    }
    Disconnect-MgGraph -EA SilentlyContinue | Out-Null
} catch {
    Write-Warn "Cert auth test failed: $_"
    Write-Warn "This is usually consent propagation. Try again in 30-60 seconds:"
    Write-Warn "  Connect-MgGraph -TenantId $tenantId -ClientId $clientId -Certificate (Get-Item Cert:\$CertStore\My\$($cert.Thumbprint))"
    Write-Warn "If still failing, check Entra portal → $AppDisplayName → API permissions"
}
#endregion

#region Summary + launch
Write-Step "Installation complete"

Write-Host ""
Write-Host "Tenant ID       : $tenantId" -ForegroundColor White
Write-Host "Client ID       : $clientId" -ForegroundColor White
Write-Host "Mailbox         : $MailboxAddress" -ForegroundColor White
Write-Host "Cert thumbprint : $($cert.Thumbprint)" -ForegroundColor White
Write-Host "Cert store      : $CertStore" -ForegroundColor White
Write-Host "Working dir     : $WorkingDir" -ForegroundColor White
Write-Host "App registration: $AppDisplayName" -ForegroundColor White
Write-Host ""
Write-Host "Next:" -ForegroundColor Cyan
Write-Host "  1. Click Run Now in the dashboard (first ingestion)" -ForegroundColor White
Write-Host "  2. Click Schedule to register the every-30-minutes task" -ForegroundColor White
Write-Host "  3. Toggle Daily Digest in Settings if you want morning emails" -ForegroundColor White
Write-Host ""

if (-not $SkipLaunch) {
    $launch = Read-Host "Launch dashboard now? (Y/n)"
    if (-not $launch -or $launch -match '^[Yy]') {
        $dashScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) "Start-DMARCDashboard.ps1"
        if (Test-Path $dashScript) {
            $exe = if (Get-Command pwsh -EA SilentlyContinue) { "pwsh" } else { "powershell" }
            Start-Process -FilePath $exe -ArgumentList @("-STA","-ExecutionPolicy","Bypass","-File","`"$dashScript`"")
            Write-OK "Dashboard launching..."
        } else {
            Write-Warn "Dashboard script not found at $dashScript"
            Write-Warn "Launch manually: pwsh -STA -ExecutionPolicy Bypass -File .\Start-DMARCDashboard.ps1"
        }
    }
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
#endregion
