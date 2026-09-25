<#
.SYNOPSIS
DMARC Monitor on a Windows server, in one command.

.DESCRIPTION
From nothing - a Windows Server 2019/2022/2025 or Windows 10/11 machine with a
DNS name pointing at it - to a running, TLS-terminated instance answering on
https://<host>. The Windows counterpart of deploy/bootstrap.sh, with the same
shape and the same arguments:

  1. Installs a private copy of the ASP.NET Core 10 runtime under C:\dmarc\dotnet
     with Microsoft's dotnet-install script, so nothing machine-wide changes.
  2. Downloads the release (or takes it from -FromDir): dmarc.exe, the web
     bundle, and the deploy scripts.
  3. Installs the web app as a Windows service (dmarc-web) running as
     NT AUTHORITY\LocalService, listening on 127.0.0.1:5000 only, with its
     data under C:\dmarc\data and nothing else writable.
  4. Installs Caddy as a service (via WinSW) in front of it, opens 80 and 443
     in Windows Firewall, and writes the Caddyfile for -HostName. Caddy gets
     and renews the certificate.
  5. Writes any configuration it was given, and registers the hourly
     collector task once it knows everything the collector needs.

Re-running it is safe: on an installed machine it only applies configuration.

.EXAMPLE
  .\bootstrap.ps1 -HostName dmarc.example.com -Email you@example.com

.EXAMPLE
  .\bootstrap.ps1 -HostName dmarc.example.com -TenantId <id> -ClientId <id>
  Adds Entra sign-in to an existing install and restarts the service.

.EXAMPLE
  .\bootstrap.ps1 -CollectorOnly -MakeIngestCert -Mailbox dmarc@example.com `
      -IngestTenantId <id> -IngestClientId <id>
  Collects hourly and scans DNS nightly, with nothing left running. No web
  service, no proxy. Open the dashboard yourself when you want it.

.EXAMPLE
  .\bootstrap.ps1 -HostName dmarc.example.com -MakeIngestCert -Mailbox dmarc@example.com `
      -IngestTenantId <id> -IngestClientId <id>
  Creates the collector's certificate, prints the .cer to upload, registers the task.

.EXAMPLE
  .\bootstrap.ps1 -HostName dmarc.example.com -Folders 'DMARC\client-a.example', 'Inbox'
  Collects from those folders, and the folders inside each, instead of Inbox
  and the folders inside it.

.NOTES
Secrets entered on the Settings page are encrypted with DPAPI as LocalService,
the account the service runs as. A provider token stored from an admin console
with `dmarc dns set` is encrypted as that admin and the service cannot read it,
so add DNS providers through the Settings page on Windows.
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$HostName,
    [string]$Email,
    [string]$Release = 'latest',
    [string]$FromDir,
    [string]$Root = 'C:\dmarc',
    [string]$ProviderName,
    [string]$TlsReportAddress,
    [string]$TenantId,
    [string]$ClientId,
    [string]$Mailbox,
    [string]$IngestTenantId,
    [string]$IngestClientId,
    [string]$CertPath,
    [string]$CertPassword,
    [string]$FallbackAddress,
    [string]$ReportingDomain,
    [string]$MasterGroupId,
    [string]$Organization,
    # The mailbox folders the collector reads, in place of Inbox and the
    # folders inside it: -Folders 'DMARC\client-a.example', 'Inbox'. Kept in
    # ingest.cmd as DMARC_FOLDERS, and changed only by giving -Folders again.
    [string[]]$Folders,
    [switch]$MakeIngestCert,
    [switch]$NoProxy,
    [switch]$NoIngestTask,
    # Collect on a schedule, and do not leave anything running.
    #
    # The dashboard is not installed as a service and no reverse proxy is set
    # up; the collector and the nightly DNS scan are scheduled tasks, which
    # wake, do their work and exit. Open the dashboard when you want to look
    # at it - the command is printed at the end.
    #
    # This is the shape for a machine that is not a server: a workstation, or
    # a box in the corner whose job is to keep the reports coming in.
    [switch]$CollectorOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A password on a command line is visible to every account on the machine for
# as long as this runs; the environment is not. -CertPassword still works.
if (-not $CertPassword -and $env:DMARC_CERT_PASSWORD) { $CertPassword = $env:DMARC_CERT_PASSWORD }
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = 'Blackvectra/DMARC-Monitoring-Dashboard'
$ServiceAccount = 'NT AUTHORITY\LocalService'
$AppDir = Join-Path $Root 'app'
$DataDir = Join-Path $Root 'data'
$BackupDir = Join-Path $Root 'backups'
$BinDir = Join-Path $Root 'bin'
$DotnetDir = Join-Path $Root 'dotnet'
$Dotnet = Join-Path $DotnetDir 'dotnet.exe'
$Cli = Join-Path $BinDir 'dmarc.exe'
$Settings = Join-Path $AppDir 'appsettings.Production.json'
$IngestCmd = Join-Path $Root 'ingest.cmd'
$Caddyfile = Join-Path $Root 'Caddyfile'

function Say([string]$Text) { Write-Host $Text }
function Fail([string]$Text, [int]$Code = 1) { Write-Error $Text -ErrorAction Continue; exit $Code }

<#
.SYNOPSIS
Downloads a file, retrying the failures that are worth retrying.

.DESCRIPTION
Every download here is from somebody else's CDN - Microsoft's, Caddy's,
GitHub's - and any of them can return a 5xx for a few seconds. A single
Invoke-WebRequest turns that into a dead install: this script gets most of
the way through, fails at the proxy step, and leaves a half-built machine
for somebody to work out by hand.

It happened in CI on the WinSW download, which answered "504 Gateway
Time-out The server didn't respond in time", and that is exactly what it
would do on a real server on a bad afternoon.

Four attempts, backing off 2, 4 and 8 seconds. Only transport failures and
5xx are retried; a 404 means the file is not there and trying again three
more times just wastes a minute before saying so.
#>
function Get-File([string]$Uri, [string]$OutFile, [hashtable]$Headers = @{}) {
    $delay = 2
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers $Headers -UseBasicParsing
            return
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }

            # 4xx is an answer, not a hiccup. Say it once and stop.
            if ($null -ne $status -and $status -lt 500) { throw }
            if ($attempt -eq 4) { throw }

            Say "   $Uri did not answer ($(if ($status) { $status } else { $_.Exception.Message })); retrying in ${delay}s"
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
}

# icacls takes accounts by SID on every language of Windows; the English display
# names ('Administrators', 'NT AUTHORITY\LocalService') only resolve on an
# English one, and icacls would fail quietly under Out-Null.
$ServiceSid = '*S-1-5-19'      # NT AUTHORITY\LocalService
$SystemSid = '*S-1-5-18'       # SYSTEM
$AdminsSid = '*S-1-5-32-544'   # BUILTIN\Administrators
# Only SYSTEM, administrators and the service account (with the given rights) see the file.
function Set-RestrictedAcl([string]$Path, [string]$ServiceGrant) {
    & icacls.exe $Path /inheritance:r /grant:r "${SystemSid}:F" "${AdminsSid}:F" $ServiceGrant /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls could not restrict $Path" 70 }
}

# Locks the whole install tree down to SYSTEM, Administrators and the service
# account. New-Item created these folders inheriting C:\'s ACL, which grants
# Users read and Authenticated Users modify: any local account could read the
# database, the cookie-signing keys and the stored secrets, and - worse -
# replace a DLL or the dotnet host that the service executes as LocalService,
# a local privilege escalation (OPEN-ISSUES.md #15).
#
# So inheritance is broken and every folder's ACL is stated outright. The
# service account may READ AND EXECUTE the code it runs (app, bin, dotnet) but
# not write it, and MODIFY only its data and its backups. Nobody else is
# named. icacls /grant:r replaces the listed principals rather than adding to
# them, and /inheritance:r drops the inherited entries, so a second run
# produces the same ACL rather than piling entries up - and repairs an install
# left world-writable by an earlier version of this script.
function Set-TreeAcl {
    # The code the service runs: read and execute for it, never write. The
    # inheritable (OI)(CI) entries replace what these folders held and, because
    # the folders no longer inherit from C:\, propagate down to the files
    # already inside - so an install left world-writable by an earlier version
    # of this script is repaired, not just new files protected. No /T is needed
    # for that (nor wanted: it would reset the per-file ACLs set later, such as
    # ingest.pfx's, on a re-run), because setting a parent's inheritable ACEs
    # re-propagates to every child that still inherits.
    foreach ($dir in @($AppDir, $BinDir, $DotnetDir)) {
        & icacls.exe $dir /inheritance:r /grant:r "${SystemSid}:(OI)(CI)F" "${AdminsSid}:(OI)(CI)F" "${ServiceSid}:(OI)(CI)RX" /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "icacls could not secure $dir" 70 }
    }
    # The data the service owns: the database, the keys, the secrets and the
    # backup copies. Modify, so it can write and prune them; still nobody else.
    # Set before the database is created so the database inherits it.
    foreach ($dir in @($DataDir, $BackupDir)) {
        & icacls.exe $dir /inheritance:r /grant:r "${SystemSid}:(OI)(CI)F" "${AdminsSid}:(OI)(CI)F" "${ServiceSid}:(OI)(CI)M" /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "icacls could not secure $dir" 70 }
    }
    # The root itself, set last and without /T so it leaves the folders above
    # alone: the service needs only to traverse it to reach them. Files written
    # directly under it (the .cmd wrappers, the public certificate) inherit
    # SYSTEM and Administrators but not the service, which the per-file
    # Set-RestrictedAcl grants back on the few that the service must run.
    & icacls.exe $Root /inheritance:r /grant:r "${SystemSid}:(OI)(CI)F" "${AdminsSid}:(OI)(CI)F" "${ServiceSid}:(RX)" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls could not secure $Root" 70 }
}

if ($CollectorOnly) { $NoProxy = $true }
if (-not $NoProxy -and -not $HostName) { Fail '-HostName is required (it is what the certificate is for). Use -NoProxy to skip Caddy, or -CollectorOnly for a machine that only collects.' 64 }
if ($HostName -and $HostName -notmatch '^[A-Za-z0-9.-]+$') { Fail '-HostName must be a bare hostname, e.g. dmarc.example.com' 64 }
if ([bool]$TenantId -ne [bool]$ClientId) { Fail '-TenantId and -ClientId go together; the app treats sign-in as configured only when both are set' 64 }
# -Folders as the collector reads DMARC_FOLDERS: the names separated by
# semicolons, so -Folders 'a', 'b' and -Folders 'a;b' come to the same thing.
# It is written inside set "..." in ingest.cmd, where a double quote would end
# the quoting early and a line break would start a command of its own.
$FolderList = (@($Folders) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ';'
if ($FolderList -match '["\r\n]') { Fail '-Folders: a folder name with a double quote or a line break in it cannot be written into ingest.cmd' 64 }
if ([Environment]::Is64BitOperatingSystem -eq $false) { Fail 'a 64-bit Windows is required' 69 }

Say "DMARC Monitor bootstrap on $([Environment]::OSVersion.VersionString)"

foreach ($dir in @($Root, $AppDir, $DataDir, $BackupDir, $BinDir, $DotnetDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}

# ---- 1. runtime --------------------------------------------------------------
# A private copy, with Microsoft's own install script. Machine-wide installs
# are fine too, but a private one means this script's result does not depend
# on what else is on the box, and the service's path to it is fixed.
Say '== runtime'
$haveRuntime = (Test-Path $Dotnet) -and ((& $Dotnet --list-runtimes 2>$null) -match '^Microsoft\.AspNetCore\.App 10\.')
if (-not $haveRuntime) {
    $installer = Join-Path $env:TEMP 'dotnet-install.ps1'
    Get-File 'https://dot.net/v1/dotnet-install.ps1' $installer
    & $installer -Runtime aspnetcore -Channel 10.0 -InstallDir $DotnetDir -NoPath | Out-Null
}
$runtimeLine = (& $Dotnet --list-runtimes) -match '^Microsoft\.AspNetCore\.App 10\.' | Select-Object -First 1
if (-not $runtimeLine) { Fail "the ASP.NET Core 10 runtime did not install under $DotnetDir" 69 }
Say "   $runtimeLine"

# ---- 2. the release ------------------------------------------------------------
$work = Join-Path $env:TEMP ("dmarc-bootstrap-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $installed = Test-Path (Join-Path $AppDir 'DmarcMonitor.Web.dll')
    $webZip = $null; $cliExe = $null; $deployDir = $null

    if ($FromDir) {
        $webZip = Join-Path $FromDir 'dmarc-web.zip'
        $cliExe = Join-Path $FromDir 'dmarc.exe'
        if (Test-Path (Join-Path $FromDir 'deploy')) { $deployDir = Join-Path $FromDir 'deploy' }
        foreach ($f in @($webZip, $cliExe)) { if (-not (Test-Path $f)) { Fail "not found in -FromDir: $f" 66 } }
    } elseif (-not $installed) {
        Say "== release $Release"
        $tag = $Release
        if ($tag -eq 'latest') {
            # Through Get-File for the same reason as every other download:
            # api.github.com rate-limits and occasionally 5xxs, and "could not
            # find the latest release" is a badly wrong thing to tell somebody
            # when the release is there and the API had a bad second.
            $tagFile = Join-Path $env:TEMP 'dmarc-latest.json'
            Get-File "https://api.github.com/repos/$Repo/releases/latest" $tagFile @{ Accept = 'application/vnd.github+json' }
            $tag = (Get-Content $tagFile -Raw | ConvertFrom-Json).tag_name
            Remove-Item $tagFile -ErrorAction SilentlyContinue
            if (-not $tag) { Fail "could not find the latest release of $Repo. Pass -Release <tag>, or -FromDir with the files." 69 }
            Say "   latest is $tag"
        }
        $base = "https://github.com/$Repo/releases/download/$tag"
        foreach ($name in @('dmarc.exe', 'dmarc-web.zip', 'dmarc-deploy.tar.gz')) {
            Say "   fetching $name"
            Get-File "$base/$name" (Join-Path $work $name)
        }
        & tar.exe -xzf (Join-Path $work 'dmarc-deploy.tar.gz') -C $work
        if ($LASTEXITCODE -ne 0) { Fail 'could not unpack dmarc-deploy.tar.gz' 65 }
        $webZip = Join-Path $work 'dmarc-web.zip'
        $cliExe = Join-Path $work 'dmarc.exe'
        $deployDir = Join-Path $work 'deploy'
    }

    # ---- 3. install, unless it already is --------------------------------------
    if ($installed) {
        Say "== already installed at $Root; applying configuration only"
    } else {
        Say '== install'
        $unpack = Join-Path $work 'unpacked'
        Expand-Archive -Path $webZip -DestinationPath $unpack -Force
        $bundle = if (Test-Path (Join-Path $unpack 'dmarc-web\DmarcMonitor.Web.dll')) { Join-Path $unpack 'dmarc-web' }
                  elseif (Test-Path (Join-Path $unpack 'DmarcMonitor.Web.dll')) { $unpack }
                  else { Fail "$webZip does not contain DmarcMonitor.Web.dll - is it the release's dmarc-web.zip?" 65 }
        Copy-Item -Path (Join-Path $bundle '*') -Destination $AppDir -Recurse -Force
        Copy-Item -Path $cliExe -Destination $Cli -Force
        if ($deployDir -and (Test-Path $deployDir)) {
            $keep = Join-Path $Root 'deploy'
            if (-not (Test-Path $keep)) { New-Item -ItemType Directory -Path $keep | Out-Null }
            Copy-Item -Path (Join-Path $deployDir '*') -Destination $keep -Recurse -Force
        }
        Say "   files under $Root"
    }

    # Lock the tree down before the database, keys and secrets are created, so
    # every one of them inherits the restricted ACL rather than C:\'s open one.
    Set-TreeAcl

    $db = Join-Path $DataDir 'dmarc.db'
    if (-not (Test-Path $db)) {
        Say '   creating the database'
        & $Cli init-db --db $db
        if ($LASTEXITCODE -ne 0) { Fail 'dmarc init-db failed' 70 }
    }

    # ---- 4. configuration ------------------------------------------------------
    # Merged into the file that is there, never written over it.
    Say '== configuration'
    if (-not (Test-Path $Settings)) {
        $template = [ordered]@{
            Urls      = 'http://127.0.0.1:5000'
            Database  = [ordered]@{ Path = $db }
            Secrets   = [ordered]@{ Directory = (Join-Path $DataDir 'secrets') }
            Reporting = [ordered]@{ ProviderName = ''; TlsReportAddress = '' }
            MtaSts    = [ordered]@{ PolicyHost = '' }
            Proxy     = [ordered]@{ Behind = $true }
            AzureAd   = [ordered]@{ Instance = 'https://login.microsoftonline.com/'; TenantId = ''; ClientId = ''; CallbackPath = '/signin-oidc' }
            Updates   = [ordered]@{ Repository = $Repo; Channel = 'stable'; Token = '' }
        }
        [IO.File]::WriteAllText($Settings, ($template | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
    }
    $cfg = Get-Content -Raw -Path $Settings | ConvertFrom-Json
    function Set-Setting($obj, [string]$section, [string]$key, $value) {
        if (-not ($obj.PSObject.Properties.Name -contains $section)) { $obj | Add-Member -NotePropertyName $section -NotePropertyValue ([pscustomobject]@{}) }
        $obj.$section | Add-Member -NotePropertyName $key -NotePropertyValue $value -Force
    }
    if ($HostName)         { Set-Setting $cfg 'MtaSts' 'PolicyHost' $HostName }
    if ($ProviderName)     { Set-Setting $cfg 'Reporting' 'ProviderName' $ProviderName }
    if ($TlsReportAddress) { Set-Setting $cfg 'Reporting' 'TlsReportAddress' $TlsReportAddress }
    if ($MasterGroupId) {
        Set-Setting $cfg 'Auth' 'MasterGroupId' $MasterGroupId
        Say "   master group: $MasterGroupId sees every organization"
    }
    if ($TenantId) {
        Set-Setting $cfg 'AzureAd' 'TenantId' $TenantId
        Set-Setting $cfg 'AzureAd' 'ClientId' $ClientId
        Say "   sign-in: Microsoft Entra (tenant $TenantId)"
    } elseif ($cfg.AzureAd.TenantId -and $cfg.AzureAd.ClientId) {
        Say "   sign-in: Microsoft Entra (tenant $($cfg.AzureAd.TenantId), unchanged)"
    } else {
        Say '   sign-in: not configured - the app serves only this machine until -TenantId/-ClientId are given'
    }
    [IO.File]::WriteAllText($Settings, ($cfg | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding $false))
    # Only the service and administrators read the configuration.
    Set-RestrictedAcl $Settings "${ServiceSid}:R"

    # ---- 5. the service --------------------------------------------------------
    #
    # Skipped entirely for a collector-only install. The point of that shape is
    # that nothing is listening between the hourly runs, so creating the
    # service and then telling somebody to stop it would be theatre.
    if ($CollectorOnly) {
        Say '== service'
        Say '   skipped: -CollectorOnly. The dashboard runs when you start it.'
    }
    else {
    Say '== service'
    $svc = Get-Service -Name 'dmarc-web' -ErrorAction SilentlyContinue
    if (-not $svc) {
        $binPath = "`"$Dotnet`" `"$(Join-Path $AppDir 'DmarcMonitor.Web.dll')`" --environment Production --contentRoot `"$AppDir`""
        $cred = New-Object System.Management.Automation.PSCredential($ServiceAccount, (New-Object System.Security.SecureString))
        New-Service -Name 'dmarc-web' -DisplayName 'DMARC Monitor' -Description 'DMARC Monitor web app (listens on 127.0.0.1:5000 for the reverse proxy)' `
            -BinaryPathName $binPath -StartupType Automatic -Credential $cred | Out-Null
        & sc.exe failure dmarc-web reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        Start-Service -Name 'dmarc-web'
        Say '   dmarc-web created and started'
    } else {
        Restart-Service -Name 'dmarc-web'
        Say '   dmarc-web restarted'
    }
    $answered = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 2
        $code = & curl.exe -s -o NUL -w '%{http_code}' http://127.0.0.1:5000/
        if ($code -match '^(2|3|4)') { $answered = $true; break }
    }
    if (-not $answered) {
        Say '   the service did not answer on 127.0.0.1:5000. See what it logged:'
        Say "   Get-WinEvent -LogName Application -MaxEvents 40 | Where-Object { `$_.ProviderName -match 'dmarc|\.NET Runtime' } | Format-List TimeCreated, ProviderName, Message"
        exit 1
    }
    Say "   answers on 127.0.0.1:5000 (HTTP $code)"
    }

    # ---- 6. the collector ------------------------------------------------------
    if ($MakeIngestCert) {
        Say '== collector certificate'
        $pfx = Join-Path $DataDir 'ingest.pfx'
        if (Test-Path $pfx) {
            Say "   $pfx already exists; not replacing it (delete it first to make a new one)"
        } else {
            $CertPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
            $cert = New-SelfSignedCertificate -Subject 'CN=DMARC Monitor ingest' -CertStoreLocation 'Cert:\LocalMachine\My' `
                -KeyExportPolicy Exportable -KeySpec Signature -NotAfter (Get-Date).AddYears(2)
            # Addressed by store path, not by the returned object: under PowerShell 7
            # the PKI module runs through the compatibility layer and hands back a
            # copy without its key.
            $certStorePath = "Cert:\LocalMachine\My\$($cert.Thumbprint)"
            try {
                Export-PfxCertificate -Cert $certStorePath -FilePath $pfx -Password (ConvertTo-SecureString $CertPassword -AsPlainText -Force) | Out-Null
                $cer = Join-Path $Root 'dmarc-ingest.cer'
                Export-Certificate -Cert $certStorePath -FilePath $cer | Out-Null
            } finally {
                # The private key lives in the .pfx from here; -DeleteKey takes the
                # store's copy of the key with it (the certificate provider ignores -Force).
                Remove-Item -Path $certStorePath -DeleteKey
            }
            Set-RestrictedAcl $pfx "${ServiceSid}:R"
            Say "   private half: $pfx (readable by the service; password goes in $IngestCmd)"
            Say "   public half:  $cer  <- upload this under the ingest app registration, Certificates & secrets"
            Say "   expires:      $($cert.NotAfter.ToString('yyyy-MM-dd'))"
            $CertPath = $pfx
        }
    }

    if ($Mailbox -or $IngestTenantId -or $IngestClientId -or $CertPath -or $CertPassword -or $FallbackAddress -or $ReportingDomain -or $Organization -or $FolderList) {
        Say '== collector'
        # The task runs this file; its values persist across runs of this script,
        # and so does a line added to it by hand for any key listed here. Only
        # the first four are required: reports are attributed by the mailbox
        # itself being the one shared address unless the fallback address or the
        # reporting domain is set, and with no folders named the collector reads
        # Inbox and the folders inside it.
        $values = [ordered]@{ DMARC_MAILBOX = ''; DMARC_TENANT_ID = ''; DMARC_CLIENT_ID = ''; DMARC_CERT_PATH = ''; DMARC_CERT_PASSWORD = ''; DMARC_FALLBACK_ADDRESS = ''; DMARC_REPORTING_DOMAIN = ''; DMARC_ORGANIZATION = ''; DMARC_FOLDERS = '' }
        if (Test-Path $IngestCmd) {
            foreach ($line in Get-Content $IngestCmd) {
                if ($line -match '^set "([A-Z_]+)=(.*)"$' -and $values.Contains($Matches[1])) { $values[$Matches[1]] = $Matches[2] }
            }
        }
        if ($Mailbox)        { $values['DMARC_MAILBOX'] = $Mailbox }
        if ($IngestTenantId) { $values['DMARC_TENANT_ID'] = $IngestTenantId }
        if ($IngestClientId) { $values['DMARC_CLIENT_ID'] = $IngestClientId }
        if ($CertPath)       { $values['DMARC_CERT_PATH'] = $CertPath }
        if ($CertPassword)    { $values['DMARC_CERT_PASSWORD'] = $CertPassword }
        if ($FallbackAddress) { $values['DMARC_FALLBACK_ADDRESS'] = $FallbackAddress }
        if ($ReportingDomain) { $values['DMARC_REPORTING_DOMAIN'] = $ReportingDomain }
        if ($Organization)    { $values['DMARC_ORGANIZATION'] = $Organization }
        # A % is doubled because cmd reads one inside set "..." as the start of
        # a variable. A value kept from the file is already written that way.
        if ($FolderList)      { $values['DMARC_FOLDERS'] = $FolderList.Replace('%', '%%') }

        $lines = @('@echo off', ':: Written by bootstrap.ps1. Runs as LocalService from the "DMARC ingest" task; pass --dry-run to test.')
        foreach ($k in $values.Keys) {
            # Left out rather than written empty: set "DMARC_FOLDERS=" would
            # unset a DMARC_FOLDERS set as a system environment variable, which
            # the docs once suggested instead of this file, and collection would
            # quietly go back to reading Inbox alone.
            if ($k -eq 'DMARC_FOLDERS' -and -not $values[$k]) { continue }
            $lines += "set `"$k=$($values[$k])`""
        }
        $lines += "`"$Cli`" ingest --db `"$db`" --mailbox `"%DMARC_MAILBOX%`" %* >> `"$(Join-Path $DataDir 'ingest.log')`" 2>&1"
        [IO.File]::WriteAllLines($IngestCmd, $lines, (New-Object Text.UTF8Encoding $false))
        Set-RestrictedAcl $IngestCmd "${ServiceSid}:RX"

        $optional = @('DMARC_CERT_PASSWORD', 'DMARC_FALLBACK_ADDRESS', 'DMARC_REPORTING_DOMAIN', 'DMARC_ORGANIZATION', 'DMARC_FOLDERS')
        $missing = @($values.Keys | Where-Object { $optional -notcontains $_ -and -not $values[$_] })
        if ($missing.Count -eq 0 -and -not $NoIngestTask) {
            $action = New-ScheduledTaskAction -Execute $IngestCmd
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)
            $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType ServiceAccount -RunLevel Limited
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -StartWhenAvailable -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName 'DMARC ingest' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
            Say "   task 'DMARC ingest' registered (hourly). Dry-run first: cmd /c `"$IngestCmd`" --dry-run  then  type $(Join-Path $DataDir 'ingest.log')"
        } else {
            Say "   task not registered yet; still missing: $($missing -join ', ')"
        }
    }

    # A scheduled task registered as LocalService, running a .cmd wrapper that
    # logs into the data directory. The wrapper pattern (and the exit-code
    # massaging in it) matches the ingest task above and the dmarc-* units on
    # Linux: a command's real failure marks the task failed, and its ordinary
    # "nothing to do" answers do not.
    function Register-DmarcTask {
        param([string]$Name, [string]$CmdPath, [string[]]$Body, $Trigger, [int]$LimitHours = 1)
        [IO.File]::WriteAllLines($CmdPath, (@('@echo off') + $Body), (New-Object Text.UTF8Encoding $false))
        Set-RestrictedAcl $CmdPath "${ServiceSid}:RX"
        $action = New-ScheduledTaskAction -Execute $CmdPath
        $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType ServiceAccount -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours $LimitHours) -StartWhenAvailable -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $Name -Action $action -Trigger $Trigger -Principal $principal -Settings $settings -Force | Out-Null
    }

    # ---- 6b. the nightly DNS scan ----------------------------------------------
    #
    # What fills the SPF, DKIM and DMARC columns on the domains page, AND what
    # turns the Sending sources page from a list of addresses into a list of
    # names. Both are the same job - reading public DNS and writing the answers
    # down - on the same nightly schedule, which is exactly how Linux runs them:
    # dmarc-dns.service has `check --all --save` and `dmarc intel --names` as
    # its two ExecStart lines. Windows ran only the first, so a server here
    # never looked up who a sender was and the sources page stayed all digits.
    #
    # Registered unconditionally: it needs no mailbox, no app registration and
    # no certificate, only the database and public DNS. Left for somebody to
    # switch on later it would be a feature that shows dashes forever with
    # nothing on screen explaining why.
    Say '== nightly DNS scan and sender-name lookup'
    $DnsCmd = Join-Path $Root 'dns-scan.cmd'
    $dnsLog = Join-Path $DataDir 'dns-scan.log'
    $dnsBody = @(
        ':: Written by bootstrap.ps1. Reads each domain''s published DNS and stores',
        ':: it, then looks up what each sending address reverse-resolves to so the',
        ':: pages can name a sender instead of printing an address. The two jobs',
        ':: dmarc-dns.service runs on Linux, on the same nightly schedule.',
        ':: Run it by hand any time; it needs no configuration.',
        "`"$Cli`" check --all --save --db `"$db`" >> `"$dnsLog`" 2>&1",
        'set "DNS_RC=%ERRORLEVEL%"',
        ':: The reverse-DNS names, exactly as the Linux unit''s second ExecStart.',
        ':: An address with no reverse record is an ordinary answer, so this only',
        ':: fails the task on a real error, never on an address it could not name.',
        "`"$Cli`" intel --names --db `"$db`" >> `"$dnsLog`" 2>&1",
        'set "INTEL_RC=%ERRORLEVEL%"',
        ':: Mirror dmarc-dns.service SuccessExitStatus=0 1 66: 0 is fine, 1 is a',
        ':: breaking fault found in somebody''s records (the command working), and',
        ':: 66 is "no domains yet" on a box the collector has not filled. Anything',
        ':: worse from either command is a genuine failure and marks the task.',
        'if %DNS_RC% GEQ 2 if not "%DNS_RC%"=="66" exit /b %DNS_RC%',
        'if %INTEL_RC% GEQ 2 if not "%INTEL_RC%"=="66" exit /b %INTEL_RC%',
        'exit /b 0')
    # Nightly, at an hour nobody is looking, with the window spread so a room
    # full of these installs does not hit the same resolver on the same minute.
    Register-DmarcTask 'DMARC DNS scan' $DnsCmd $dnsBody `
        (New-ScheduledTaskTrigger -Daily -At '03:20' -RandomDelay (New-TimeSpan -Minutes 30))
    Say "   task 'DMARC DNS scan' registered (nightly, DNS records and sender names). Run it now with: Start-ScheduledTask -TaskName 'DMARC DNS scan'"

    # ---- 6c. backup, retention and health --------------------------------------
    #
    # The three things a Linux install switches on during setup and a Windows
    # one used to lack entirely (OPEN-ISSUES.md 10b): nothing was protecting the
    # reports, nothing was applying the retention window, and nothing would tell
    # anybody the collector had quietly stopped. The commands are cross-platform;
    # only the scheduling was missing. Registered unconditionally, for the same
    # reason as the DNS scan and mirroring the dmarc-backup/prune/health timers.
    Say '== backup, retention and health'

    # Nightly 03:20, 14 kept, into a directory only the service and admins can
    # read - matching dmarc-backup.timer. The command verifies the live database
    # before copying it, so a database that has begun to corrupt stops the run.
    $BackupCmd = Join-Path $Root 'backup.cmd'
    $backupLog = Join-Path $DataDir 'backup.log'
    $backupBody = @(
        ':: Written by bootstrap.ps1. A verified copy of the database; keeps 14.',
        ':: Real failures (a corrupt database, an unwritable target) mark the task.',
        "`"$Cli`" backup --to `"$BackupDir`" --keep 14 --db `"$db`" >> `"$backupLog`" 2>&1",
        'exit /b %ERRORLEVEL%')
    Register-DmarcTask 'DMARC backup' $BackupCmd $backupBody `
        (New-ScheduledTaskTrigger -Daily -At '03:20' -RandomDelay (New-TimeSpan -Minutes 5))

    # Weekly, Sunday 04:40 - after the nightly backup's slot - matching
    # dmarc-prune.timer. The window is written here where an operator can read
    # and change it, aggregate 400 days and forensic 30, and the command refuses
    # a policy where the forensic window is the longer of the two.
    $PruneCmd = Join-Path $Root 'prune.cmd'
    $pruneLog = Join-Path $DataDir 'prune.log'
    $pruneBody = @(
        ':: Written by bootstrap.ps1. Applies the retention window: aggregate 400',
        ':: days, forensic 30. Forensic reports hold real message headers, so that',
        ':: window is deliberately the shortest. Edit these two numbers only.',
        "`"$Cli`" prune --apply --by `"DMARC prune`" --aggregate-days 400 --forensic-days 30 --db `"$db`" >> `"$pruneLog`" 2>&1",
        'exit /b %ERRORLEVEL%')
    Register-DmarcTask 'DMARC prune' $PruneCmd $pruneBody `
        (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At '04:40' -RandomDelay (New-TimeSpan -Minutes 30))

    # 09:10 and 21:10 - matching dmarc-health.timer. --quiet, so a healthy run
    # says nothing; when it finds the collector or the backups have stopped it
    # exits non-zero, which marks the task failed. Windows has no OnFailure= to
    # hang an alert on, but a failed task shows in Task Scheduler's Last Run
    # Result and is what a monitoring agent watching the task reports.
    $HealthCmd = Join-Path $Root 'health.cmd'
    $healthLog = Join-Path $DataDir 'health.log'
    $healthBody = @(
        ':: Written by bootstrap.ps1. Asks whether collection and backups are',
        ':: still happening; a non-zero exit (something actually broken) marks',
        ':: the task failed. See it by hand: schtasks /query /tn "DMARC health" /v',
        "`"$Cli`" health --db `"$db`" --backups `"$BackupDir`" --quiet >> `"$healthLog`" 2>&1",
        'exit /b %ERRORLEVEL%')
    Register-DmarcTask 'DMARC health' $HealthCmd $healthBody @(
        (New-ScheduledTaskTrigger -Daily -At '09:10' -RandomDelay (New-TimeSpan -Minutes 5)),
        (New-ScheduledTaskTrigger -Daily -At '21:10' -RandomDelay (New-TimeSpan -Minutes 5)))
    Say "   tasks 'DMARC backup' (nightly), 'DMARC prune' (weekly) and 'DMARC health' (twice daily) registered"

    # And take the first backup now, rather than leaving the first until 03:20
    # tomorrow - the same reason install.sh does on Linux. It seeds a copy so
    # the health task does not report "no backups" on its first evening, and it
    # proves the backup works on this machine while somebody is watching.
    # Never fatal: everything above is installed, and a backup problem must not
    # make a working install look like a failed one.
    try {
        & $Cli backup --to $BackupDir --keep 14 --db $db 2>&1 |
            Out-File -FilePath (Join-Path $DataDir 'backup.log') -Append -Encoding utf8
        if ($LASTEXITCODE -eq 0) {
            $newest = Get-ChildItem -Path $BackupDir -Filter 'dmarc-*.bak' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($newest) { Say "   first backup taken: $($newest.Name)" }
            else { Say '   backup reported success but wrote nothing to the backups folder' }
        } else {
            Say "   the first backup did not succeed (exit $LASTEXITCODE); the nightly task will retry. See $(Join-Path $DataDir 'backup.log')"
        }
    } catch {
        Say "   the first backup could not run: $($_.Exception.Message)"
    }
    # A non-zero from the backup above must not leak into a later step's check.
    $global:LASTEXITCODE = 0

    # ---- 7. Caddy in front -----------------------------------------------------
    if (-not $NoProxy) {
        Say '== proxy'
        # Caddy needs 80 and 443. On a machine with IIS they belong to
        # http.sys, which shows as the System process (pid 4), and Caddy's
        # own error for that is a sentence about socket access permissions.
        if (-not (Get-Service -Name 'caddy' -ErrorAction SilentlyContinue)) {
            foreach ($port in 80, 443) {
                $taken = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($taken) {
                    $pid_ = $taken.OwningProcess
                    $name = (Get-Process -Id $pid_ -ErrorAction SilentlyContinue).ProcessName
                    $hint = if ($pid_ -eq 4) { 'pid 4 is http.sys, usually IIS: Stop-Service W3SVC; Set-Service W3SVC -StartupType Disabled' } else { "stop $name, or run with -NoProxy and put your own proxy in front" }
                    Fail "port $port is already taken by $name (pid $pid_). Caddy needs 80 and 443. $hint" 69
                }
            }
        }
        $caddy = Join-Path $BinDir 'caddy.exe'
        if (-not (Test-Path $caddy)) {
            Say '   fetching Caddy'
            Get-File 'https://caddyserver.com/api/download?os=windows&arch=amd64' $caddy
        }
        $winsw = Join-Path $BinDir 'caddy-service.exe'
        if (-not (Test-Path $winsw)) {
            Say '   fetching WinSW (runs Caddy as a service)'
            Get-File 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe' $winsw
        }
        $caddyHome = Join-Path $Root 'caddy'
        if (-not (Test-Path $caddyHome)) { New-Item -ItemType Directory -Path $caddyHome | Out-Null }
        $caddyLines = @()
        if ($Email) { $caddyLines += '{'; $caddyLines += "    email $Email"; $caddyLines += '}'; $caddyLines += '' }
        $caddyLines += "$HostName {"; $caddyLines += '    reverse_proxy 127.0.0.1:5000'; $caddyLines += '}'
        [IO.File]::WriteAllLines($Caddyfile, $caddyLines, (New-Object Text.UTF8Encoding $false))
        # Caddy logs to stderr even when the file is fine. Windows PowerShell 5.1
        # turns redirected native stderr into errors that 'Stop' would throw on,
        # so the preference is relaxed for this one call and the exit code decides.
        $eap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & $caddy validate --config $Caddyfile --adapter caddyfile 2>&1 | Out-Null } finally { $ErrorActionPreference = $eap }
        if ($LASTEXITCODE -ne 0) { Fail "Caddy rejected $Caddyfile" 65 }

        $xml = @"
<service>
  <id>caddy</id>
  <name>Caddy (DMARC Monitor)</name>
  <description>Reverse proxy and TLS for DMARC Monitor</description>
  <executable>$caddy</executable>
  <arguments>run --config $Caddyfile --adapter caddyfile</arguments>
  <env name="XDG_DATA_HOME" value="$caddyHome"/>
  <env name="XDG_CONFIG_HOME" value="$caddyHome"/>
  <log mode="roll"></log>
  <onfailure action="restart" delay="10 sec"/>
  <startmode>Automatic</startmode>
</service>
"@
        [IO.File]::WriteAllText((Join-Path $BinDir 'caddy-service.xml'), $xml, (New-Object Text.UTF8Encoding $false))

        if (-not (Get-NetFirewallRule -DisplayName 'DMARC Monitor web' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'DMARC Monitor web' -Direction Inbound -Protocol TCP -LocalPort 80, 443 -Action Allow | Out-Null
            Say '   Windows Firewall: 80 and 443 open'
        }

        if (-not (Get-Service -Name 'caddy' -ErrorAction SilentlyContinue)) {
            & $winsw install | Out-Null
            & $winsw start | Out-Null
            Say '   caddy service created and started'
        } else {
            Restart-Service -Name 'caddy'
            Say '   caddy restarted'
        }
        Start-Sleep -Seconds 3
        $code = & curl.exe -sk -o NUL -w '%{http_code}' --resolve "${HostName}:443:127.0.0.1" "https://$HostName/"
        # The probe is advisory, and it is the last native command the script
        # runs: a curl that could not connect leaves its exit code in
        # $LASTEXITCODE, which a CI step wrapper then turns into a failed step
        # after the script has printed Done. Fail still exits through a real
        # exit, so clearing this here loses nothing.
        if (-not $code) { $code = '000' }
        $global:LASTEXITCODE = 0
        switch ($code) {
            '403' { Say "   https://$HostName/ answers 403: TLS and the proxy work; sign-in is not configured yet, so only this machine is served" }
            '302' { Say "   https://$HostName/ redirects to sign-in: TLS, the proxy and Entra are all wired" }
            default { Say "   https://$HostName/ answered '$code'. Caddy may still be getting the certificate; see $BinDir\caddy-service.out.log" }
        }
    }
} finally {
    Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- done -------------------------------------------------------------------
Say ''
Say 'Done.'

# A collector-only install has nothing listening, so the last thing printed is
# how to look at what it collected. Without this the install finishes with no
# URL and no service, which reads as a failure.
if ($CollectorOnly) {
    $dbPath = Join-Path $DataDir 'dmarc.db'
    Say @"
Collecting on a schedule. Nothing is left running.

  DMARC ingest     hourly, catches up if the machine was asleep
  DMARC DNS scan   nightly at 03:20
  database         $dbPath

To look at it, from an elevated PowerShell:
  & "$Dotnet" "$(Join-Path $AppDir 'DmarcMonitor.Web.dll')" --contentRoot "$AppDir"
then open http://127.0.0.1:5000 . Close the window when you are done; the
collector keeps running without it.

To see the tasks, or run one now:
  Get-ScheduledTask -TaskName 'DMARC*'
  Start-ScheduledTask -TaskName 'DMARC ingest'
"@
}

$signInConfigured = $TenantId -or ((Test-Path $Settings) -and ((Get-Content -Raw $Settings | ConvertFrom-Json).AzureAd.TenantId))
if (-not $CollectorOnly -and -not $signInConfigured) {
    $h = if ($HostName) { $HostName } else { '<host>' }
    Say @"
Next: sign-in. In Entra, App registrations -> New registration:
  name DMARC Monitor, single tenant, Redirect URI (Web) https://$h/signin-oidc
  Authentication: add Redirect URI https://$h/signout-callback-oidc,
    Front-channel logout URL https://$h/signout-oidc,
    tick "ID tokens (used for implicit and hybrid flows)", Save.
  Enterprise applications -> DMARC Monitor -> Permissions -> Grant admin consent;
    Properties -> Assignment required = Yes; Users and groups -> add who may sign in.
Then, here:
  .\bootstrap.ps1 -HostName $h -TenantId <directory id> -ClientId <application id>
"@
}
if (-not (Test-Path $IngestCmd)) {
    $where = if ($CollectorOnly) { '-CollectorOnly' } else { "-HostName $(if ($HostName) { $HostName } else { '<host>' })" }
    Say @"
Mailbox collection: docs/INGEST-SETUP.md. When the ingest app registration exists:
  .\bootstrap.ps1 $where -MakeIngestCert -Mailbox dmarc@example.com ``
      -IngestTenantId <directory id> -IngestClientId <ingest application id>
"@
}
