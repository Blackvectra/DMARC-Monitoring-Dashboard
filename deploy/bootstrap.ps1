<#
.SYNOPSIS
DMARC Monitor on a Windows server, in one command.

.DESCRIPTION
From nothing - a Windows Server 2019/2022/2025 or Windows 10/11 machine with a
DNS name pointing at it - to a running, TLS-terminated instance answering on
https://<host>. The Windows counterpart of deploy/bootstrap.sh, with the same
shape and the same arguments:

  1. Installs a private copy of the ASP.NET Core 8 runtime under C:\dmarc\dotnet
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
  .\bootstrap.ps1 -HostName dmarc.example.com -MakeIngestCert -Mailbox dmarc@example.com `
      -IngestTenantId <id> -IngestClientId <id>
  Creates the collector's certificate, prints the .cer to upload, registers the task.

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
    [switch]$MakeIngestCert,
    [switch]$NoProxy,
    [switch]$NoIngestTask
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
$BinDir = Join-Path $Root 'bin'
$DotnetDir = Join-Path $Root 'dotnet'
$Dotnet = Join-Path $DotnetDir 'dotnet.exe'
$Cli = Join-Path $BinDir 'dmarc.exe'
$Settings = Join-Path $AppDir 'appsettings.Production.json'
$IngestCmd = Join-Path $Root 'ingest.cmd'
$Caddyfile = Join-Path $Root 'Caddyfile'

function Say([string]$Text) { Write-Host $Text }
function Fail([string]$Text, [int]$Code = 1) { Write-Error $Text -ErrorAction Continue; exit $Code }

# icacls takes accounts by SID on every language of Windows; the English display
# names ('Administrators', 'NT AUTHORITY\LocalService') only resolve on an
# English one, and icacls would fail quietly under Out-Null.
$ServiceSid = '*S-1-5-19'      # NT AUTHORITY\LocalService
$SystemSid = '*S-1-5-18'       # SYSTEM
$AdminsSid = '*S-1-5-32-544'   # BUILTIN\Administrators
function Grant-Acl([string]$Path, [string]$Grant) {
    & icacls.exe $Path /grant $Grant /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls could not grant '$Grant' on $Path" 70 }
}
# Only SYSTEM, administrators and the service account (with the given rights) see the file.
function Set-RestrictedAcl([string]$Path, [string]$ServiceGrant) {
    & icacls.exe $Path /inheritance:r /grant:r "${SystemSid}:F" "${AdminsSid}:F" $ServiceGrant /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls could not restrict $Path" 70 }
}

if (-not $NoProxy -and -not $HostName) { Fail '-HostName is required (it is what the certificate is for). Use -NoProxy to skip Caddy.' 64 }
if ($HostName -and $HostName -notmatch '^[A-Za-z0-9.-]+$') { Fail '-HostName must be a bare hostname, e.g. dmarc.example.com' 64 }
if ([bool]$TenantId -ne [bool]$ClientId) { Fail '-TenantId and -ClientId go together; the app treats sign-in as configured only when both are set' 64 }
if ([Environment]::Is64BitOperatingSystem -eq $false) { Fail 'a 64-bit Windows is required' 69 }

Say "DMARC Monitor bootstrap on $([Environment]::OSVersion.VersionString)"

foreach ($dir in @($Root, $AppDir, $DataDir, $BinDir, $DotnetDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}

# ---- 1. runtime --------------------------------------------------------------
# A private copy, with Microsoft's own install script. Machine-wide installs
# are fine too, but a private one means this script's result does not depend
# on what else is on the box, and the service's path to it is fixed.
Say '== runtime'
$haveRuntime = (Test-Path $Dotnet) -and ((& $Dotnet --list-runtimes 2>$null) -match '^Microsoft\.AspNetCore\.App 8\.')
if (-not $haveRuntime) {
    $installer = Join-Path $env:TEMP 'dotnet-install.ps1'
    Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $installer -UseBasicParsing
    & $installer -Runtime aspnetcore -Channel 8.0 -InstallDir $DotnetDir -NoPath | Out-Null
}
$runtimeLine = (& $Dotnet --list-runtimes) -match '^Microsoft\.AspNetCore\.App 8\.' | Select-Object -First 1
if (-not $runtimeLine) { Fail "the ASP.NET Core 8 runtime did not install under $DotnetDir" 69 }
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
            $tag = (Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ Accept = 'application/vnd.github+json' } -UseBasicParsing).tag_name
            if (-not $tag) { Fail "could not find the latest release of $Repo. Pass -Release <tag>, or -FromDir with the files." 69 }
            Say "   latest is $tag"
        }
        $base = "https://github.com/$Repo/releases/download/$tag"
        foreach ($name in @('dmarc.exe', 'dmarc-web.zip', 'dmarc-deploy.tar.gz')) {
            Say "   fetching $name"
            Invoke-WebRequest -Uri "$base/$name" -OutFile (Join-Path $work $name) -UseBasicParsing
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

    # The service account may write data and read everything else. Done before
    # the database is created, so the file inherits it.
    Grant-Acl $DataDir "${ServiceSid}:(OI)(CI)M"
    foreach ($dir in @($AppDir, $BinDir, $DotnetDir)) { Grant-Acl $dir "${ServiceSid}:(OI)(CI)RX" }

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

    if ($Mailbox -or $IngestTenantId -or $IngestClientId -or $CertPath -or $CertPassword -or $FallbackAddress -or $ReportingDomain) {
        Say '== collector'
        # The task runs this file; its values persist across runs of this script.
        # The last two are optional: reports are attributed by the mailbox
        # itself being the one shared address unless one of them is set.
        $values = [ordered]@{ DMARC_MAILBOX = ''; DMARC_TENANT_ID = ''; DMARC_CLIENT_ID = ''; DMARC_CERT_PATH = ''; DMARC_CERT_PASSWORD = ''; DMARC_FALLBACK_ADDRESS = ''; DMARC_REPORTING_DOMAIN = ''; DMARC_ORGANIZATION = '' }
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

        $lines = @('@echo off', ':: Written by bootstrap.ps1. Runs as LocalService from the "DMARC ingest" task; pass --dry-run to test.')
        foreach ($k in $values.Keys) { $lines += "set `"$k=$($values[$k])`"" }
        $lines += "`"$Cli`" ingest --db `"$db`" --mailbox `"%DMARC_MAILBOX%`" %* >> `"$(Join-Path $DataDir 'ingest.log')`" 2>&1"
        [IO.File]::WriteAllLines($IngestCmd, $lines, (New-Object Text.UTF8Encoding $false))
        Set-RestrictedAcl $IngestCmd "${ServiceSid}:RX"

        $optional = @('DMARC_CERT_PASSWORD', 'DMARC_FALLBACK_ADDRESS', 'DMARC_REPORTING_DOMAIN', 'DMARC_ORGANIZATION')
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
            Invoke-WebRequest -Uri 'https://caddyserver.com/api/download?os=windows&arch=amd64' -OutFile $caddy -UseBasicParsing
        }
        $winsw = Join-Path $BinDir 'caddy-service.exe'
        if (-not (Test-Path $winsw)) {
            Say '   fetching WinSW (runs Caddy as a service)'
            Invoke-WebRequest -Uri 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe' -OutFile $winsw -UseBasicParsing
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
$signInConfigured = $TenantId -or ((Test-Path $Settings) -and ((Get-Content -Raw $Settings | ConvertFrom-Json).AzureAd.TenantId))
if (-not $signInConfigured) {
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
    Say @"
Mailbox collection: docs/INGEST-SETUP.md. When the ingest app registration exists:
  .\bootstrap.ps1 -HostName $(if ($HostName) { $HostName } else { '<host>' }) -MakeIngestCert -Mailbox dmarc@example.com ``
      -IngestTenantId <directory id> -IngestClientId <ingest application id>
"@
}
