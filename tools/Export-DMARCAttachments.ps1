<#
.SYNOPSIS
    Saves every DMARC report attachment from a mailbox to disk, Inbox included.

.DESCRIPTION
    One file, nothing to install. Copy it onto a machine with Outlook open and
    run it. No repository, no .NET, no app registration, no admin involvement.
    Windows PowerShell as it ships is enough.

    The Inbox is always exported. Naming a folder used to mean only that
    folder was read, which quietly missed every report that had arrived and
    not yet been filed - and on a mailbox where a rule sorts reports into
    per-domain folders, the unfiled ones are the newest ones. Pass -SkipInbox
    if you really want just the folder.

    Subfolders are included and mirrored into the output, so reports sorted
    into DMARC\acme.com land in <output>\acme.com and still say which domain
    they belong to.

    Run it again into the same folder and it saves only what is new. Every
    report it saves is fingerprinted by its contents into
    .dmarc-export-index.txt in the output folder, and a report already there
    is not saved again - under the same name or a different one, since
    receivers reuse file names. Files that were in the folder before the
    index existed count as exported too, so an old export folder can simply
    be kept. Deleting a file after importing it does not bring it back: the
    index remembers it. Delete the index to start over.

    Every folder it looks in is listed with what it found, including the ones
    that held nothing. "Inbox  412 scanned  0 saved" and no line at all for
    the Inbox mean different things, and only one of them is a problem.

.PARAMETER Folder
    The folder to export, as its name appears in Outlook. Leave it out to
    export the whole mailbox, which is usually what you want for a mailbox
    that exists only to receive reports.

.PARAMETER SkipInbox
    Do not add the Inbox when -Folder is given. Only useful when you know the
    Inbox holds nothing you want.

.PARAMETER LeaveUnread
    Leave messages as they were. By default a message whose report was saved
    is marked as read, so the next run's "unread" count means new reports
    rather than everything ever received. A message whose attachment could
    not be saved is never marked, so it is still there to be noticed.

.PARAMETER Schedule
    Register a Windows scheduled task that runs this export every day at the
    given time - "07:00", "6:30 PM" - with the same -OutputPath, -Mailbox,
    -Folder and other options, then exit without exporting. The task runs as
    you, only while you are signed in, because Outlook runs in your session
    and nothing outside it can reach it. Each run is appended to
    .dmarc-export-log.txt in the output folder. Run with -Schedule again to
    change the time or options; it replaces the task.

.PARAMETER Unschedule
    Remove the daily task registered by -Schedule.

.PARAMETER LogFile
    Append everything this run prints to a file. The scheduled task passes
    this so a run nobody watched still leaves a record.

.PARAMETER List
    Show what is there and exit, without exporting anything. Use this when a
    name does not match and you want to see what is actually available.

    With several mailboxes open and no -Mailbox, it prints their NAMES only.
    Add -Mailbox to look inside one. The stores Outlook keeps open beside a
    reporting mailbox are somebody's real mail - a personal account, an
    archive, public folders - and printing all of their folders is both more
    than anyone needs to pick one and more than belongs in the ticket this
    output gets pasted into.

.PARAMETER OutputPath
    Where to write. Created if it does not exist.

.PARAMETER Mailbox
    Which mailbox to look in, when more than one is open. A shared mailbox is
    a SEPARATE store in Outlook, so without this the script searches whichever
    happens to be first, which is usually the operator's own. Matching is on
    any part of the name, so "DMARC" or the full address both work.

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -OutputPath C:\dmarc-export -Mailbox "DMARC Reports"
    The whole mailbox, Inbox and every folder under it. Quote a mailbox name
    containing a space, or PowerShell reads the second word as the next
    parameter.

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -Folder DMARC -OutputPath C:\dmarc-export
    The DMARC folder AND the Inbox, because reports that have not been filed
    yet are still reports.

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -OutputPath C:\dmarc-export -Mailbox "DMARC Reports" -Schedule 07:00
    Export every morning at 7 into the same folder, new reports only, marking
    each message read. -Unschedule removes it.

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -OutputPath C:\x -Mailbox "DMARC Reports" -List
    Show what folders exist, without exporting.

.NOTES
    This file is no longer signed. Editing a signed script invalidates its
    signature, and an invalid signature is worse than none - it reads as
    tampering. Re-sign it with your own certificate before deploying it:

        Set-AuthenticodeSignature .\Export-DMARCAttachments.ps1 `
            -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0]
#>

[CmdletBinding()]
param(
    # Empty means the whole mailbox. That is the right default for a mailbox
    # that exists only to receive reports: there is nothing else in it.
    [string]$Folder = '',
    [Parameter(Mandatory)] [string]$OutputPath,
    [string]$Mailbox,
    [switch]$List,
    [switch]$SkipInbox,
    [switch]$LeaveUnread,
    [string]$Schedule,
    [switch]$Unschedule,
    [string]$LogFile,

    # A mailbox also holds signature images and auto-replies. Reports are
    # always one of these, so everything else is skipped rather than written.
    [string[]]$Extensions = @('.gz', '.zip', '.xml', '.json')
)

$ErrorActionPreference = 'Stop'

# Outlook saves attachments relative to ITS working directory, not this
# shell's. Given "-OutputPath .\export", the directory was created here and
# the files were written wherever Outlook happened to be - usually the user's
# profile - or not at all. Both examples in the help use absolute paths, which
# is why it never showed. Made absolute once, before anything looks at it.
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

# The file's extension is lowercased before it is compared, so the list it is
# compared against has to be too, or "-Extensions .XML" matched nothing and
# said nothing. A missing dot is supplied for the same reason.
#
# Split on commas as well: a scheduled task passes "-Extensions .gz,.zip" to
# powershell -File, which hands it over as one string rather than a list.
$Extensions = @($Extensions | ForEach-Object { $_ -split ',' } | ForEach-Object {
    $e = $_.Trim().ToLowerInvariant()
    if ($e -and -not $e.StartsWith('.')) { ".$e" } else { $e }
} | Where-Object { $_ })

# ---- run daily ------------------------------------------------------------

$TaskName = 'DMARC report export'

if ($Unschedule) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed the daily task '$TaskName'." -ForegroundColor Green
    } else {
        Write-Host "No task called '$TaskName' is registered."
    }
    exit 0
}

if ($Schedule) {
    $at = [datetime]::MinValue
    if (-not [datetime]::TryParse($Schedule, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$at)) {
        Write-Host "-Schedule takes a time of day, such as 07:00 or `"6:30 PM`"." -ForegroundColor Red
        exit 64
    }

    # The same export, run by the task. Everything that shapes it is passed
    # through; -Schedule itself is not, or every run would re-register.
    $log = if ($LogFile) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFile) }
           else { Join-Path $OutputPath '.dmarc-export-log.txt' }
    $taskArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
                  '-File', "`"$PSCommandPath`"", '-OutputPath', "`"$OutputPath`"", '-LogFile', "`"$log`"")
    if ($Mailbox)     { $taskArgs += @('-Mailbox', "`"$Mailbox`"") }
    if ($Folder)      { $taskArgs += @('-Folder', "`"$Folder`"") }
    if ($SkipInbox)   { $taskArgs += '-SkipInbox' }
    if ($LeaveUnread) { $taskArgs += '-LeaveUnread' }
    if ($PSBoundParameters.ContainsKey('Extensions')) { $taskArgs += @('-Extensions', ($Extensions -join ',')) }

    # Whichever PowerShell is running this - Windows PowerShell or 7 - runs
    # the task too, so it behaves the way it did when it was set up.
    $shell = (Get-Process -Id $PID).Path

    $action = New-ScheduledTaskAction -Execute $shell -Argument ($taskArgs -join ' ')
    $trigger = New-ScheduledTaskTrigger -Daily -At $at

    # Interactive, as the signed-in user. Outlook runs in that session; a
    # task set to run "whether the user is logged on or not" runs in a
    # session with no Outlook in it and can only fail.
    $principal = New-ScheduledTaskPrincipal -UserId "$([Environment]::UserDomainName)\$([Environment]::UserName)" -LogonType Interactive

    # A laptop asleep at 7:00 runs it when it wakes, rather than skipping a day.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2)

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Force | Out-Null

    Write-Host ""
    Write-Host "Registered '$TaskName': every day at $($at.ToString('HH:mm')), into $OutputPath." -ForegroundColor Green
    Write-Host "It runs while you are signed in, with Outlook open or not yet started; each run is logged to" -ForegroundColor DarkGray
    Write-Host "  $log" -ForegroundColor DarkGray
    Write-Host "Run it now to check:  Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor DarkGray
    Write-Host "Remove it:            .\Export-DMARCAttachments.ps1 -OutputPath `"$OutputPath`" -Unschedule" -ForegroundColor DarkGray
    Write-Host ""
    exit 0
}

if ($LogFile) {
    $LogFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFile)
    $logDir = Split-Path -Parent $LogFile
    if ($logDir -and -not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    Start-Transcript -Path $LogFile -Append | Out-Null
}

# ---- connect --------------------------------------------------------------

# Two ways in, and when both fail the reason each gave IS the diagnosis.
# Printing "could not talk to Outlook, open Outlook" and throwing the
# exceptions away sent people to stare at an Outlook that was open the whole
# time - the one thing the message told them to check.
#
# Three causes look identical from here and share no fix:
#   - the new Outlook (olk.exe) registers no COM class at all
#   - an elevated shell cannot reach an Outlook running as the ordinary user
#   - PowerShell 7 has no Marshal::GetActiveObject, so only the second way works
$attempts = New-Object 'System.Collections.Generic.List[string]'
$outlook = $null

$hasGetActiveObject = @(
    [Runtime.InteropServices.Marshal].GetMethods() | Where-Object { $_.Name -eq 'GetActiveObject' }
).Count -gt 0

if ($hasGetActiveObject) {
    try {
        # Reuse the running Outlook if there is one, so this does not start a
        # second instance and trip the security prompt.
        $outlook = [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application')
    } catch {
        $attempts.Add("attach to a running Outlook: $($_.Exception.Message)")
    }
} else {
    # Worth saying, and worth saying it is not the problem: the API was never
    # ported to .NET Core. The way below works on PowerShell 7 regardless.
    $attempts.Add("attach to a running Outlook: PowerShell $($PSVersionTable.PSVersion) has no Marshal::GetActiveObject, which is .NET Framework only. Harmless on its own - the next way does not need it.")
}

if (-not $outlook) {
    try {
        # Outlook is a single-instance COM server, so this attaches to the one
        # already running rather than starting a second.
        $outlook = New-Object -ComObject Outlook.Application
    } catch {
        $attempts.Add("start Outlook through COM: $($_.Exception.Message)")
    }
}

if (-not $outlook) {
    $classic    = @(Get-Process -Name outlook -ErrorAction SilentlyContinue).Count
    $newOutlook = @(Get-Process -Name olk     -ErrorAction SilentlyContinue).Count
    $registered = Test-Path 'Registry::HKEY_CLASSES_ROOT\Outlook.Application\CLSID'
    $elevated   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                      [Security.Principal.WindowsBuiltInRole]::Administrator)

    Write-Host ""
    Write-Host "Could not talk to Outlook." -ForegroundColor Red

    Write-Host ""
    Write-Host "What was tried:" -ForegroundColor DarkGray
    foreach ($attempt in $attempts) { Write-Host "    $attempt" }

    Write-Host ""
    Write-Host "What is true on this machine:" -ForegroundColor DarkGray
    Write-Host ("    classic Outlook running     {0}" -f $(if ($classic)    { "yes ($classic)" } else { 'no' }))
    Write-Host ("    new Outlook running         {0}" -f $(if ($newOutlook) { "yes ($newOutlook)" } else { 'no' }))
    Write-Host ("    Outlook.Application in COM  {0}" -f $(if ($registered) { 'registered' } else { 'NOT registered' }))
    Write-Host ("    this shell                  PowerShell {0} ({1}), {2}" -f `
        $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, $(if ($elevated) { 'elevated' } else { 'not elevated' }))

    Write-Host ""
    if ($newOutlook -and -not $classic) {
        Write-Host "The new Outlook cannot be automated: it has no COM interface, so no script can read it." -ForegroundColor Yellow
        Write-Host "Turn the 'New Outlook' toggle off, at the top right of its window, to go back to classic"
        Write-Host "Outlook, then run this again. If classic Outlook is not on this machine at all, export from"
        Write-Host "the provider instead, or point the collector at the mailbox - see docs/INGEST-SETUP.md."
    } elseif (-not $registered) {
        Write-Host "Nothing has registered Outlook.Application, so the classic desktop Outlook is not installed." -ForegroundColor Yellow
        Write-Host "This script needs it. Outlook on the web and the new Outlook cannot be read by any script."
    } elseif ($elevated -and $classic) {
        Write-Host "This shell is elevated and Outlook is not, and COM will not cross that line." -ForegroundColor Yellow
        Write-Host "Run this in an ordinary PowerShell window. It needs no administrator rights."
    } elseif ($classic) {
        Write-Host "Outlook is running but refused the connection." -ForegroundColor Yellow
        Write-Host "That usually means it is mid-something: a dialog waiting to be answered, a profile still"
        Write-Host "loading, or a repair running. Bring it to the front, clear whatever it wants, then re-run."
    } else {
        Write-Host "Outlook is not running. Open it, wait for it to finish loading, then run this again." -ForegroundColor Yellow
    }

    Write-Host ""
    exit 1
}

$namespace = $outlook.GetNamespace('MAPI')

# ---- find the folder ------------------------------------------------------

# Every place that walked into a folder's children asked for .Folders bare.
# On an ordinary mailbox that is fine. On the other stores Outlook keeps open
# beside it - public folders, an online archive, a SharePoint list - reading
# .Folders throws, and with ErrorActionPreference = Stop an unguarded throw
# ended the whole run. That is the same fault the attachment loop below was
# already fixed for, and it was worst in -List, which is the mode used to
# find out why nothing matched: it died before printing the mailbox that
# actually held the reports.
function Get-ChildFolders {
    param($Parent)

    try {
        $children = $Parent.Folders
        if ($null -eq $children) { return @() }
        return @($children)
    } catch {
        Write-Verbose "Could not list folders under '$($Parent.Name)': $($_.Exception.Message)"
        return @()
    }
}

function Find-Folder {
    param($Parent, [string]$Name)

    foreach ($child in (Get-ChildFolders $Parent)) {
        if ($child.Name -eq $Name) { return $child }
        $found = Find-Folder -Parent $child -Name $Name
        if ($found) { return $found }
    }
    return $null
}

function Get-Inbox {
    param($Store)

    # Asked of the store rather than matched by name, so this works on a
    # mailbox whose Outlook is not in English. GetDefaultFolder on the Store
    # is the only way to get the right Inbox for a SHARED mailbox - the one on
    # the namespace always returns the operator's own.
    try {
        $inbox = $Store.Store.GetDefaultFolder(6)      # olFolderInbox
        if ($inbox) { return $inbox }
    } catch {
        # Older Outlook, or a store that will not answer. Fall through.
    }

    foreach ($child in (Get-ChildFolders $Store)) {
        if ($child.Name -eq 'Inbox') { return $child }
    }

    return $null
}

# Every open store, not just the first. A shared mailbox such as
# DMARC@nrgtechservices.com is its own store sitting alongside the operator's
# own, and searching only the first would silently find nothing.
$stores = Get-ChildFolders $namespace
if ($stores.Count -eq 0) {
    Write-Host ""
    Write-Host "Outlook is running but no mailbox could be read from it." -ForegroundColor Red
    Write-Host "Wait for it to finish loading and try again. If it is asking a question, answer it first."
    exit 1
}

if ($Mailbox) {
    $matched = @($stores | Where-Object { $_.Name -like "*$Mailbox*" })
    if ($matched.Count -eq 0) {
        Write-Host ""
        Write-Host "No mailbox matching '$Mailbox' is open in Outlook." -ForegroundColor Red
        Write-Host "Mailboxes currently available:"
        foreach ($s in $stores) { Write-Host "    $($s.Name)" }
        exit 1
    }
    $stores = $matched
}

function Show-Tree {
    param($MailFolder, [int]$Depth = 0)

    $count = 0
    try { $count = $MailFolder.Items.Count } catch { $count = 0 }
    Write-Host ("    {0}{1}  {2}" -f ('  ' * $Depth), $MailFolder.Name, $(if ($count) { "($count)" } else { '' }))

    # Two levels is enough to see the shape without printing a whole mailbox.
    if ($Depth -lt 2) {
        foreach ($child in (Get-ChildFolders $MailFolder)) { Show-Tree -MailFolder $child -Depth ($Depth + 1) }
    }
}

# Printed from two places - on -List, and when a named folder is not found -
# and the two copies had already drifted from each other once.
function Show-Stores {
    foreach ($store in $stores) {
        Write-Host ""
        Write-Host $store.Name -ForegroundColor Cyan
        foreach ($child in (Get-ChildFolders $store)) { Show-Tree -MailFolder $child -Depth 1 }
    }
}

if ($List) {
    # With several mailboxes open and none named, print only their NAMES.
    #
    # Walking into every store was the old behaviour and it was too much in
    # both directions. Too much to read: thirteen stores, two levels deep, to
    # find one folder. And too much to hand out - the stores Outlook keeps open
    # beside a reporting mailbox are somebody's real mail. A real run printed a
    # university account's folder tree, a personal calendar and a set of vendor
    # and alert folders, none of which have anything to do with DMARC, and all
    # of which then get pasted into a ticket or a chat window along with the
    # bit that was wanted.
    #
    # The names alone are all that is needed to pick one, which is what -List
    # is for.
    if ($stores.Count -gt 1 -and -not $Mailbox) {
        Write-Host ""
        Write-Host "$($stores.Count) mailboxes are open in Outlook:" -ForegroundColor Cyan
        foreach ($s in $stores) { Write-Host "    $($s.Name)" }
        Write-Host ""
        Write-Host "Add -Mailbox <name> to look inside one. Matching is on any part of the name," -ForegroundColor DarkGray
        Write-Host "so -Mailbox DMARC is usually enough." -ForegroundColor DarkGray
        Write-Host ""
        exit 0
    }

    Show-Stores
    Write-Host ""
    exit 0
}

# What gets exported, as a list, because it can now be more than one thing.
$targets = @()
$foundIn = ''

if (-not $Folder) {
    # No folder named, so take the whole store. Its Folders collection
    # includes the Inbox, so nothing extra is needed here.
    #
    # But only when there is one store to take. With several open - the
    # operator's own beside the shared one is the ordinary case - this took
    # whichever came first and said which at the top of the output, which is
    # a line nobody reads until the export turns out to be their own Sent
    # Items. A -Mailbox that matches two stores has the same problem. Refused
    # rather than guessed, with the list, so the next run can say which.
    if ($stores.Count -gt 1) {
        Write-Host ""
        if ($Mailbox) {
            Write-Host "'$Mailbox' matches more than one open mailbox:" -ForegroundColor Red
        } else {
            Write-Host "More than one mailbox is open in Outlook, and no -Folder was given:" -ForegroundColor Red
        }
        foreach ($s in $stores) { Write-Host "    $($s.Name)" }
        Write-Host ""
        Write-Host "Say which with -Mailbox, using enough of the name to match only one." -ForegroundColor DarkGray
        exit 1
    }

    $targets += [pscustomobject]@{ MailFolder = $stores[0]; Into = $OutputPath }
    $foundIn = $stores[0].Name
} else {
    $named = $null
    foreach ($store in $stores) {
        $named = Find-Folder -Parent $store -Name $Folder
        if ($named) { $foundIn = $store.Name; $chosenStore = $store; break }
    }

    if ($named) {
        $targets += [pscustomobject]@{ MailFolder = $named; Into = $OutputPath }

        # The point of this change. A rule that files reports into per-domain
        # folders leaves the newest ones sitting in the Inbox, and exporting
        # only the named folder misses exactly those.
        if (-not $SkipInbox) {
            $inbox = Get-Inbox -Store $chosenStore
            if ($inbox) {
                $targets += [pscustomobject]@{
                    MailFolder = $inbox
                    Into       = (Join-Path $OutputPath 'Inbox')
                }
            } else {
                Write-Warning "No Inbox found in '$foundIn'. Only '$Folder' will be exported."
            }
        }
    }
}

if ($targets.Count -eq 0) {
    Write-Host ""
    Write-Host "No folder called '$Folder' in $(if ($Mailbox) { "'$Mailbox'" } else { 'any open mailbox' })." -ForegroundColor Red
    Write-Host ""
    Write-Host "Folders that DO exist:" -ForegroundColor DarkGray
    Show-Stores
    Write-Host ""
    Write-Host "Re-run with -Folder <name>, or leave -Folder out to export the whole mailbox." -ForegroundColor DarkGray
    exit 1
}

# ---- export ---------------------------------------------------------------

# ---- what has been exported before ----------------------------------------

# Content fingerprints, not names. Receivers reuse file names across days, so
# a name says nothing about whether this is the same report; and a report
# saved under google.xml last week and google(1).xml this week is still one
# report. The index outlives the files: deleting a report after importing it
# does not have the next run fetch it again.
if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }

$IndexPath = Join-Path $OutputPath '.dmarc-export-index.txt'
$known = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$indexedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

if (Test-Path -LiteralPath $IndexPath) {
    foreach ($line in (Get-Content -LiteralPath $IndexPath)) {
        $parts = $line -split "`t", 2
        if ($parts[0]) { [void]$known.Add($parts[0]) }
        if ($parts.Count -gt 1 -and $parts[1]) { [void]$indexedPaths.Add($parts[1]) }
    }
}

function Get-RelativePath([string]$Path) {
    $Path.Substring($OutputPath.TrimEnd('\', '/').Length).TrimStart('\', '/')
}

# Whatever is already in the folder counts as exported, whether an earlier
# run put it there before there was an index or somebody copied it in.
# Only files the index does not already name are read, so this costs
# nothing after the first run.
$adopted = 0
foreach ($file in (Get-ChildItem -LiteralPath $OutputPath -Recurse -File -ErrorAction SilentlyContinue)) {
    if ($file.Name.StartsWith('.')) { continue }
    if ($Extensions -notcontains $file.Extension.ToLowerInvariant()) { continue }
    $relative = Get-RelativePath $file.FullName
    if ($relative.StartsWith('.') -or $indexedPaths.Contains($relative)) { continue }

    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    if ($known.Add($hash)) { $adopted++ }
    [void]$indexedPaths.Add($relative)
    Add-Content -LiteralPath $IndexPath -Value "$hash`t$relative"
}

# Saved here first and moved into place only once it is known to be new,
# so a duplicate never appears in the folder even briefly.
$Staging = Join-Path $OutputPath '.incoming'
if (-not (Test-Path $Staging)) { New-Item -Path $Staging -ItemType Directory -Force | Out-Null }

$script:alreadyTotal = 0

# Folders already done, by EntryID. Without this, -Folder Inbox would export
# the Inbox twice: once as the folder asked for and once as the Inbox added
# to it.
$seen = New-Object 'System.Collections.Generic.HashSet[string]'

function Export-Folder {
    param($MailFolder, [string]$Destination)

    $id = ''
    try { $id = [string]$MailFolder.EntryID } catch { $id = '' }
    if ($id -and -not $seen.Add($id)) { return 0 }

    if (-not (Test-Path $Destination)) {
        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    }

    $saved = 0
    $already = 0
    $scanned = 0
    $skipped = 0
    $marked = 0

    $items = $null
    try { $items = $MailFolder.Items } catch { $items = $null }

    if ($items) {
        $count = 0
        try { $count = $items.Count } catch { $count = 0 }

        for ($i = 1; $i -le $count; $i++) {
            $item = $null
            try { $item = $items.Item($i) } catch { continue }
            if ($null -eq $item) { continue }
            $scanned++

            # Calendar items and contacts live in mail folders too, and asking
            # some item types for attachments throws rather than returning
            # nothing.
            $attachments = $null
            try { $attachments = $item.Attachments } catch { continue }
            if ($null -eq $attachments) { continue }

            $attachmentCount = 0
            try { $attachmentCount = $attachments.Count } catch { $attachmentCount = 0 }

            $savedHere = 0
            $alreadyHere = 0
            $failedHere = 0

            for ($a = 1; $a -le $attachmentCount; $a++) {
                # Every step here is inside the try, and that is the whole
                # point. Reading .FileName throws on some attachments - OLE
                # objects, certain inline images - and with
                # ErrorActionPreference = Stop an unguarded throw ended the
                # entire run. A mailbox of ninety reports would export the two
                # that came before the first awkward attachment and stop,
                # reporting success.
                try {
                    $attachment = $attachments.Item($a)
                    $name = $attachment.FileName
                    if ([string]::IsNullOrWhiteSpace($name)) { continue }

                    $extension = [System.IO.Path]::GetExtension($name)
                    if ($Extensions -notcontains $extension.ToLower()) { continue }

                    # Into staging first, to be fingerprinted before it is
                    # allowed into the folder.
                    $incoming = Join-Path $Staging ([guid]::NewGuid().ToString('N') + $extension)
                    $attachment.SaveAsFile($incoming)
                    $hash = (Get-FileHash -LiteralPath $incoming -Algorithm SHA256).Hash

                    if ($known.Contains($hash)) {
                        Remove-Item -LiteralPath $incoming -Force
                        $already++
                        $alreadyHere++
                        continue
                    }

                    # Receivers reuse file names across days, so a collision is
                    # the normal case rather than an oddity. Overwriting would
                    # shrink the export without saying so.
                    $safeName = ($name -replace '[<>:"/\\|?*]', '_')
                    $target = Join-Path $Destination $safeName
                    $n = 1
                    while (Test-Path $target) {
                        $base = [System.IO.Path]::GetFileNameWithoutExtension($safeName)
                        $target = Join-Path $Destination "$base($n)$extension"
                        $n++
                    }

                    Move-Item -LiteralPath $incoming -Destination $target
                    [void]$known.Add($hash)
                    Add-Content -LiteralPath $IndexPath -Value "$hash`t$(Get-RelativePath $target)"
                    $saved++
                    $savedHere++
                } catch {
                    # Counted and carried on. One unreadable attachment must
                    # not cost the rest of the mailbox.
                    $skipped++
                    $failedHere++
                    Write-Verbose "Skipped an attachment in '$($MailFolder.Name)': $($_.Exception.Message)"
                }
            }

            # Marked read only once its report is on disk, and never when an
            # attachment on it failed: a message left unread is one somebody
            # will still look at. Anything else in the mailbox - an
            # auto-reply, a message with no report on it - is left alone.
            #
            # A message whose report an earlier run already saved counts: it
            # is exported, and leaving it unread would have every run
            # re-read it and the unread count never go down.
            if (-not $LeaveUnread -and ($savedHere + $alreadyHere) -gt 0 -and $failedHere -eq 0) {
                try {
                    if ($item.UnRead) {
                        $item.UnRead = $false
                        $item.Save()
                        $marked++
                    }
                } catch {
                    # A read-only store, or a shared mailbox without write
                    # access. The export still counts; the flag is a nicety.
                    Write-Verbose "Could not mark a message read in '$($MailFolder.Name)': $($_.Exception.Message)"
                }
            }
        }
    }

    $unread = 0
    try { $unread = $MailFolder.UnReadItemCount } catch { $unread = 0 }

    # Every folder looked in is printed, including empty ones. A folder that
    # was searched and held nothing, and a folder that was never searched,
    # are different problems and used to look identical.
    Write-Host ("    {0,-34} {1,8} {2,6} {3,12} {4,8} {5,12}" -f `
        $MailFolder.Name, $scanned, $saved, $(if ($already) { $already } else { '' }),
        $(if ($skipped) { $skipped } else { '' }), $(if ($marked) { $marked } else { '' }))

    $script:alreadyTotal += $already

    if ($unread -gt 0) {
        Write-Host ("    {0,-34} {1}" -f '', "$unread still unread (read or not, all of them were scanned)") -ForegroundColor DarkGray
    }

    $total = $saved

    foreach ($child in (Get-ChildFolders $MailFolder)) {
        # Mirror the folder structure, so a report sorted into DMARC\acme.com
        # still says which domain it belongs to after export.
        $safe = ($child.Name -replace '[<>:"/\\|?*]', '_')
        $total += Export-Folder -MailFolder $child -Destination (Join-Path $Destination $safe)
    }

    return $total
}

Write-Host ""
Write-Host "Mailbox : $foundIn"
if ($Folder) {
    Write-Host "Folder  : $Folder$(if (-not $SkipInbox) { ' + Inbox' })"
} else {
    Write-Host "Folder  : (whole mailbox, Inbox included)"
}
Write-Host "Output  : $OutputPath"
Write-Host ""
Write-Host ("    {0,-34} {1,8} {2,6} {3,12} {4,8} {5,12}" -f 'folder', 'scanned', 'new', 'had already', 'skipped', 'marked read') -ForegroundColor DarkGray

$count = 0
foreach ($target in $targets) {
    $count += Export-Folder -MailFolder $target.MailFolder -Destination $target.Into
}

Remove-Item -LiteralPath $Staging -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "$count new report(s) written to $OutputPath" -ForegroundColor Green
if ($script:alreadyTotal -gt 0) {
    Write-Host "$($script:alreadyTotal) already exported by an earlier run, not saved again." -ForegroundColor DarkGray
}
if ($adopted -gt 0) {
    Write-Host "$adopted report(s) already in the folder were added to the index, so they will not be exported again." -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "Next: import them." -ForegroundColor DarkGray
Write-Host "  Drop the folder onto the Import page, or:" -ForegroundColor DarkGray
Write-Host "  dmarc import --from $OutputPath" -ForegroundColor DarkGray
Write-Host ""

if ($LogFile) { Stop-Transcript | Out-Null }
