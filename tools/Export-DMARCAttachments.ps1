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

.PARAMETER List
    Show the folder tree and exit, without exporting anything. Use this when
    a name does not match and you want to see what is actually there.

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
$Extensions = @($Extensions | ForEach-Object {
    $e = $_.Trim().ToLowerInvariant()
    if ($e -and -not $e.StartsWith('.')) { ".$e" } else { $e }
} | Where-Object { $_ })

# ---- connect --------------------------------------------------------------

try {
    # Reuse the running Outlook if there is one, so this does not start a
    # second instance and trip the security prompt.
    $outlook = [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application')
} catch {
    try {
        $outlook = New-Object -ComObject Outlook.Application
    } catch {
        Write-Host ""
        Write-Host "Could not talk to Outlook." -ForegroundColor Red
        Write-Host "Open Outlook on this machine, wait for it to finish loading, then run this again."
        exit 1
    }
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
    $scanned = 0
    $skipped = 0

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

                    $attachment.SaveAsFile($target)
                    $saved++
                } catch {
                    # Counted and carried on. One unreadable attachment must
                    # not cost the rest of the mailbox.
                    $skipped++
                    Write-Verbose "Skipped an attachment in '$($MailFolder.Name)': $($_.Exception.Message)"
                }
            }
        }
    }

    $unread = 0
    try { $unread = $MailFolder.UnReadItemCount } catch { $unread = 0 }

    # Every folder looked in is printed, including empty ones. A folder that
    # was searched and held nothing, and a folder that was never searched,
    # are different problems and used to look identical.
    Write-Host ("    {0,-34} {1,8} {2,7} {3,8}" -f `
        $MailFolder.Name, $scanned, $saved, $(if ($skipped) { $skipped } else { '' }))

    if ($unread -gt 0) {
        Write-Host ("    {0,-34} {1}" -f '', "$unread unread (read or not, all of them were scanned)") -ForegroundColor DarkGray
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
Write-Host ("    {0,-34} {1,8} {2,7} {3,8}" -f 'folder', 'scanned', 'saved', 'skipped') -ForegroundColor DarkGray

$count = 0
foreach ($target in $targets) {
    $count += Export-Folder -MailFolder $target.MailFolder -Destination $target.Into
}

Write-Host ""
Write-Host "$count attachment(s) written to $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "Next: import them." -ForegroundColor DarkGray
Write-Host "  Drop the folder onto the Import page, or:" -ForegroundColor DarkGray
Write-Host "  dmarc import --from $OutputPath" -ForegroundColor DarkGray
Write-Host ""
