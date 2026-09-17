<#
.SYNOPSIS
    Saves every DMARC report attachment from a mailbox folder to disk.

.DESCRIPTION
    One file, nothing to install. Copy it onto a machine with Outlook open and
    run it. No repository, no .NET, no app registration, no admin involvement.
    Windows PowerShell as it ships is enough.

    Subfolders are included and mirrored into the output, so reports sorted
    into DMARC\acme.com land in <output>\acme.com and still say which domain
    they belong to.

.PARAMETER Folder
    The folder to export, as its name appears in Outlook. Leave it out to
    export the whole mailbox, which is usually what you want for a mailbox
    that exists only to receive reports. Doing that requires -Mailbox, so a
    missing argument cannot end up dumping the operator's own mail.

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
    Quote a mailbox name containing a space, or PowerShell reads the second
    word as the next parameter.

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -OutputPath C:\x -Mailbox "DMARC Reports" -List
    Show what folders exist, without exporting.

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -Folder DMARC -OutputPath C:\dmarc-export
#>

[CmdletBinding()]
param(
    # Empty means the whole mailbox. That is the right default for a mailbox
    # that exists only to receive reports: there is nothing else in it.
    [string]$Folder = '',
    [Parameter(Mandatory)] [string]$OutputPath,
    [string]$Mailbox,
    [switch]$List,

    # A mailbox also holds signature images and auto-replies. Reports are
    # always one of these, so everything else is skipped rather than written.
    [string[]]$Extensions = @('.gz', '.zip', '.xml', '.json')
)

$ErrorActionPreference = 'Stop'

# Printed on every run. A copy sitting in Downloads looks identical to the
# current one until it fails on a parameter it does not have, so the run says
# which copy it is before it does anything else.
$scriptVersion = '2026-09-17.3'
Write-Host ""
Write-Host "Export-DMARCAttachments $scriptVersion" -ForegroundColor DarkGray

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

function Find-Folder {
    param($Parent, [string]$Name)

    foreach ($child in $Parent.Folders) {
        if ($child.Name -eq $Name) { return $child }
        $found = Find-Folder -Parent $child -Name $Name
        if ($found) { return $found }
    }
    return $null
}

# Every open store, not just the first. A shared mailbox such as
# DMARC@nrgtechservices.com is its own store sitting alongside the operator's
# own, and searching only the first would silently find nothing.
$stores = @($namespace.Folders)

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
        foreach ($child in $MailFolder.Folders) { Show-Tree -MailFolder $child -Depth ($Depth + 1) }
    }
}

if ($List) {
    foreach ($store in $stores) {
        Write-Host ""
        Write-Host $store.Name -ForegroundColor Cyan
        foreach ($child in $store.Folders) { Show-Tree -MailFolder $child -Depth 1 }
    }
    Write-Host ""
    exit 0
}

$source = $null
$foundIn = ''

if (-not $Folder) {
    # No folder named, so take the whole mailbox. That is right for a mailbox
    # whose only purpose is receiving reports, and wrong for a person's own
    # mailbox, so it is only allowed once the mailbox has been named: without
    # -Mailbox this would walk whichever store Outlook happens to list first,
    # which is the operator's own, and write their attachments to disk.
    if (-not $Mailbox) {
        Write-Host ""
        Write-Host "Refusing to export a whole mailbox without being told which one." -ForegroundColor Red
        Write-Host "Whichever mailbox Outlook lists first is usually your own, and this would"
        Write-Host "write every attachment in it to disk."
        Write-Host ""
        Write-Host "Mailboxes currently available:"
        foreach ($s in $stores) { Write-Host "    $($s.Name)" }
        Write-Host ""
        Write-Host 'Re-run with -Mailbox "<name>" (quote it if it contains a space), or name a -Folder.' -ForegroundColor DarkGray
        exit 1
    }

    if ($stores.Count -gt 1) {
        Write-Host ""
        Write-Host "'$Mailbox' matches more than one mailbox:" -ForegroundColor Red
        foreach ($s in $stores) { Write-Host "    $($s.Name)" }
        Write-Host ""
        Write-Host "Use a longer name that picks out just one." -ForegroundColor DarkGray
        exit 1
    }

    $source = $stores[0]
    $foundIn = $stores[0].Name
} else {
    foreach ($store in $stores) {
        $source = Find-Folder -Parent $store -Name $Folder
        if ($source) { $foundIn = $store.Name; break }
    }
}

if (-not $source) {
    Write-Host ""
    Write-Host "No folder called '$Folder' in $(if ($Mailbox) { "'$Mailbox'" } else { 'any open mailbox' })." -ForegroundColor Red
    Write-Host ""
    Write-Host "Folders that DO exist:" -ForegroundColor DarkGray
    foreach ($store in $stores) {
        Write-Host ""
        Write-Host $store.Name -ForegroundColor Cyan
        foreach ($child in $store.Folders) { Show-Tree -MailFolder $child -Depth 1 }
    }
    Write-Host ""
    Write-Host "Re-run with -Folder <name>, or leave -Folder out to export the whole mailbox." -ForegroundColor DarkGray
    exit 1
}

# ---- export ---------------------------------------------------------------

function Export-Folder {
    param($MailFolder, [string]$Destination)

    if (-not (Test-Path $Destination)) {
        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    }

    $saved = 0
    $items = $MailFolder.Items

    for ($i = 1; $i -le $items.Count; $i++) {
        try { $item = $items.Item($i) } catch { continue }

        # Calendar items and contacts live in mail folders too and have no
        # attachments worth reading.
        if ($null -eq $item -or $null -eq $item.Attachments) { continue }

        for ($a = 1; $a -le $item.Attachments.Count; $a++) {
            $attachment = $item.Attachments.Item($a)
            $extension = [System.IO.Path]::GetExtension($attachment.FileName)
            if ($Extensions -notcontains $extension.ToLower()) { continue }

            # Receivers reuse file names across days, so a collision is the
            # normal case rather than an oddity. Overwriting would shrink the
            # export without saying so.
            $target = Join-Path $Destination $attachment.FileName
            $n = 1
            while (Test-Path $target) {
                $base = [System.IO.Path]::GetFileNameWithoutExtension($attachment.FileName)
                $target = Join-Path $Destination "$base($n)$extension"
                $n++
            }

            try {
                $attachment.SaveAsFile($target)
                $saved++
            } catch {
                Write-Warning "Could not save $($attachment.FileName): $($_.Exception.Message)"
            }
        }
    }

    if ($saved -gt 0 -or $MailFolder.Folders.Count -eq 0) {
        Write-Host ("    {0,-36} {1,6}" -f $MailFolder.Name, $saved)
    }
    $total = $saved

    foreach ($child in $MailFolder.Folders) {
        # Mirror the folder structure, so a report sorted into DMARC\acme.com
        # still says which domain it belongs to after export.
        $safe = ($child.Name -replace '[<>:"/\\|?*]', '_')
        $total += Export-Folder -MailFolder $child -Destination (Join-Path $Destination $safe)
    }

    return $total
}

Write-Host ""
Write-Host "Mailbox : $foundIn"
Write-Host "Folder  : $(if ($Folder) { $Folder } else { '(whole mailbox)' })"
Write-Host "Output  : $OutputPath"
Write-Host ""
Write-Host ("    {0,-36} {1,6}" -f 'folder', 'saved') -ForegroundColor DarkGray

$count = Export-Folder -MailFolder $source -Destination $OutputPath

Write-Host ""
Write-Host "$count attachment(s) written to $OutputPath" -ForegroundColor Green
Write-Host ""
