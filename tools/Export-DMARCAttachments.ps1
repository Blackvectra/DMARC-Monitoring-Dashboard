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
    The folder to export, as its name appears in Outlook. Default: DMARC

.PARAMETER OutputPath
    Where to write. Created if it does not exist.

.PARAMETER Mailbox
    Which mailbox to look in, when more than one is open. A shared mailbox is
    a SEPARATE store in Outlook, so without this the script searches whichever
    happens to be first, which is usually the operator's own. Matching is on
    any part of the name, so "DMARC" or the full address both work.

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -OutputPath C:\dmarc-export -Mailbox DMARC@nrgtechservices.com

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -Folder DMARC -OutputPath C:\dmarc-export
#>

[CmdletBinding()]
param(
    [string]$Folder = 'DMARC',
    [Parameter(Mandatory)] [string]$OutputPath,
    [string]$Mailbox,

    # A mailbox also holds signature images and auto-replies. Reports are
    # always one of these, so everything else is skipped rather than written.
    [string[]]$Extensions = @('.gz', '.zip', '.xml', '.json')
)

$ErrorActionPreference = 'Stop'

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

$source = $null
$foundIn = ''
foreach ($store in $stores) {
    $source = Find-Folder -Parent $store -Name $Folder
    if ($source) { $foundIn = $store.Name; break }
}

if (-not $source) {
    Write-Host ""
    Write-Host "No folder called '$Folder' in $(if ($Mailbox) { "'$Mailbox'" } else { 'any open mailbox' })." -ForegroundColor Red
    Write-Host "Check the name as it appears in Outlook. Mailboxes searched:"
    foreach ($s in $stores) { Write-Host "    $($s.Name)" }
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
Write-Host "Folder  : $Folder"
Write-Host "Output  : $OutputPath"
Write-Host ""
Write-Host ("    {0,-36} {1,6}" -f 'folder', 'saved') -ForegroundColor DarkGray

$count = Export-Folder -MailFolder $source -Destination $OutputPath

Write-Host ""
Write-Host "$count attachment(s) written to $OutputPath" -ForegroundColor Green
Write-Host ""
