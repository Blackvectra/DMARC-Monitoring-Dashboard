<#
.SYNOPSIS
    Saves every attachment from a mail folder (and its subfolders) to disk.

.DESCRIPTION
    A stopgap for getting reports out of a mailbox before the Graph ingest is
    set up. Talks to the Outlook already running on this machine, so it needs
    no app registration, no certificate and no admin involvement.

    Once "dmarc ingest" is configured this is unnecessary: that reads the
    mailbox directly, moves processed mail out of the way and resumes where it
    stopped. This exists for the half hour before that is true.

.PARAMETER Folder
    Folder to export, as it appears in Outlook. Subfolders are included, which
    is the point: reports sorted into a folder per domain are the normal shape.

.PARAMETER OutputPath
    Where to write. One subfolder per mail folder, so the domain a report came
    from survives the export and can still be used for attribution.

.EXAMPLE
    .\Export-DMARCAttachments.ps1 -Folder "DMARC" -OutputPath C:\dmarc-export
    Then: dmarc import --from C:\dmarc-export --db dmarc.db
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Folder,
    [Parameter(Mandatory)] [string]$OutputPath,

    # Report attachments are always one of these. Anything else is a signature
    # image or somebody's auto-reply, and writing those wastes time and disk.
    [string[]]$Extensions = @('.gz', '.zip', '.xml', '.json')
)

$ErrorActionPreference = 'Stop'

function Find-Folder {
    <#  Depth-first search by display name, so "DMARC" is found wherever it
        sits rather than only at the top of the mailbox.  #>
    param($Parent, [string]$Name)

    foreach ($child in $Parent.Folders) {
        if ($child.Name -eq $Name) { return $child }
        $found = Find-Folder -Parent $child -Name $Name
        if ($found) { return $found }
    }
    return $null
}

function Export-Folder {
    param($MailFolder, [string]$Destination)

    if (-not (Test-Path $Destination)) {
        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    }

    $saved = 0
    $items = $MailFolder.Items

    for ($i = 1; $i -le $items.Count; $i++) {
        $item = $items.Item($i)

        # Calendar invitations and contacts live in mail folders too and have
        # no Attachments property worth reading.
        if (-not ($item -is [System.__ComObject]) -or $null -eq $item.Attachments) { continue }

        for ($a = 1; $a -le $item.Attachments.Count; $a++) {
            $attachment = $item.Attachments.Item($a)
            $extension = [System.IO.Path]::GetExtension($attachment.FileName)
            if ($Extensions -notcontains $extension.ToLowerInvariant()) { continue }

            # Receivers reuse file names across days, so a collision is normal
            # rather than exceptional. Losing a report to one would silently
            # shrink the export.
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
                Write-Warning "Could not save $($attachment.FileName): $_"
            }
        }
    }

    Write-Host ("  {0,-34} {1,5} attachment(s)" -f $MailFolder.Name, $saved)
    $total = $saved

    foreach ($child in $MailFolder.Folders) {
        # One subfolder per mail folder, so a report sorted into DMARC\acme.com
        # still says so after export.
        $safe = ($child.Name -replace '[<>:"/\\|?*]', '_')
        $total += Export-Folder -MailFolder $child -Destination (Join-Path $Destination $safe)
    }

    return $total
}

try {
    $outlook = [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application')
} catch {
    try {
        $outlook = New-Object -ComObject Outlook.Application
    } catch {
        Write-Error "Could not talk to Outlook. Open Outlook on this machine and try again."
        exit 1
    }
}

$namespace = $outlook.GetNamespace('MAPI')
$root = $namespace.Folders.Item(1)

$source = Find-Folder -Parent $root -Name $Folder
if (-not $source) {
    Write-Error "No folder called '$Folder' in this mailbox. Check the name as it appears in Outlook."
    exit 1
}

Write-Host "Exporting '$Folder' to $OutputPath"
Write-Host ""
$count = Export-Folder -MailFolder $source -Destination $OutputPath

Write-Host ""
Write-Host "$count attachment(s) written."
Write-Host "Next: dmarc import --from `"$OutputPath`" --db dmarc.db"
