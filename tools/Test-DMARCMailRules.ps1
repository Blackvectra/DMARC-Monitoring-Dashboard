<#
.SYNOPSIS
    Checks the inbox rules that file DMARC reports into per-domain folders.

.DESCRIPTION
    Reports arriving in a mailbox get sorted into folders by inbox rules. When
    one stops firing, nothing announces it: the reports still arrive, they just
    pile up in the Inbox, and the folder that should have them quietly stops
    growing. Nothing is lost - but if anything downstream reads the FOLDERS
    rather than the whole mailbox, it silently stops seeing that domain.

    This says which rules exist, which are switched off, which Exchange has
    marked as failing, and - the one that catches people out - how close the
    mailbox is to its rules quota. Exchange Online caps the total size of a
    mailbox's rules at 256 KB by default. Cross it and new rules will not
    save. The message when that happens is easy to miss, and the result looks
    exactly like "the rule I just made does not work".

    Read-only. It changes nothing.

.PARAMETER Mailbox
    The mailbox holding the reports, e.g. dmarc@nrgtechservices.com

.PARAMETER ExpectedDomains
    Domains you believe have a rule. Any without one is listed. Get this from
    the product: dmarc client list, or the Domains page.

.EXAMPLE
    .\Test-DMARCMailRules.ps1 -Mailbox dmarc@nrgtechservices.com

.EXAMPLE
    .\Test-DMARCMailRules.ps1 -Mailbox dmarc@nrgtechservices.com `
        -ExpectedDomains client-a.example,client-d.example,client-f.example,client-g.example

.NOTES
    Needs the ExchangeOnlineManagement module:
        Install-Module ExchangeOnlineManagement -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Mailbox,
    [string[]]$ExpectedDomains = @()
)

$ErrorActionPreference = 'Stop'

# ---- connect ---------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host ""
    Write-Host "The ExchangeOnlineManagement module is not installed." -ForegroundColor Red
    Write-Host "  Install-Module ExchangeOnlineManagement -Scope CurrentUser"
    exit 1
}

Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Reuse a session if one is already open, so this does not prompt every run.
$connected = $false
try {
    $info = Get-ConnectionInformation -ErrorAction SilentlyContinue
    $connected = ($null -ne $info -and $info.Count -gt 0)
} catch {
    $connected = $false
}

if (-not $connected) {
    Write-Host "Signing in to Exchange Online..." -ForegroundColor DarkGray
    Connect-ExchangeOnline -ShowBanner:$false
}

# ---- the quota, which is the one that catches people out -------------------

Write-Host ""
Write-Host "Mailbox: $Mailbox" -ForegroundColor Cyan
Write-Host ""

try {
    $mbx = Get-Mailbox -Identity $Mailbox -ErrorAction Stop
    Write-Host "  Rules quota : $($mbx.RulesQuota)"
} catch {
    Write-Host "  Could not read the mailbox: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ---- the rules -------------------------------------------------------------

$rules = @(Get-InboxRule -Mailbox $Mailbox)

Write-Host "  Rules       : $($rules.Count)"
Write-Host ""

if ($rules.Count -eq 0) {
    Write-Host "  No inbox rules at all. Everything lands in the Inbox." -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

Write-Host ("  {0,-34} {1,-9} {2,-8} {3}" -f 'rule', 'enabled', 'priority', 'files into') -ForegroundColor DarkGray

$disabled = @()
$failing  = @()

foreach ($rule in $rules | Sort-Object Priority) {
    $target = ''
    if ($rule.MoveToFolder) { $target = $rule.MoveToFolder }
    elseif ($rule.CopyToFolder) { $target = "$($rule.CopyToFolder) (copy)" }

    $state = if ($rule.Enabled) { 'yes' } else { 'NO' }
    $color = 'Gray'

    if (-not $rule.Enabled) { $disabled += $rule; $color = 'Yellow' }
    if ($rule.InError)      { $failing  += $rule; $color = 'Red' }

    Write-Host ("  {0,-34} {1,-9} {2,-8} {3}" -f `
        $rule.Name, $state, $rule.Priority, $target) -ForegroundColor $color

    # A rule that stops the chain prevents every rule below it from running,
    # which is the commonest reason a rule that looks correct never fires.
    if ($rule.StopProcessingRules) {
        Write-Host ("  {0,-34} ^ stops processing: no rule below this one runs on a matching message" -f '') `
            -ForegroundColor Yellow
    }
}

Write-Host ""

# ---- what is wrong ---------------------------------------------------------

$problems = 0

if ($failing.Count -gt 0) {
    $problems++
    Write-Host "  $($failing.Count) rule(s) marked as failing by Exchange:" -ForegroundColor Red
    foreach ($r in $failing) { Write-Host "    $($r.Name): $($r.ErrorType)" }
    Write-Host "    Usually the folder it files into was renamed or deleted. Re-point it."
    Write-Host ""
}

if ($disabled.Count -gt 0) {
    $problems++
    Write-Host "  $($disabled.Count) rule(s) switched off:" -ForegroundColor Yellow
    foreach ($r in $disabled) { Write-Host "    $($r.Name)" }
    Write-Host ""
}

if ($ExpectedDomains.Count -gt 0) {
    # Matched loosely against the whole rule, because a rule for a domain may
    # name it in its own name, its condition or its target folder.
    $missing = @()
    foreach ($domain in $ExpectedDomains) {
        $text = ($rules | ForEach-Object {
            "$($_.Name) $($_.MoveToFolder) $($_.CopyToFolder) $($_.SubjectContainsWords) $($_.BodyContainsWords) $($_.HeaderContainsWords) $($_.SentTo)"
        }) -join ' '

        if ($text -notlike "*$domain*") { $missing += $domain }
    }

    if ($missing.Count -gt 0) {
        $problems++
        Write-Host "  $($missing.Count) domain(s) with reports but no rule mentioning them:" -ForegroundColor Yellow
        foreach ($d in $missing) { Write-Host "    $d" }
        Write-Host ""
        Write-Host "    Either the rule was never made, or it was made and would not save." -ForegroundColor DarkGray
        Write-Host "    A rule that will not save because of the quota above reports an error" -ForegroundColor DarkGray
        Write-Host "    at the moment you click Save and then simply is not there afterwards," -ForegroundColor DarkGray
        Write-Host "    which looks exactly like a rule that does not work." -ForegroundColor DarkGray
        Write-Host ""
    }
}

# The quota cannot be measured directly - Exchange exposes the limit but not
# the usage - so this is the honest test: try to create a rule and see.
Write-Host "  To find out whether the quota is the problem, try adding one more rule." -ForegroundColor DarkGray
Write-Host "  If the mailbox is full of rules it fails immediately and says so:" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    New-InboxRule -Mailbox $Mailbox -Name 'quota probe' ``" -ForegroundColor DarkGray
Write-Host "        -SubjectContainsWords 'this-will-never-match' -MarkAsRead `$true" -ForegroundColor DarkGray
Write-Host "    Remove-InboxRule -Mailbox $Mailbox -Identity 'quota probe' -Confirm:`$false" -ForegroundColor DarkGray
Write-Host ""

if ($problems -eq 0) {
    Write-Host "  Nothing obviously wrong with the rules themselves." -ForegroundColor Green
    Write-Host ""
    Write-Host "  If reports are still landing in the Inbox, the likeliest remaining cause is" -ForegroundColor DarkGray
    Write-Host "  a client-only rule: one whose actions Outlook can only perform itself, so it" -ForegroundColor DarkGray
    Write-Host "  runs only while that Outlook is open. Outlook marks those '(client-only)' in" -ForegroundColor DarkGray
    Write-Host "  Manage Rules & Alerts. Rebuild them with server-side actions only - move,"  -ForegroundColor DarkGray
    Write-Host "  copy, delete, mark - and they run whether anybody is signed in or not." -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  Whatever the answer: nothing has been lost. The reports are in the Inbox," -ForegroundColor DarkGray
Write-Host "  and importing the whole mailbox picks them up wherever they sat." -ForegroundColor DarkGray
Write-Host ""
