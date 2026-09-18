<#
    Export-DMARCAttachments.ps1, run end to end against a fake Outlook.

    This is the one script that stays when the rest of the PowerShell goes: a
    single file somebody copies onto a machine with Outlook open when there is
    no other way in. It had no tests at all. Everything here is driven through
    the script's front door with a stand-in for the Outlook object model, so
    what is asserted is what a person would see - files on disk, and what was
    printed - rather than the internals.

    The fake is deliberately shaped like the real thing where the script
    touches it, including the parts that THROW: reading .Folders on a public
    folder store, reading .FileName on an OLE attachment. Those throws are the
    reason the script has most of its try blocks, and the tests make sure a
    throw in one place costs one folder or one attachment, never the run.
#>

BeforeAll {
    # The one script kept out of legacy/, at the path docs/OPEN-ISSUES.md
    # already named for it. A stale earlier revision sat there beside the
    # live copy at the root; this is the live copy, moved.
    $script:Target = Join-Path (Split-Path $PSScriptRoot -Parent) 'tools' 'Export-DMARCAttachments.ps1'

    # ---- a fake Outlook ------------------------------------------------------

    function New-FakeAttachment {
        param([string]$FileName, [string]$Body = 'report', [switch]$ThrowsOnName)
        $a = [pscustomobject]@{ Body = $Body; SavedTo = $null }
        if ($ThrowsOnName) {
            $a | Add-Member ScriptProperty FileName { throw 'The attachment is not readable (OLE)' }
        } else {
            $a | Add-Member NoteProperty FileName $FileName
        }
        # Records where it was asked to save, so a test can check the path was
        # absolute - which is the bug this file exists to pin.
        $a | Add-Member ScriptMethod SaveAsFile {
            param([string]$Path)
            $this.SavedTo = $Path
            Set-Content -LiteralPath $Path -Value $this.Body -NoNewline
        }
        $a
    }

    # Outlook collections are 1-based and expose Count and Item(i).
    function New-FakeCollection {
        param([object[]]$List = @())
        $c = [pscustomobject]@{ Count = $List.Count; List = @($List) }
        $c | Add-Member ScriptMethod Item { param([int]$i) $this.List[$i - 1] }
        $c
    }

    function New-FakeItem {
        param([object[]]$Attachments = @())
        [pscustomobject]@{ Attachments = (New-FakeCollection $Attachments) }
    }

    function New-FakeFolder {
        param([string]$Name, [object[]]$Items = @(), [object[]]$Children = @(), [string]$EntryID)
        if (-not $EntryID) { $EntryID = [guid]::NewGuid().ToString() }
        [pscustomobject]@{
            Name            = $Name
            EntryID         = $EntryID
            Items           = (New-FakeCollection $Items)
            Folders         = @($Children)
            UnReadItemCount = 0
        }
    }

    # A store whose .Folders throws the way a real one does.
    #
    # A PowerShell ScriptProperty that throws is NOT that: the engine turns
    # the getter's exception into a non-terminating "Exception getting
    # 'Folders'" and hands back $null, so the script sailed past it and the
    # test proving the guard passed with the guard removed. A .NET getter
    # throwing a COMException is what Outlook actually does, and is what
    # ErrorActionPreference = Stop turns into the end of the run.
    if (-not ('ThrowingStore' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class ThrowingStore {
    public string Name { get; set; }
    public string EntryID { get; set; }
    public object Items { get; set; }
    public object Store { get; set; }
    public int UnReadItemCount { get; set; }
    public object Folders {
        get { throw new COMException("The operation failed. The store is not available.", unchecked((int)0x80004005)); }
    }
}
'@
    }

    # A store is a folder with a .Store that can answer GetDefaultFolder(6).
    function New-FakeStore {
        param([string]$Name, [object[]]$Children = @(), $Inbox, [switch]$FoldersThrow)

        $inner = [pscustomobject]@{ Inbox = $Inbox }
        $inner | Add-Member ScriptMethod GetDefaultFolder { param([int]$kind) if ($kind -eq 6) { $this.Inbox } }

        if ($FoldersThrow) {
            # A public folder store, an online archive: asking for .Folders
            # throws rather than returning nothing.
            $t = [ThrowingStore]::new()
            $t.Name = $Name
            $t.EntryID = [guid]::NewGuid().ToString()
            $t.Items = New-FakeCollection @()
            $t.Store = $inner
            return $t
        }

        $s = New-FakeFolder -Name $Name -Children $Children
        $s | Add-Member NoteProperty Store $inner
        $s
    }

    function New-FakeOutlook {
        param([object[]]$Stores)
        $ns = [pscustomobject]@{ Folders = @($Stores) }
        $app = [pscustomobject]@{ Namespace = $ns }
        $app | Add-Member ScriptMethod GetNamespace { param($kind) $this.Namespace }
        $app
    }

    # Runs the script the way a person does, capturing every stream so the
    # printed summary can be asserted on, and returning the exit code the
    # script chose. `exit` inside a script file invoked with & ends that
    # script only.
    function Invoke-Export {
        param([object[]]$Stores, [string[]]$Arguments)
        # Global on purpose: the shadow New-Object below is a global function,
        # and inside one $script: means the global scope, so a $script:
        # variable set here would be a different variable from the one it
        # reads. Every test failed on a null Outlook until this was global on
        # both sides.
        $global:FakeOutlook = New-FakeOutlook -Stores $Stores

        # Written as a flat list at the call sites for readability, bound by
        # name here. Splatting the list directly binds a trailing switch such
        # as -SkipInbox positionally and fails on it.
        $named = @{}
        for ($i = 0; $i -lt $Arguments.Count; $i++) {
            $arg = $Arguments[$i]
            if (-not $arg.StartsWith('-')) { throw "unexpected positional argument '$arg'" }
            $key = $arg.TrimStart('-')
            $next = if ($i + 1 -lt $Arguments.Count) { $Arguments[$i + 1] } else { $null }
            if ($null -eq $next -or $next.StartsWith('-')) {
                $named[$key] = $true
            } else {
                $named[$key] = $next
                $i++
            }
        }

        $global:LASTEXITCODE = 0
        $text = & $script:Target @named *>&1 | Out-String
        [pscustomobject]@{ Text = $text; ExitCode = $global:LASTEXITCODE }
    }
}

Describe 'Export-DMARCAttachments' {

    BeforeEach {
        # GetActiveObject throws here (no COM on Linux; no Outlook on a CI
        # runner), so the script falls through to New-Object, which is what
        # gets answered with the fake.
        #
        # A global function rather than a Pester Mock. Mocks live in the test's
        # session state, and a script file invoked with & does not see them:
        # every call reached the real cmdlet and reported that Outlook could
        # not be talked to. A function shadows the cmdlet in every child scope.
        # Every other New-Object - the HashSet the script builds for itself -
        # is passed through to the real one by module-qualified name.
        #
        # Forwarded losslessly, with every bound parameter, rather than by
        # picking out the ones this script is known to use. The first version
        # forwarded three named parameters and dropped the rest - and because
        # the AfterEach below was removing the wrong path, the shadow outlived
        # the test and every later file in the run went through it. Twelve
        # TLS-RPT parser tests that pass on their own failed in the combined
        # run. A shadow that forwards everything cannot break a caller even if
        # it does leak.
        function global:New-Object {
            [CmdletBinding()]
            param(
                [Parameter(Position = 0)][string]$TypeName,
                [string]$ComObject,
                [object[]]$ArgumentList,
                [System.Collections.IDictionary]$Property,
                [switch]$Strict
            )
            if ($ComObject -eq 'Outlook.Application') { return $global:FakeOutlook }
            Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
        }
        $script:Out = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    }

    AfterEach {
        # The Function: drive has no scope prefix in its paths. Removing
        # "Function:\global:New-Object" matches nothing, fails silently under
        # SilentlyContinue, and leaves the shadow in place for the rest of the
        # session - which is exactly what happened.
        Remove-Item Function:\New-Object -ErrorAction SilentlyContinue
    }

    # ---- the four things that were wrong ----------------------------------

    Context 'the path it saves to' {
        It 'hands Outlook an absolute path even when given a relative one' {
            # Outlook resolves a relative path against ITS working directory,
            # not this shell's. The directory was created here and the files
            # went wherever Outlook happened to be, or nowhere. Both examples
            # in the help use absolute paths, which is why it never showed.
            $att = New-FakeAttachment 'google.xml.gz'
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @($att))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Push-Location $TestDrive
            try { Invoke-Export -Stores @($store) -Arguments @('-OutputPath', 'rel-export') | Out-Null }
            finally { Pop-Location }

            [IO.Path]::IsPathRooted($att.SavedTo) | Should -BeTrue
            $att.SavedTo | Should -BeLike "*rel-export*google.xml.gz"
            # A whole-mailbox export mirrors the Inbox as a folder of its own,
            # so the file lands one level down. The first version of this
            # test looked for it at the top and blamed the script.
            Test-Path (Join-Path $TestDrive 'rel-export' 'Inbox' 'google.xml.gz') | Should -BeTrue
        }
    }

    Context 'the extension filter' {
        It 'matches an extension given without the dot or in upper case' {
            # The file's extension was lowercased before comparing; the list
            # it was compared against was not. "-Extensions .XML" matched
            # nothing and said nothing.
            $keep = New-FakeAttachment 'report.xml'
            $drop = New-FakeAttachment 'report.json'
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @($keep, $drop))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-Extensions', 'XML') | Out-Null

            Test-Path (Join-Path $script:Out 'Inbox' 'report.xml')  | Should -BeTrue
            Test-Path (Join-Path $script:Out 'Inbox' 'report.json') | Should -BeFalse
        }
    }

    Context 'a store that will not list its folders' {
        It 'still lists the others with -List instead of dying on the first' {
            # -List is the mode used to find out why nothing matched. It died
            # on a public-folder store before printing the mailbox that held
            # the reports.
            $good = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'DMARC')
            $bad  = New-FakeStore 'Public Folders - someone' -FoldersThrow

            $r = Invoke-Export -Stores @($bad, $good) -Arguments @('-OutputPath', $script:Out, '-List')

            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'DMARC Reports'
            $r.Text | Should -Match 'DMARC'
        }

        It 'still finds a named folder in the store beside it' {
            $att = New-FakeAttachment 'a.xml'
            $dmarc = New-FakeFolder 'DMARC' -Items @(New-FakeItem @($att))
            $inbox = New-FakeFolder 'Inbox'
            $good = New-FakeStore 'DMARC Reports' -Children @($dmarc, $inbox) -Inbox $inbox
            $bad  = New-FakeStore 'Online Archive' -FoldersThrow

            $r = Invoke-Export -Stores @($bad, $good) -Arguments @('-OutputPath', $script:Out, '-Folder', 'DMARC')

            $r.ExitCode | Should -Be 0
            Test-Path (Join-Path $script:Out 'a.xml') | Should -BeTrue
        }
    }

    Context 'more than one mailbox' {
        It 'refuses to guess which whole mailbox to export, and lists them' {
            # It used to take whichever came first and mention which at the
            # top of the output - a line nobody reads until the export turns
            # out to be their own Sent Items.
            $a = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'Inbox' -Items @(New-FakeItem @(New-FakeAttachment 'a.xml')))
            $b = New-FakeStore 'DMARC Archive' -Children @(New-FakeFolder 'Inbox')

            $r = Invoke-Export -Stores @($a, $b) -Arguments @('-OutputPath', $script:Out, '-Mailbox', 'DMARC')

            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'DMARC Reports'
            $r.Text | Should -Match 'DMARC Archive'
            Test-Path $script:Out | Should -BeFalse
        }

        It 'refuses with no -Mailbox at all when several are open' {
            $mine = New-FakeStore 'me@example.com' -Children @(New-FakeFolder 'Inbox')
            $shared = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'Inbox')

            $r = Invoke-Export -Stores @($mine, $shared) -Arguments @('-OutputPath', $script:Out)

            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match 'More than one mailbox'
        }

        It 'proceeds when the match is exactly one' {
            $att = New-FakeAttachment 'a.xml'
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @($att))
            $mine = New-FakeStore 'me@example.com' -Children @(New-FakeFolder 'Inbox')
            $shared = New-FakeStore 'DMARC Reports' -Children @($inbox) -Inbox $inbox

            $r = Invoke-Export -Stores @($mine, $shared) -Arguments @('-OutputPath', $script:Out, '-Mailbox', 'Reports')

            $r.ExitCode | Should -Be 0
            # Whole-mailbox export, so the Inbox is mirrored as a folder.
            Test-Path (Join-Path $script:Out 'Inbox' 'a.xml') | Should -BeTrue
        }
    }

    # ---- what it was always meant to do, pinned -----------------------------

    Context 'the Inbox' {
        It 'is exported alongside a named folder, because unfiled reports are the newest ones' {
            $filed   = New-FakeAttachment 'filed.xml'
            $unfiled = New-FakeAttachment 'unfiled.xml'
            $dmarc = New-FakeFolder 'DMARC' -Items @(New-FakeItem @($filed))
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @($unfiled))
            $store = New-FakeStore 'DMARC Reports' -Children @($dmarc, $inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-Folder', 'DMARC') | Out-Null

            Test-Path (Join-Path $script:Out 'filed.xml')         | Should -BeTrue
            Test-Path (Join-Path $script:Out 'Inbox' 'unfiled.xml') | Should -BeTrue
        }

        It 'is left out with -SkipInbox' {
            $dmarc = New-FakeFolder 'DMARC' -Items @(New-FakeItem @(New-FakeAttachment 'filed.xml'))
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @(New-FakeAttachment 'unfiled.xml'))
            $store = New-FakeStore 'DMARC Reports' -Children @($dmarc, $inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-Folder', 'DMARC', '-SkipInbox') | Out-Null

            Test-Path (Join-Path $script:Out 'Inbox') | Should -BeFalse
        }

        It 'is not exported twice when it is the folder asked for' {
            $att = New-FakeAttachment 'a.xml'
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @($att))
            $store = New-FakeStore 'DMARC Reports' -Children @($inbox) -Inbox $inbox

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-Folder', 'Inbox')

            $r.Text | Should -Match '1 attachment\(s\) written'
            Test-Path (Join-Path $script:Out 'a(1).xml') | Should -BeFalse
        }
    }

    Context 'file names' {
        It 'never overwrites: the same name twice becomes name and name(1)' {
            # Receivers reuse file names across days, so a collision is the
            # normal case. Overwriting would shrink the export without saying.
            $a = New-FakeAttachment 'google.xml' -Body 'first'
            $b = New-FakeAttachment 'google.xml' -Body 'second'
            $inbox = New-FakeFolder 'Inbox' -Items @((New-FakeItem @($a)), (New-FakeItem @($b)))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            Get-Content (Join-Path $script:Out 'Inbox' 'google.xml')    | Should -Be 'first'
            Get-Content (Join-Path $script:Out 'Inbox' 'google(1).xml') | Should -Be 'second'
        }

        It 'mirrors a per-domain subfolder so the export still says which domain' {
            $att = New-FakeAttachment 'r.xml'
            $acme = New-FakeFolder 'acme.com' -Items @(New-FakeItem @($att))
            $dmarc = New-FakeFolder 'DMARC' -Children @($acme)
            $inbox = New-FakeFolder 'Inbox'
            $store = New-FakeStore 'DMARC Reports' -Children @($dmarc, $inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-Folder', 'DMARC') | Out-Null

            Test-Path (Join-Path $script:Out 'acme.com' 'r.xml') | Should -BeTrue
        }

        It 'skips anything that is not a report' {
            # A report rides along in the same message, so the png being
            # absent proves the filter and not merely that nothing ran. The
            # first version of this asserted absence at a path nothing would
            # ever have been written to, and passed on nothing.
            $img = New-FakeAttachment 'signature.png'
            $rpt = New-FakeAttachment 'google.xml'
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @($img, $rpt))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            Test-Path (Join-Path $script:Out 'Inbox' 'google.xml')     | Should -BeTrue
            Test-Path (Join-Path $script:Out 'Inbox' 'signature.png') | Should -BeFalse
        }
    }

    Context 'an attachment that cannot be read' {
        It 'costs one attachment, not the run' {
            # Reading .FileName throws on OLE objects and some inline images.
            # A mailbox of ninety reports used to export the two that came
            # before the first awkward one and stop, reporting success.
            $ole = New-FakeAttachment -ThrowsOnName
            $ok  = New-FakeAttachment 'after.xml'
            $inbox = New-FakeFolder 'Inbox' -Items @((New-FakeItem @($ole)), (New-FakeItem @($ok)))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out)

            $r.ExitCode | Should -Be 0
            Test-Path (Join-Path $script:Out 'Inbox' 'after.xml') | Should -BeTrue
        }
    }

    Context 'when nothing matches' {
        It 'names the folder it could not find and shows what exists' {
            $store = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'Inbox'), (New-FakeFolder 'Reports')

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-Folder', 'Nope')

            $r.ExitCode | Should -Be 1
            $r.Text | Should -Match "No folder called 'Nope'"
            $r.Text | Should -Match 'Reports'
        }
    }
}
