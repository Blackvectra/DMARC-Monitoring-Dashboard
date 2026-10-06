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
        param([string]$FileName, [string]$Body, [switch]$ThrowsOnName, [switch]$ThrowsOnSave)
        # Distinct unless a test says otherwise: the exporter recognizes a
        # report it has saved before by its contents, and a dozen fakes all
        # reading "report" are, to it, one report.
        if (-not $Body) { $Body = "report $([guid]::NewGuid())" }
        $a = [pscustomobject]@{ Body = $Body; SavedTo = $null }
        if ($ThrowsOnName) {
            $a | Add-Member ScriptProperty FileName { throw 'The attachment is not readable (OLE)' }
        } else {
            $a | Add-Member NoteProperty FileName $FileName
        }
        # Records where it was asked to save, so a test can check the path was
        # absolute - which is the bug this file exists to pin.
        $a | Add-Member NoteProperty ThrowsOnSave ([bool]$ThrowsOnSave)
        $a | Add-Member ScriptMethod SaveAsFile {
            param([string]$Path)
            # A method that throws does propagate, unlike a property getter,
            # so this is a real failure the way a full disk or a blocked file
            # type is.
            if ($this.ThrowsOnSave) { throw 'Cannot save the attachment.' }
            $this.SavedTo = $Path
            Set-Content -LiteralPath $Path -Value $this.Body -NoNewline
        }
        $a
    }

    # Outlook collections are 1-based and expose Count and Item(i).
    #
    # Count is read live, not fixed when the collection is made: moving a
    # message out of a folder shrinks the folder's Items, and a script that
    # walks 1..Count while it moves things skips every other message. A fake
    # whose Count never changed could not show that.
    function New-FakeCollection {
        param([object[]]$List = @())
        $c = [pscustomobject]@{ List = [System.Collections.Generic.List[object]]::new() }
        foreach ($x in $List) { $c.List.Add($x) }
        $c | Add-Member ScriptProperty Count { $this.List.Count }
        $c | Add-Member ScriptMethod Item { param([int]$i) $this.List[$i - 1] }
        $c
    }

    function New-FakeItem {
        param(
            [object[]]$Attachments = @(),
            [bool]$UnRead = $true,
            [switch]$SaveThrows,
            [switch]$MoveThrows
        )
        # UnRead and Save() as Outlook has them: the flag changes nothing
        # until the item is saved, so Saved counts the writes. Save() throws
        # the way it does on a mailbox the signed-in user may only read.
        #
        # Move() takes the item out of the folder it is in and puts it in the
        # destination, as Outlook does, and hands back the moved item. Parent
        # is set when the item is put in a folder; MovedTo is where it went.
        $item = [pscustomobject]@{
            Attachments = (New-FakeCollection $Attachments)
            UnRead      = $UnRead
            Saved       = 0
            Parent      = $null
            MovedTo     = $null
            SaveThrows  = [bool]$SaveThrows
            MoveThrows  = [bool]$MoveThrows
        }
        $item | Add-Member ScriptMethod Save {
            if ($this.SaveThrows) { throw 'You do not have sufficient permission to perform this operation on this object.' }
            $this.Saved++
        }
        $item | Add-Member ScriptMethod Move {
            param($Destination)
            if ($this.MoveThrows) { throw 'The operation failed.' }
            if ($this.Parent) { [void]$this.Parent.Items.List.Remove($this) }
            $Destination.Items.List.Add($this)
            $this.Parent = $Destination
            $this.MovedTo = $Destination
            $this
        }
        $item
    }

    function New-FakeFolder {
        # -Virtual lists items that live in some other folder, as a search
        # folder does: their Parent stays the folder they are really in.
        param([string]$Name, [object[]]$Items = @(), [object[]]$Children = @(), [string]$EntryID, [switch]$Virtual)
        if (-not $EntryID) { $EntryID = [guid]::NewGuid().ToString() }
        $folder = [pscustomobject]@{
            Name            = $Name
            EntryID         = $EntryID
            Items           = (New-FakeCollection $Items)
            Folders         = @($Children)
            UnReadItemCount = 0
        }
        if (-not $Virtual) {
            foreach ($item in $Items) { if ($item.PSObject.Properties['Parent']) { $item.Parent = $folder } }
        }
        $folder
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

    # Every folder under a store answers .Store, as in Outlook. That is how the
    # script finds the Deleted Items of the mailbox a message is IN, rather
    # than the one belonging to whoever is signed in.
    function Set-FakeStoreOn {
        param($Folder, $Store)
        if ($null -eq $Folder) { return }
        # A test that writes its children as "@(a), (b)" hands over an array
        # inside the array. Outlook never does; the walk copes so the test can.
        if ($Folder -is [array]) {
            foreach ($f in $Folder) { Set-FakeStoreOn -Folder $f -Store $Store }
            return
        }
        if (-not $Folder.PSObject.Properties['Store']) { $Folder | Add-Member NoteProperty Store $Store }
        foreach ($child in @($Folder.Folders)) { Set-FakeStoreOn -Folder $child -Store $Store }
    }

    # A store is a folder with a .Store that answers GetDefaultFolder for the
    # kinds the script asks about: 6 Inbox, 3 Deleted Items, 5 Sent Items,
    # 16 Drafts, 23 Junk Email. A kind it has no folder for answers nothing,
    # and -DeletedThrows makes the Deleted Items question throw, as it does on
    # a store that will not answer.
    function New-FakeStore {
        param(
            [string]$Name, [object[]]$Children = @(), $Inbox,
            $Deleted, $Sent, $Drafts, $Junk,
            [hashtable]$Other = @{},
            [switch]$FoldersThrow, [switch]$DeletedThrows
        )

        $inner = [pscustomobject]@{
            StoreID = [guid]::NewGuid().ToString()
            Inbox = $Inbox; Deleted = $Deleted; Sent = $Sent; Drafts = $Drafts; Junk = $Junk
            DeletedThrows = [bool]$DeletedThrows
            Other = $Other
            Root = $null
        }
        $inner | Add-Member ScriptMethod GetDefaultFolder {
            param([int]$kind)
            switch ($kind) {
                6  { $this.Inbox }
                3  { if ($this.DeletedThrows) { throw 'The operation failed.' }; $this.Deleted }
                5  { $this.Sent }
                16 { $this.Drafts }
                23 { $this.Junk }
                default { $this.Other[$kind] }
            }
        }
        $inner | Add-Member ScriptMethod GetRootFolder { $this.Root }

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
        $inner.Root = $s
        Set-FakeStoreOn -Folder $s -Store $inner
        # The default folders are tagged too, whether or not the test also
        # lists them among the children.
        foreach ($f in @($Inbox, $Deleted, $Sent, $Drafts, $Junk) + @($Other.Values)) { if ($f) { Set-FakeStoreOn -Folder $f -Store $inner } }
        $s
    }

    # Reference equality, because Should -Be on two folders compares what they
    # look like rather than whether they are the same folder, and every empty
    # fake folder looks alike.
    function Test-Same { param($A, $B) [object]::ReferenceEquals($A, $B) }

    # A mailbox with reports in the Inbox and a Deleted Items to move them to.
    function New-MoveFixture {
        param([object[]]$InboxItems, [string]$StoreName = 'DMARC')
        $inbox = New-FakeFolder 'Inbox' -Items $InboxItems
        $deleted = New-FakeFolder 'Deleted Items'
        $store = New-FakeStore $StoreName -Children @($inbox, $deleted) -Inbox $inbox -Deleted $deleted
        [pscustomobject]@{ Inbox = $inbox; Deleted = $deleted; Store = $store }
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
            # Saved into the folder's staging area first, then moved in once
            # it is known to be new; either way, under the folder asked for.
            $att.SavedTo | Should -BeLike "*rel-export*"
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
            $good = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'Quarantine')
            $bad  = New-FakeStore 'Public Folders - someone' -FoldersThrow

            # -Mailbox names one, so this walks into it rather than printing
            # names only - which is what makes the throwing store beside it
            # something this can still die on.
            $r = Invoke-Export -Stores @($bad, $good) `
                -Arguments @('-OutputPath', $script:Out, '-List', '-Mailbox', 'DMARC Reports')

            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'DMARC Reports'
            $r.Text | Should -Match 'Quarantine'
        }

        It 'survives a throwing store when listing names across all of them' {
            $good = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'DMARC')
            $bad  = New-FakeStore 'Public Folders - someone' -FoldersThrow

            $r = Invoke-Export -Stores @($bad, $good) -Arguments @('-OutputPath', $script:Out, '-List')

            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'DMARC Reports'
            $r.Text | Should -Match 'Public Folders - someone'
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

    Context '-List with several mailboxes open' {
        # A real run printed thirteen stores two levels deep: a university
        # account's folder tree, a personal calendar, vendor and alert folders,
        # public folders. None of it has anything to do with DMARC, all of it
        # is somebody's real mail, and the whole lot then gets pasted into a
        # ticket along with the bit that was wanted. The names alone are what
        # -List is for.

        It 'prints the mailbox names and does not walk into any of them' {
            $mine = New-FakeStore 'me@example.com' -Children @(
                New-FakeFolder 'Financial Aid'
                New-FakeFolder 'Inbox')
            $shared = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'DMARC')

            $r = Invoke-Export -Stores @($mine, $shared) -Arguments @('-OutputPath', $script:Out, '-List')

            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'me@example\.com'
            $r.Text | Should -Match 'DMARC Reports'
            $r.Text | Should -Not -Match 'Financial Aid'
        }

        It 'says how to look inside one' {
            # A listing that shows less has to say how to get more, or it is
            # just a worse listing.
            $a = New-FakeStore 'me@example.com' -Children @(New-FakeFolder 'Inbox')
            $b = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'Inbox')

            $r = Invoke-Export -Stores @($a, $b) -Arguments @('-OutputPath', $script:Out, '-List')

            $r.Text | Should -Match '-Mailbox'
        }

        It 'walks into the one named, and only that one' {
            $mine = New-FakeStore 'me@example.com' -Children @(New-FakeFolder 'Financial Aid')
            $shared = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'DMARC')

            $r = Invoke-Export -Stores @($mine, $shared) `
                -Arguments @('-OutputPath', $script:Out, '-List', '-Mailbox', 'DMARC Reports')

            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'DMARC'
            $r.Text | Should -Not -Match 'Financial Aid'
        }

        It 'shows the whole tree when only one mailbox is open' {
            # Nothing to choose between, so nothing to withhold.
            $only = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'DMARC')

            $r = Invoke-Export -Stores @($only) -Arguments @('-OutputPath', $script:Out, '-List')

            $r.ExitCode | Should -Be 0
            $r.Text | Should -Match 'DMARC'
        }

        It 'exports nothing either way' {
            $a = New-FakeStore 'me@example.com' -Children @(
                New-FakeFolder 'Inbox' -Items @(New-FakeItem @(New-FakeAttachment 'private.xml')))
            $b = New-FakeStore 'DMARC Reports' -Children @(New-FakeFolder 'Inbox')

            $r = Invoke-Export -Stores @($a, $b) -Arguments @('-OutputPath', $script:Out, '-List')

            $r.ExitCode | Should -Be 0
            Test-Path (Join-Path $script:Out 'private.xml') | Should -BeFalse
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

            $r.Text | Should -Match '1 new report\(s\) written'
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

    Context 'marking as read' {
        It 'marks a message read once its report is saved' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out)

            $item.UnRead | Should -BeFalse
            $item.Saved  | Should -Be 1
            $r.Text | Should -Match 'marked read'
        }

        It 'leaves a message with no report on it alone' {
            $item = New-FakeItem @(New-FakeAttachment 'signature.png')
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            $item.UnRead | Should -BeTrue
        }

        It 'leaves a message unread when one of its attachments could not be saved' {
            # Unread is how somebody notices it. Marking it read would hide
            # the one message that needs looking at.
            $item = New-FakeItem @((New-FakeAttachment 'broken.xml' -ThrowsOnSave), (New-FakeAttachment 'google.xml'))
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            $item.UnRead | Should -BeTrue
        }

        It 'does not rewrite a message that was already read' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml') -UnRead $false
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            $item.Saved | Should -Be 0
        }

        It 'changes nothing with -LeaveUnread' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-LeaveUnread') | Out-Null

            Test-Path (Join-Path $script:Out 'Inbox' 'google.xml') | Should -BeTrue
            $item.UnRead | Should -BeTrue
            $item.Saved  | Should -Be 0
        }

        It 'says so when a message could not be marked read, rather than only with -Verbose' {
            # A shared mailbox the signed-in user may read but not change
            # refuses the write. The export is fine and the flag is a nicety,
            # but a flag that silently never changes is exactly how "my script
            # is not marking them read" goes unexplained for weeks.
            $item = New-FakeItem @(New-FakeAttachment 'google.xml') -SaveThrows
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out)

            $r.ExitCode | Should -Be 0
            Test-Path (Join-Path $script:Out 'Inbox' 'google.xml') | Should -BeTrue
            $r.Text | Should -Match '1 message\(s\) could not be marked read'
            $r.Text | Should -Match 'sufficient permission'
        }

        It 'says nothing about failures when every message was marked' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out)

            $r.Text | Should -Not -Match 'could not be marked read'
        }
    }

    Context 'moving to Deleted Items' {
        # The cleanup half of the job. Opt in, because a script that moves
        # people's mail unasked is a surprise; and soft, because Deleted Items
        # is where a person can still drag a message back from.

        It 'leaves every message where it is without the switch' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $fx = New-MoveFixture @($item)

            Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            $item.MovedTo | Should -BeNullOrEmpty
            $fx.Inbox.Items.Count   | Should -Be 1
            $fx.Deleted.Items.Count | Should -Be 0
        }

        It 'marks a message read and moves it to Deleted Items once its report is saved' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $fx = New-MoveFixture @($item)

            $r = Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')

            $r.ExitCode | Should -Be 0
            Test-Path (Join-Path $script:Out 'Inbox' 'google.xml') | Should -BeTrue
            $item.UnRead | Should -BeFalse
            $item.Saved  | Should -Be 1
            Test-Same $item.MovedTo $fx.Deleted | Should -BeTrue
            $fx.Inbox.Items.Count   | Should -Be 0
            $fx.Deleted.Items.Count | Should -Be 1
            $r.Text | Should -Match '1 message\(s\) moved to Deleted Items'
        }

        It 'moves every message, although the folder shrinks as it goes' {
            # Taking a message out of a folder shifts the next one into its
            # place. A loop that counts upward while it moves skips every
            # other message: five reports in, three moved, and the other two
            # waiting for tomorrow, where the same thing happens again.
            $items = 1..5 | ForEach-Object { New-FakeItem @(New-FakeAttachment "report$_.xml") }
            $fx = New-MoveFixture $items

            $r = Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')

            $fx.Inbox.Items.Count   | Should -Be 0
            $fx.Deleted.Items.Count | Should -Be 5
            @($items | Where-Object { $_.UnRead }).Count | Should -Be 0
            @(Get-ChildItem (Join-Path $script:Out 'Inbox') -File).Count | Should -Be 5
            $r.Text | Should -Match '5 message\(s\) moved to Deleted Items'
        }

        It 'moves without marking read when asked to leave messages unread' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $fx = New-MoveFixture @($item)

            Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted', '-LeaveUnread') | Out-Null

            $item.UnRead | Should -BeTrue
            $item.Saved  | Should -Be 0
            Test-Same $item.MovedTo $fx.Deleted | Should -BeTrue
        }

        It 'leaves a message with no report on it where it is' {
            $item = New-FakeItem @(New-FakeAttachment 'signature.png')
            $fx = New-MoveFixture @($item)

            Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted') | Out-Null

            $item.MovedTo | Should -BeNullOrEmpty
            $fx.Inbox.Items.Count | Should -Be 1
        }

        It 'leaves a message where it is when one of its attachments could not be saved' {
            # The same rule as marking read, and for the same reason: this is
            # the one message somebody needs to look at.
            $item = New-FakeItem @((New-FakeAttachment 'broken.xml' -ThrowsOnSave), (New-FakeAttachment 'google.xml'))
            $fx = New-MoveFixture @($item)

            Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted') | Out-Null

            $item.MovedTo | Should -BeNullOrEmpty
            $item.UnRead  | Should -BeTrue
            $fx.Inbox.Items.Count | Should -Be 1
        }

        It 'still moves a message whose report an earlier run saved' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $fx = New-MoveFixture @($item)
            Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            $r = Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')

            $r.Text | Should -Match '0 new report\(s\) written'
            Test-Same $item.MovedTo $fx.Deleted | Should -BeTrue
            $fx.Inbox.Items.Count | Should -Be 0
        }

        It 'moves out of the Inbox and out of folders somebody made, in one run' {
            # A rule that files reports into DMARC\<domain> leaves the newest
            # ones in the Inbox, so both have to be cleaned. The folder is
            # named with a literal backslash, as the real ones are.
            $a = New-FakeItem @(New-FakeAttachment 'a.xml')
            $b = New-FakeItem @(New-FakeAttachment 'b.xml')
            $c = New-FakeItem @(New-FakeAttachment 'c.xml')
            $sub   = New-FakeFolder 'Quarterly' -Items @($c)
            $inbox = New-FakeFolder 'Inbox' -Items @($a) -Children @($sub)
            $acme  = New-FakeFolder 'DMARC\acme.example' -Items @($b)
            $deleted = New-FakeFolder 'Deleted Items'
            $store = New-FakeStore 'DMARC' -Children @($inbox, $acme, $deleted) -Inbox $inbox -Deleted $deleted

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')

            $deleted.Items.Count | Should -Be 3
            $inbox.Items.Count + $acme.Items.Count + $sub.Items.Count | Should -Be 0
            $r.Text | Should -Match '3 message\(s\) moved to Deleted Items'
        }

        It 'never moves anything out of Sent Items, Drafts, Junk Email or Deleted Items itself' {
            # A whole-mailbox export visits every folder, and a report file
            # attached to something somebody sent, or kept as a draft, is not
            # a message this script has any business deleting.
            $sentItem  = New-FakeItem @(New-FakeAttachment 'sent.xml')
            $subItem   = New-FakeItem @(New-FakeAttachment 'sentsub.xml')
            $draftItem = New-FakeItem @(New-FakeAttachment 'draft.xml')
            $junkItem  = New-FakeItem @(New-FakeAttachment 'junk.xml')
            $oldItem   = New-FakeItem @(New-FakeAttachment 'old.xml')
            $newItem   = New-FakeItem @(New-FakeAttachment 'new.xml')
            $sentSub = New-FakeFolder 'Old sent' -Items @($subItem)
            $sent    = New-FakeFolder 'Sent Items' -Items @($sentItem) -Children @($sentSub)
            $drafts  = New-FakeFolder 'Drafts' -Items @($draftItem)
            $junk    = New-FakeFolder 'Junk Email' -Items @($junkItem)
            $deleted = New-FakeFolder 'Deleted Items' -Items @($oldItem)
            $inbox   = New-FakeFolder 'Inbox' -Items @($newItem)
            $store = New-FakeStore 'DMARC' -Children @($inbox, $sent, $drafts, $junk, $deleted) `
                -Inbox $inbox -Deleted $deleted -Sent $sent -Drafts $drafts -Junk $junk

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')

            # Every one of them is still exported; only the move is withheld.
            foreach ($f in 'Sent Items\sent.xml', 'Sent Items\Old sent\sentsub.xml', 'Drafts\draft.xml', 'Junk Email\junk.xml', 'Deleted Items\old.xml', 'Inbox\new.xml') {
                Test-Path (Join-Path $script:Out ($f -replace '\\', [IO.Path]::DirectorySeparatorChar)) | Should -BeTrue -Because $f
            }
            foreach ($i in $sentItem, $subItem, $draftItem, $junkItem, $oldItem) { $i.MovedTo | Should -BeNullOrEmpty }
            $sent.Items.Count    | Should -Be 1
            $sentSub.Items.Count | Should -Be 1
            $drafts.Items.Count  | Should -Be 1
            $junk.Items.Count    | Should -Be 1
            # The one message that was in the Inbox is the only one that moved.
            Test-Same $newItem.MovedTo $deleted | Should -BeTrue
            $deleted.Items.Count | Should -Be 2
            $r.Text | Should -Match '1 message\(s\) moved to Deleted Items'
        }

        It 'leaves Conflicts and Sync Issues alone too' {
            $conflict = New-FakeItem @(New-FakeAttachment 'conflict.xml')
            $sync     = New-FakeItem @(New-FakeAttachment 'sync.xml')
            $conflicts  = New-FakeFolder 'Conflicts' -Items @($conflict)
            $syncIssues = New-FakeFolder 'Sync Issues' -Items @($sync)
            $inbox = New-FakeFolder 'Inbox'
            $deleted = New-FakeFolder 'Deleted Items'
            $store = New-FakeStore 'DMARC' -Children @($inbox, $conflicts, $syncIssues, $deleted) `
                -Inbox $inbox -Deleted $deleted -Other @{ 19 = $conflicts; 20 = $syncIssues }

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted') | Out-Null

            $conflict.MovedTo | Should -BeNullOrEmpty
            $sync.MovedTo     | Should -BeNullOrEmpty
            $conflicts.Items.Count  | Should -Be 1
            $syncIssues.Items.Count | Should -Be 1
        }

        It 'does not move a message it only reaches through a search folder' {
            # "Unread Mail" and its kind list messages that sit in other
            # folders, Sent Items among them. Moving one from there moves the
            # original, past the protection on Sent Items itself. A message
            # is only moved from the folder it actually lives in.
            $sentItem = New-FakeItem @(New-FakeAttachment 'sent.xml')
            $inboxItem = New-FakeItem @(New-FakeAttachment 'inbox.xml')
            $sent = New-FakeFolder 'Sent Items' -Items @($sentItem)
            $unreadMail = New-FakeFolder 'Unread Mail' -Items @($sentItem, $inboxItem) -Virtual
            $searchFolders = New-FakeFolder 'Search Folders' -Children @($unreadMail)
            $inbox = New-FakeFolder 'Inbox' -Items @($inboxItem)
            $deleted = New-FakeFolder 'Deleted Items'
            $store = New-FakeStore 'DMARC' -Children @($inbox, $sent, $searchFolders, $deleted) `
                -Inbox $inbox -Deleted $deleted -Sent $sent

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')

            $sentItem.MovedTo | Should -BeNullOrEmpty
            $sent.Items.Count | Should -Be 1
            # The Inbox message is still moved, once, from the Inbox.
            Test-Same $inboxItem.MovedTo $deleted | Should -BeTrue
            $deleted.Items.Count | Should -Be 1
            $r.Text | Should -Match '1 message\(s\) moved to Deleted Items'
        }

        It 'moves into the Deleted Items of the mailbox the message is in, not the signed-in user''s own' {
            # The shared mailbox is a store of its own beside the operator's.
            # Asking the namespace for Deleted Items answers with the
            # operator's, and the report would leave the shared mailbox for
            # somebody's personal one.
            $ownInbox = New-FakeFolder 'Inbox'
            $ownDeleted = New-FakeFolder 'Deleted Items'
            $own = New-FakeStore 'Someone Personal' -Children @($ownInbox, $ownDeleted) -Inbox $ownInbox -Deleted $ownDeleted

            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $fx = New-MoveFixture @($item) -StoreName 'DMARC Reports'

            Invoke-Export -Stores @($own, $fx.Store) -Arguments @('-OutputPath', $script:Out, '-Mailbox', 'DMARC Reports', '-MoveToDeleted') | Out-Null

            Test-Same $item.MovedTo $fx.Deleted | Should -BeTrue
            $ownDeleted.Items.Count | Should -Be 0
        }

        It 'falls back to the folder called Deleted Items when the store will not answer for it' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $deleted = New-FakeFolder 'Deleted Items'
            $store = New-FakeStore 'DMARC' -Children @($inbox, $deleted) -Inbox $inbox -DeletedThrows

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted') | Out-Null

            Test-Same $item.MovedTo $deleted | Should -BeTrue
        }

        It 'says so, and leaves the mail where it is, when there is no Deleted Items to be found' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox -DeletedThrows

            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')

            $r.ExitCode | Should -Be 0
            $item.MovedTo | Should -BeNullOrEmpty
            $inbox.Items.Count | Should -Be 1
            $r.Text | Should -Match "no Deleted Items folder.*'DMARC'"
            # Marking read does not depend on it.
            $item.UnRead | Should -BeFalse
        }

        It 'costs one message, not the run, when a move fails, and says so' {
            $first  = New-FakeItem @(New-FakeAttachment 'one.xml')
            $stuck  = New-FakeItem @(New-FakeAttachment 'two.xml') -MoveThrows
            $third  = New-FakeItem @(New-FakeAttachment 'three.xml')
            $fx = New-MoveFixture @($first, $stuck, $third)

            $r = Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')

            $r.ExitCode | Should -Be 0
            $fx.Deleted.Items.Count | Should -Be 2
            $fx.Inbox.Items.Count   | Should -Be 1
            Test-Path (Join-Path $script:Out 'Inbox' 'two.xml') | Should -BeTrue
            $r.Text | Should -Match '2 message\(s\) moved to Deleted Items'
            $r.Text | Should -Match '1 message\(s\) could not be moved to Deleted Items'
            $r.Text | Should -Match 'The operation failed'
        }

        It 'shows what it moved in the table, and not at all when it was not asked to' {
            $fx = New-MoveFixture @(New-FakeItem @(New-FakeAttachment 'google.xml'))
            $with = Invoke-Export -Stores @($fx.Store) -Arguments @('-OutputPath', $script:Out, '-MoveToDeleted')
            $with.Text | Should -Match 'marked read\s+moved'

            $fx2 = New-MoveFixture @(New-FakeItem @(New-FakeAttachment 'other.xml'))
            $without = Invoke-Export -Stores @($fx2.Store) -Arguments @('-OutputPath', (Join-Path $script:Out 'again'))
            $without.Text | Should -Not -Match 'moved'
        }
    }

    Context 'running again into the same folder' {
        # The folder had to be deleted before every run to see only new mail:
        # otherwise every report came back as name(1), name(2)...

        It 'saves nothing the second time' {
            $att = New-FakeAttachment 'google.xml'
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @($att))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null
            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out)

            $r.Text | Should -Match '0 new report\(s\) written'
            $r.Text | Should -Match '1 already exported by an earlier run'
            @(Get-ChildItem (Join-Path $script:Out 'Inbox') -File).Name | Should -Be @('google.xml')
        }

        It 'saves only what arrived since' {
            $first = New-FakeItem @(New-FakeAttachment 'a.xml')
            $inbox = New-FakeFolder 'Inbox' -Items @($first)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox
            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            $inbox = New-FakeFolder 'Inbox' -Items @($first, (New-FakeItem @(New-FakeAttachment 'b.xml')))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox
            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out)

            $r.Text | Should -Match '1 new report\(s\) written'
            @(Get-ChildItem (Join-Path $script:Out 'Inbox') -File | Sort-Object Name).Name | Should -Be @('a.xml', 'b.xml')
        }

        It 'recognizes a report by its contents, whatever it is called' {
            # Receivers reuse names; the same report can also arrive twice
            # under different ones.
            $inbox = New-FakeFolder 'Inbox' -Items @(
                (New-FakeItem @(New-FakeAttachment 'one.xml' -Body 'same report')),
                (New-FakeItem @(New-FakeAttachment 'two.xml' -Body 'same report')))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            @(Get-ChildItem (Join-Path $script:Out 'Inbox') -File).Name | Should -Be @('one.xml')
        }

        It 'keeps an old export folder and does not save its reports again' {
            # A folder from before the index existed: its files are adopted.
            New-Item -ItemType Directory -Path (Join-Path $script:Out 'Inbox') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $script:Out 'Inbox' 'google.xml') -Value 'already here' -NoNewline

            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @(New-FakeAttachment 'google.xml' -Body 'already here'))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox
            $r = Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out)

            $r.Text | Should -Match '0 new report\(s\) written'
            $r.Text | Should -Match '1 report\(s\) already in the folder were added to the index'
            Test-Path (Join-Path $script:Out 'Inbox' 'google(1).xml') | Should -BeFalse
        }

        It 'does not bring back a report deleted after it was imported' {
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @(New-FakeAttachment 'google.xml'))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox
            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            Remove-Item (Join-Path $script:Out 'Inbox' 'google.xml')
            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            Test-Path (Join-Path $script:Out 'Inbox' 'google.xml') | Should -BeFalse
        }

        It 'still marks a message read when its report was exported before' {
            $item = New-FakeItem @(New-FakeAttachment 'google.xml')
            $inbox = New-FakeFolder 'Inbox' -Items @($item)
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox
            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out, '-LeaveUnread') | Out-Null

            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            $item.UnRead | Should -BeFalse
        }

        It 'leaves no staging files behind' {
            $inbox = New-FakeFolder 'Inbox' -Items @(New-FakeItem @(New-FakeAttachment 'google.xml'))
            $store = New-FakeStore 'DMARC' -Children @($inbox) -Inbox $inbox
            Invoke-Export -Stores @($store) -Arguments @('-OutputPath', $script:Out) | Out-Null

            Test-Path (Join-Path $script:Out '.incoming') | Should -BeFalse
        }
    }

    Context 'running daily' {
        BeforeEach {
            # The ScheduledTasks module is Windows-only. Stand-ins record what
            # would have been registered.
            $global:Registered = $null
            function global:New-ScheduledTaskAction { param($Execute, $Argument) [pscustomobject]@{ Execute = $Execute; Argument = $Argument } }
            function global:New-ScheduledTaskTrigger { param([switch]$Daily, $At) [pscustomobject]@{ At = $At } }
            function global:New-ScheduledTaskPrincipal { param($UserId, $LogonType) [pscustomobject]@{ LogonType = $LogonType } }
            function global:New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, $ExecutionTimeLimit) [pscustomobject]@{} }
            function global:Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Principal, $Settings, [switch]$Force) $global:Registered = [pscustomobject]@{ Name = $TaskName; Action = $Action; Trigger = $Trigger; Principal = $Principal } }
        }

        AfterEach {
            foreach ($f in 'New-ScheduledTaskAction', 'New-ScheduledTaskTrigger', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet', 'Register-ScheduledTask') {
                Remove-Item "Function:\$f" -ErrorAction SilentlyContinue
            }
        }

        It 'registers the same export to run every day, without re-registering itself' {
            $r = Invoke-Export -Stores @() -Arguments @('-OutputPath', $script:Out, '-Mailbox', 'DMARC Reports', '-Schedule', '07:00')

            $r.ExitCode | Should -Be 0
            $global:Registered.Name | Should -Be 'DMARC report export'
            $global:Registered.Trigger.At.ToString('HH:mm') | Should -Be '07:00'
            $global:Registered.Principal.LogonType | Should -Be 'Interactive'
            $global:Registered.Action.Argument | Should -Match ([regex]::Escape($script:Out))
            $global:Registered.Action.Argument | Should -Match '-Mailbox "DMARC Reports"'
            $global:Registered.Action.Argument | Should -Match '-LogFile'
            $global:Registered.Action.Argument | Should -Not -Match '-Schedule'
        }

        It 'passes -MoveToDeleted through to the task, and only when it was asked for' {
            $with = Invoke-Export -Stores @() -Arguments @('-OutputPath', $script:Out, '-Schedule', '07:00', '-MoveToDeleted')
            $with.ExitCode | Should -Be 0
            $global:Registered.Action.Argument | Should -Match '-MoveToDeleted'

            $global:Registered = $null
            Invoke-Export -Stores @() -Arguments @('-OutputPath', $script:Out, '-Schedule', '07:00') | Out-Null
            $global:Registered.Action.Argument | Should -Not -Match 'MoveToDeleted'
        }

        It 'refuses a time it cannot read, and registers nothing' {
            $r = Invoke-Export -Stores @() -Arguments @('-OutputPath', $script:Out, '-Schedule', 'teatime')

            $r.ExitCode | Should -Be 64
            $global:Registered | Should -BeNullOrEmpty
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
