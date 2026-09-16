<#
.SYNOPSIS
    Test helpers for loading engine functions without executing the engine.

.DESCRIPTION
    Invoke-DMARCReporter.ps1 is a script, not a module: dot-sourcing it would
    run its param block, create directories, and try to reach Microsoft Graph.
    So instead we parse it with the PowerShell AST, pull out the specific
    function definitions we want to test, and hand back a scriptblock the
    caller dot-sources into its own scope.

    Why the AST rather than line offsets or regex: the AST gives exact extents
    for each FunctionDefinitionAst, so tests keep working when the engine file
    grows, shrinks, or gets reordered. A regex over braces does not survive a
    nested hashtable containing a "}" in a string.

    This deliberately touches no production code. When the engine is later
    extracted into a real module (see db/schema.sql's rebuild notes), swap
    Import-EngineFunction for a plain Import-Module and the tests keep passing
    unchanged — which is the point: they characterize current behavior so the
    refactor has a safety net.
#>

Set-StrictMode -Version Latest

function Get-EngineScriptPath {
    <#  Resolves a script in the repo root from anywhere under tests/.  #>
    param(
        [Parameter(Mandatory)] [string]$FileName
    )
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $full = Join-Path $repoRoot $FileName
    if (-not (Test-Path $full)) {
        throw "Expected to find $FileName at repo root ($full) but it is not there."
    }
    return $full
}

function Import-EngineFunction {
    <#
    .SYNOPSIS
        Returns a scriptblock defining the named functions from a script file.

    .EXAMPLE
        . (Import-EngineFunction -ScriptPath $p -FunctionName 'ConvertFrom-DMARCReport')
    #>
    param(
        [Parameter(Mandatory)] [string]$ScriptPath,
        [Parameter(Mandatory)] [string[]]$FunctionName
    )

    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath, [ref]$null, [ref]$parseErrors)

    if ($parseErrors -and $parseErrors.Count -gt 0) {
        $detail = ($parseErrors | ForEach-Object {
            "  L$($_.Extent.StartLineNumber):$($_.Extent.StartColumnNumber) $($_.Message)"
        }) -join "`n"
        throw "Cannot extract functions - $ScriptPath has $($parseErrors.Count) parse error(s):`n$detail"
    }

    $allFunctions = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)

    $sourceParts = [System.Collections.Generic.List[string]]::new()
    foreach ($wanted in $FunctionName) {
        $match = $allFunctions | Where-Object { $_.Name -eq $wanted } | Select-Object -First 1
        if (-not $match) {
            $available = ($allFunctions.Name | Sort-Object) -join ', '
            throw "Function '$wanted' not found in $ScriptPath. Available: $available"
        }
        $sourceParts.Add($match.Extent.Text)
    }

    return [scriptblock]::Create($sourceParts -join "`n`n")
}

function New-EngineStub {
    <#
    .SYNOPSIS
        Returns a scriptblock defining no-op stubs for engine-wide helpers that
        the extracted functions call but that live outside them.

    .DESCRIPTION
        Write-Log writes to a log file path built by the engine's top-level
        code, which we never execute. Stubbing it keeps the parsers pure and
        keeps test output clean. Set $env:DMARC_TEST_VERBOSE=1 to see the
        messages, which is useful when a parser is silently swallowing an error.

        Built via [scriptblock]::Create rather than a literal { } block: a
        literal is bound to THIS module's session state, so dot-sourcing it
        from a test would define the stubs inside the module instead of in the
        test's scope, and the extracted parsers would still not find Write-Log.
        A Create()d scriptblock is unbound and dot-sources where the caller
        wants it.
    #>
    return [scriptblock]::Create(@'
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    if ($env:DMARC_TEST_VERBOSE) { Write-Host "[$Level] $Message" -ForegroundColor DarkGray }
}
function Write-AuditEvent {
    param([string]$Message, [string]$EntryType = 'Information', [int]$EventId = 1000)
}
'@)
}

function New-TempDmarcFile {
    <#
    .SYNOPSIS
        Writes content to a temp file with a specific encoding and returns the path.

    .DESCRIPTION
        Encoding matters here: the RUA parser is supposed to honour the XML
        declaration rather than assuming UTF-8, and that is only testable if
        the fixture is genuinely written in the declared encoding. Pass
        -Encoding to produce a real ISO-8859-1 or UTF-16 file.
    #>
    param(
        # AllowEmptyString: "parser must not throw on a zero-byte attachment"
        # is a real case worth testing, and Mandatory rejects '' without it.
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$Content,
        [string]$Extension = '.xml',
        [string]$Encoding = 'utf8'
    )
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("dmarctest_$([guid]::NewGuid().ToString('N'))$Extension")

    switch ($Encoding.ToLowerInvariant()) {
        'iso-8859-1' {
            $enc = [System.Text.Encoding]::GetEncoding('ISO-8859-1')
            [System.IO.File]::WriteAllText($path, $Content, $enc)
        }
        'utf-16' {
            $enc = New-Object System.Text.UnicodeEncoding($false, $true)
            [System.IO.File]::WriteAllText($path, $Content, $enc)
        }
        'utf8-bom' {
            $enc = New-Object System.Text.UTF8Encoding($true)
            [System.IO.File]::WriteAllText($path, $Content, $enc)
        }
        default {
            $enc = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($path, $Content, $enc)
        }
    }
    return $path
}

function Get-FixturePath {
    param([Parameter(Mandatory)] [string]$Name)
    $p = Join-Path (Join-Path $PSScriptRoot 'fixtures') $Name
    if (-not (Test-Path $p)) { throw "Fixture not found: $p" }
    return $p
}

Export-ModuleMember -Function Get-EngineScriptPath, Import-EngineFunction, New-EngineStub, New-TempDmarcFile, Get-FixturePath
