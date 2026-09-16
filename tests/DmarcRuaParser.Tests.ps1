<#
    ConvertFrom-DMARCReport — RFC 7489 aggregate (RUA) parser.

    This is the highest-value thing in the codebase to pin down: every chart,
    score, and client report is downstream of it, and a silent parse failure
    shows up as "no data" rather than as an error.

    Several cases here are regression tests for bugs fixed in PR #4 and are
    marked as such.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $enginePath = Get-EngineScriptPath -FileName 'Invoke-DMARCReporter.ps1'
    . (New-EngineStub)
    . (Import-EngineFunction -ScriptPath $enginePath -FunctionName 'ConvertFrom-DMARCReport')

    # 2025-09-16T00:00:00Z .. 2025-09-16T23:59:59Z
    $script:Begin = 1757980800
    $script:End   = 1758067199

    function New-RuaXml {
        param(
            [string]$Declaration = '<?xml version="1.0" encoding="UTF-8"?>',
            [string]$OrgName     = 'google.com',
            [string]$ReportId    = 'RPT-1',
            [string]$Domain      = 'acme.com',
            [string]$PolicyTags  = '<adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>none</sp><pct>100</pct>',
            [string]$Records
        )
        if (-not $Records) {
            $Records = @'
  <record><row><source_ip>1.2.3.4</source_ip><count>42</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>acme.com</header_from></identifiers>
    <auth_results><dkim><domain>acme.com</domain><result>pass</result></dkim><spf><domain>acme.com</domain><result>pass</result></spf></auth_results>
  </record>
'@
        }
        return @"
$Declaration
<feedback>
  <report_metadata>
    <org_name>$OrgName</org_name>
    <email>noreply@$OrgName</email>
    <report_id>$ReportId</report_id>
    <date_range><begin>$($script:Begin)</begin><end>$($script:End)</end></date_range>
  </report_metadata>
  <policy_published><domain>$Domain</domain>$PolicyTags</policy_published>
$Records
</feedback>
"@
    }
}

Describe 'ConvertFrom-DMARCReport' {

    Context 'a well-formed single-record report' {
        BeforeAll {
            $script:file = New-TempDmarcFile -Content (New-RuaXml)
            $script:rec  = (ConvertFrom-DMARCReport -FilePath $script:file)[0]
        }
        AfterAll { Remove-Item $script:file -Force -ErrorAction SilentlyContinue }

        It 'extracts the reporting organisation and report id' {
            $script:rec.OrgName  | Should -Be 'google.com'
            $script:rec.ReportId | Should -Be 'RPT-1'
        }

        It 'converts the unix date range to yyyy-MM-dd in UTC' {
            $script:rec.ReportDate | Should -Be '2025-09-16'
            $script:rec.ReportEnd  | Should -Be '2025-09-16'
        }

        It 'reads the published policy' {
            $script:rec.Domain    | Should -Be 'acme.com'
            $script:rec.Policy    | Should -Be 'quarantine'
            $script:rec.SubPolicy | Should -Be 'none'
            $script:rec.PCTPct    | Should -Be 100
        }

        It 'reads the row counters and evaluated results' {
            $script:rec.SourceIP     | Should -Be '1.2.3.4'
            $script:rec.MessageCount | Should -Be 42
            $script:rec.Disposition  | Should -Be 'none'
            $script:rec.DKIMResult   | Should -Be 'pass'
            $script:rec.SPFResult    | Should -Be 'pass'
        }

        It 'stamps ParsedAt so rows can be traced to an ingest run' {
            $script:rec.ParsedAt | Should -Not -BeNullOrEmpty
        }
    }

    Context 'DMARC result derivation' {
        # DMARC passes when EITHER mechanism aligns - not both. Getting this
        # backwards would understate every customer's pass rate.
        It 'is <expected> when dkim=<dkim> and spf=<spf>' -ForEach @(
            @{ dkim = 'pass'; spf = 'pass'; expected = 'pass'; reason = 'aligned'   }
            @{ dkim = 'pass'; spf = 'fail'; expected = 'pass'; reason = 'dkim-only' }
            @{ dkim = 'fail'; spf = 'pass'; expected = 'pass'; reason = 'spf-only'  }
            @{ dkim = 'fail'; spf = 'fail'; expected = 'fail'; reason = 'both-fail' }
        ) {
            $rows = @"
  <record><row><source_ip>9.9.9.9</source_ip><count>7</count>
    <policy_evaluated><disposition>none</disposition><dkim>$dkim</dkim><spf>$spf</spf></policy_evaluated></row>
    <identifiers><header_from>acme.com</header_from></identifiers>
  </record>
"@
            $f = New-TempDmarcFile -Content (New-RuaXml -Records $rows)
            try {
                $r = (ConvertFrom-DMARCReport -FilePath $f)[0]
                $r.DMARCResult | Should -Be $expected
                $r.FailReason  | Should -Be $reason
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'multiple records in one report' {
        It 'returns one row per record element' {
            $rows = ''
            1..5 | ForEach-Object {
                $rows += @"
  <record><row><source_ip>10.0.0.$_</source_ip><count>$($_ * 10)</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>acme.com</header_from></identifiers>
  </record>
"@
            }
            $f = New-TempDmarcFile -Content (New-RuaXml -Records $rows)
            try {
                $r = ConvertFrom-DMARCReport -FilePath $f
                $r.Count | Should -Be 5
                ($r | Measure-Object MessageCount -Sum).Sum | Should -Be 150
                $r[4].SourceIP | Should -Be '10.0.0.5'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'character encoding (regression: PR #4 finding #18)' {
        # The parser used to force UTF-8 via Get-Content, which corrupted
        # reports that declare another encoding. Yahoo and several EU/Asian
        # receivers send ISO-8859-1. XmlDocument.Load honours the declaration.

        It 'honours an ISO-8859-1 declaration and preserves high-bytes' {
            $xml = New-RuaXml -Declaration '<?xml version="1.0" encoding="ISO-8859-1"?>' -OrgName 'rapporteur-fran' -ReportId 'ISO-1'
            # Inject a genuine Latin-1 character into the org name
            $xml = $xml -replace 'rapporteur-fran', "rapporteur-fran$([char]0xE7)ais"
            $f = New-TempDmarcFile -Content $xml -Encoding 'iso-8859-1'
            try {
                $r = ConvertFrom-DMARCReport -FilePath $f
                $r.Count | Should -Be 1
                $r[0].OrgName | Should -Be "rapporteur-fran$([char]0xE7)ais"
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'parses a UTF-16 encoded report' {
            $xml = New-RuaXml -Declaration '<?xml version="1.0" encoding="UTF-16"?>' -ReportId 'UTF16-1'
            $f = New-TempDmarcFile -Content $xml -Encoding 'utf-16'
            try {
                $r = ConvertFrom-DMARCReport -FilePath $f
                $r.Count | Should -Be 1
                $r[0].ReportId | Should -Be 'UTF16-1'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'parses UTF-8 with a byte-order mark' {
            $f = New-TempDmarcFile -Content (New-RuaXml -ReportId 'BOM-1') -Encoding 'utf8-bom'
            try {
                $r = ConvertFrom-DMARCReport -FilePath $f
                $r.Count | Should -Be 1
                $r[0].ReportId | Should -Be 'BOM-1'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'optional policy tags' {
        It 'defaults pct to 100 and sp to inherit when absent' {
            $f = New-TempDmarcFile -Content (New-RuaXml -PolicyTags '<p>reject</p>')
            try {
                $r = (ConvertFrom-DMARCReport -FilePath $f)[0]
                $r.PCTPct    | Should -Be 100
                $r.SubPolicy | Should -Be 'inherit'
                $r.ADKIM     | Should -Be 'r'
                $r.ASPF      | Should -Be 'r'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'reads strict alignment when published' {
            $f = New-TempDmarcFile -Content (New-RuaXml -PolicyTags '<p>reject</p><adkim>s</adkim><aspf>s</aspf><pct>50</pct>')
            try {
                $r = (ConvertFrom-DMARCReport -FilePath $f)[0]
                $r.ADKIM  | Should -Be 's'
                $r.ASPF   | Should -Be 's'
                $r.PCTPct | Should -Be 50
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'policy override reasons' {
        It 'captures an override type and folds it into FailReason' {
            $rows = @'
  <record><row><source_ip>5.5.5.5</source_ip><count>3</count>
    <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
      <reason><type>forwarded</type><comment>mailing list</comment></reason>
    </policy_evaluated></row>
    <identifiers><header_from>acme.com</header_from></identifiers>
  </record>
'@
            $f = New-TempDmarcFile -Content (New-RuaXml -Records $rows)
            try {
                $r = (ConvertFrom-DMARCReport -FilePath $f)[0]
                $r.OverrideReason | Should -Be 'forwarded'
                $r.FailReason     | Should -Be 'override:forwarded'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'reports none when no override is present' {
            $f = New-TempDmarcFile -Content (New-RuaXml)
            try {
                (ConvertFrom-DMARCReport -FilePath $f)[0].OverrideReason | Should -Be 'none'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'subdomain detection' {
        It 'flags <headerFrom> against policy domain acme.com as subdomain=<expected>' -ForEach @(
            @{ headerFrom = 'acme.com';          expected = $false }
            @{ headerFrom = 'mail.acme.com';     expected = $true  }
            @{ headerFrom = 'a.b.acme.com';      expected = $true  }
            @{ headerFrom = 'notacme.com';       expected = $false }
            @{ headerFrom = 'acme.com.evil.net'; expected = $false }
        ) {
            $rows = @"
  <record><row><source_ip>1.1.1.1</source_ip><count>1</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>$headerFrom</header_from></identifiers>
  </record>
"@
            $f = New-TempDmarcFile -Content (New-RuaXml -Records $rows)
            try {
                (ConvertFrom-DMARCReport -FilePath $f)[0].IsSubdomain | Should -Be $expected
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'auth_results domains' {
        It 'captures the DKIM and SPF domains when present' {
            $rows = @'
  <record><row><source_ip>2.2.2.2</source_ip><count>9</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>acme.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>mail.acme.com</domain><result>pass</result></dkim>
      <spf><domain>bounce.acme.com</domain><result>fail</result></spf>
    </auth_results>
  </record>
'@
            $f = New-TempDmarcFile -Content (New-RuaXml -Records $rows)
            try {
                $r = (ConvertFrom-DMARCReport -FilePath $f)[0]
                $r.DKIMDomain | Should -Be 'mail.acme.com'
                $r.SPFDomain  | Should -Be 'bounce.acme.com'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'returns empty strings when auth_results is absent rather than throwing' {
            $rows = @'
  <record><row><source_ip>3.3.3.3</source_ip><count>1</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>acme.com</header_from></identifiers>
  </record>
'@
            $f = New-TempDmarcFile -Content (New-RuaXml -Records $rows)
            try {
                $r = (ConvertFrom-DMARCReport -FilePath $f)[0]
                $r.DKIMDomain | Should -Be ''
                $r.SPFDomain  | Should -Be ''
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'malformed and hostile input' {
        # The engine treats an empty result as "parse produced no records" and
        # leaves the message in the inbox for retry. What it must never do is
        # throw, because that aborts the whole ingest run.

        It 'returns no records for truncated XML without throwing' {
            $f = New-TempDmarcFile -Content '<?xml version="1.0"?><feedback><report_metadata><org_name>x'
            try {
                { ConvertFrom-DMARCReport -FilePath $f } | Should -Not -Throw
                (ConvertFrom-DMARCReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'returns no records for an empty file without throwing' {
            $f = New-TempDmarcFile -Content ''
            try {
                { ConvertFrom-DMARCReport -FilePath $f } | Should -Not -Throw
                (ConvertFrom-DMARCReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'returns no records for a non-existent path without throwing' {
            $missing = Join-Path ([System.IO.Path]::GetTempPath()) 'definitely-not-here-98237.xml'
            { ConvertFrom-DMARCReport -FilePath $missing } | Should -Not -Throw
            (ConvertFrom-DMARCReport -FilePath $missing).Count | Should -Be 0
        }

        It 'returns no records for well-formed XML that is not a DMARC report' {
            $f = New-TempDmarcFile -Content '<?xml version="1.0"?><rss><channel><title>not dmarc</title></channel></rss>'
            try {
                { ConvertFrom-DMARCReport -FilePath $f } | Should -Not -Throw
                (ConvertFrom-DMARCReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'does not resolve external entities (XXE)' {
            # A report is attacker-influenced input: anyone can send mail that
            # provokes a report. An XXE here would read files off the engine host.
            $evil = @'
<?xml version="1.0"?>
<!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<feedback>
  <report_metadata><org_name>&xxe;</org_name><report_id>XXE</report_id>
    <date_range><begin>1757980800</begin><end>1758067199</end></date_range></report_metadata>
  <policy_published><domain>acme.com</domain><p>none</p></policy_published>
  <record><row><source_ip>1.1.1.1</source_ip><count>1</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>acme.com</header_from></identifiers></record>
</feedback>
'@
            $f = New-TempDmarcFile -Content $evil
            try {
                $r = ConvertFrom-DMARCReport -FilePath $f

                # Either outcome is acceptable: the parse is rejected outright,
                # or it succeeds with the entity left unresolved. .NET gives us
                # the latter because XmlDocument.XmlResolver defaults to null on
                # .NET Core+, so the SYSTEM entity is never fetched.
                #
                # Asserted on the whole serialised record rather than one field,
                # so this cannot pass vacuously if the shape of the output
                # changes or the leak surfaces somewhere other than OrgName.
                $serialised = $r | ConvertTo-Json -Depth 5 -Compress
                $serialised | Should -Not -Match 'root:'
                $serialised | Should -Not -Match '/bin/(ba)?sh'
                $serialised | Should -Not -Match 'daemon:'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }
}
