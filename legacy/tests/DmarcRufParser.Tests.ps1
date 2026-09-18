<#
    ConvertFrom-DMARCForensicReport — RFC 6591 ARF (forensic / RUF) parser.

    RUF reports are genuinely awkward input: a multipart/report envelope whose
    third part is the *reported* message, often with folded headers and
    sometimes base64-encoded. The naive version of this parser read headers off
    the outer envelope and reported the forwarder's own From/Subject instead of
    the spoofed message's — which is exactly backwards for a forensics feature.

    Most cases here are regression cover for PR #4 finding #20.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $enginePath = Get-EngineScriptPath -FileName 'Invoke-DMARCReporter.ps1'
    . (New-EngineStub)
    . (Import-EngineFunction -ScriptPath $enginePath -FunctionName 'ConvertFrom-DMARCForensicReport')
}

Describe 'ConvertFrom-DMARCForensicReport' {

    Context 'a flat (non-multipart) ARF report' {
        BeforeAll {
            $arf = @'
Feedback-Type: auth-failure
User-Agent: Lua/1.0
Version: 1
Original-Mail-From: attacker@evil.example
Arrival-Date: Tue, 16 Sep 2026 09:14:22 -0000
Source-IP: 203.0.113.55
Reported-Domain: acme.com
Authentication-Results: mx.google.com; dkim=fail header.d=acme.com; spf=fail

Return-Path: <bounce@evil.example>
From: "Finance" <ceo@acme.com>
Subject: Urgent wire transfer
Message-ID: <abc123@evil.example>
'@
            $script:f = New-TempDmarcFile -Content $arf -Extension '.eml'
            $script:r = (ConvertFrom-DMARCForensicReport -FilePath $script:f)[0]
        }
        AfterAll { Remove-Item $script:f -Force -ErrorAction SilentlyContinue }

        It 'extracts the feedback-report envelope fields' {
            $script:r.SourceIP    | Should -Be '203.0.113.55'
            $script:r.ArrivalDate | Should -Match '16 Sep 2026'
            $script:r.Domain      | Should -Be 'acme.com'
        }

        It 'extracts the reported message headers' {
            $script:r.HeaderFrom | Should -Match 'ceo@acme\.com'
            $script:r.Subject    | Should -Be 'Urgent wire transfer'
            $script:r.MessageId  | Should -Be 'abc123@evil.example'
            $script:r.ReturnPath | Should -Be 'bounce@evil.example'
        }

        It 'extracts the authentication results' {
            $script:r.DKIMResult | Should -Be 'fail'
            $script:r.SPFResult  | Should -Be 'fail'
        }

        It 'tags the record as RUF and stamps ParsedAt' {
            $script:r.ReportType | Should -Be 'RUF'
            $script:r.ParsedAt   | Should -Not -BeNullOrEmpty
        }
    }

    Context 'multipart/report with an embedded message/rfc822 (regression: PR #4 finding #20)' {
        It 'reads From and Subject from the reported message, not the envelope' {
            # The trap: the outer envelope has its own From/Subject. A parser
            # that regexes the whole blob picks up "DMARC Report Generator" and
            # "Report Domain: acme.com" instead of the spoofed message.
            $arf = @'
From: DMARC Report Generator <noreply@google.com>
Subject: Report Domain: acme.com Submitter: google.com
Content-Type: multipart/report; report-type=feedback-report; boundary="BOUND1"

--BOUND1
Content-Type: text/plain

This is an authentication failure report.

--BOUND1
Content-Type: message/feedback-report

Feedback-Type: auth-failure
Arrival-Date: Tue, 16 Sep 2026 09:14:22 -0000
Source-IP: 198.51.100.42
Reported-Domain: acme.com

--BOUND1
Content-Type: message/rfc822

Return-Path: <bounce@evil.example>
From: "Payroll" <payroll@acme.com>
Subject: Please update your bank details
Message-ID: <spoof-9981@evil.example>
Authentication-Results: mx.google.com; dkim=fail; spf=softfail

--BOUND1--
'@
            $f = New-TempDmarcFile -Content $arf -Extension '.eml'
            try {
                $r = (ConvertFrom-DMARCForensicReport -FilePath $f)[0]

                $r.HeaderFrom | Should -Match 'payroll@acme\.com'
                $r.HeaderFrom | Should -Not -Match 'noreply@google\.com'

                $r.Subject    | Should -Be 'Please update your bank details'
                $r.Subject    | Should -Not -Match 'Report Domain'

                $r.MessageId  | Should -Be 'spoof-9981@evil.example'
                $r.SourceIP   | Should -Be '198.51.100.42'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'decodes a base64-encoded message/rfc822 part' {
            $inner = @"
Return-Path: <b@evil.example>
From: "CEO" <ceo@acme.com>
Subject: Base64 wrapped spoof
Message-ID: <b64-1@evil.example>
"@
            $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($inner))
            $arf = @"
Content-Type: multipart/report; boundary="B2"

--B2
Content-Type: message/feedback-report

Arrival-Date: Tue, 16 Sep 2026 10:00:00 -0000
Source-IP: 192.0.2.77
Reported-Domain: acme.com

--B2
Content-Type: message/rfc822
Content-Transfer-Encoding: base64

$b64

--B2--
"@
            $f = New-TempDmarcFile -Content $arf -Extension '.eml'
            try {
                $r = (ConvertFrom-DMARCForensicReport -FilePath $f)[0]
                $r.Subject   | Should -Be 'Base64 wrapped spoof'
                $r.MessageId | Should -Be 'b64-1@evil.example'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'RFC 5322 folded headers (regression: PR #4 finding #20)' {
        It 'unfolds a Subject split across continuation lines' {
            # Long subjects are folded by the sending MTA. Without unfolding,
            # only the first fragment survives into the forensics table.
            $arf = @"
Feedback-Type: auth-failure
Arrival-Date: Tue, 16 Sep 2026 09:14:22 -0000
Source-IP: 203.0.113.9
Reported-Domain: acme.com

From: <ceo@acme.com>
Subject: This is a very long subject line that the sending
`tMTA decided to fold across multiple physical lines
Message-ID: <folded-1@evil.example>
"@
            $f = New-TempDmarcFile -Content $arf -Extension '.eml'
            try {
                $r = (ConvertFrom-DMARCForensicReport -FilePath $f)[0]
                $r.Subject | Should -Match 'fold across multiple physical lines'
                $r.Subject | Should -Match 'very long subject line'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'domain resolution' {
        It 'prefers the explicit Reported-Domain header' {
            $arf = @'
Arrival-Date: Tue, 16 Sep 2026 09:00:00 -0000
Source-IP: 203.0.113.1
Reported-Domain: explicit.example

From: <someone@different.example>
Subject: x
'@
            $f = New-TempDmarcFile -Content $arf -Extension '.eml'
            try {
                (ConvertFrom-DMARCForensicReport -FilePath $f)[0].Domain | Should -Be 'explicit.example'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'falls back to the header-from domain when Reported-Domain is absent' {
            $arf = @'
Arrival-Date: Tue, 16 Sep 2026 09:00:00 -0000
Source-IP: 203.0.113.2

From: <victim@fallback.example>
Subject: x
'@
            $f = New-TempDmarcFile -Content $arf -Extension '.eml'
            try {
                (ConvertFrom-DMARCForensicReport -FilePath $f)[0].Domain | Should -Be 'fallback.example'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'malformed input' {
        It 'returns no records for an empty file without throwing' {
            $f = New-TempDmarcFile -Content '' -Extension '.eml'
            try {
                { ConvertFrom-DMARCForensicReport -FilePath $f } | Should -Not -Throw
                (ConvertFrom-DMARCForensicReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'returns no records for a whitespace-only file' {
            $f = New-TempDmarcFile -Content "   `n`n   `n" -Extension '.eml'
            try {
                (ConvertFrom-DMARCForensicReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'does not throw on a non-existent path' {
            $missing = Join-Path ([System.IO.Path]::GetTempPath()) 'no-such-ruf-11923.eml'
            { ConvertFrom-DMARCForensicReport -FilePath $missing } | Should -Not -Throw
        }

        It 'still produces a record when only some headers are present' {
            # Partial data is better than none for forensics - an IP alone is
            # actionable. The parser should degrade, not bail.
            $f = New-TempDmarcFile -Content "Source-IP: 203.0.113.99`nReported-Domain: acme.com`n" -Extension '.eml'
            try {
                $r = ConvertFrom-DMARCForensicReport -FilePath $f
                $r.Count      | Should -Be 1
                $r[0].SourceIP | Should -Be '203.0.113.99'
                $r[0].Subject  | Should -Be ''
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }
}
