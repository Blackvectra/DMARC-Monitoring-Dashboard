<#
    ConvertFrom-TLSRPTReport — RFC 8460 SMTP TLS Reporting.

    TLS-RPT tells you when another MTA could not establish TLS to you: expired
    certificates, STARTTLS stripped in transit, DANE/MTA-STS mismatches. Unlike
    DMARC it is per-policy rather than per-message, and one report can carry
    several policies each with several distinct failure types.

    The row-fan-out is the thing worth pinning: one record per failure-detail,
    but still exactly one record for a policy that had no failures at all, so a
    clean day does not silently vanish from the table.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $enginePath = Get-EngineScriptPath -FileName 'Invoke-DMARCReporter.ps1'
    . (New-EngineStub)
    . (Import-EngineFunction -ScriptPath $enginePath `
        -FunctionName 'ConvertTo-ReportDate', 'ConvertFrom-TLSRPTReport')

    function New-TlsRptFile {
        param([Parameter(Mandatory)] $Report)
        $json = $Report | ConvertTo-Json -Depth 10
        return New-TempDmarcFile -Content $json -Extension '.json'
    }

    function New-TlsRptReport {
        param(
            [string]$OrgName  = 'Google Inc.',
            [string]$ReportId = 'tlsrpt-2026-09-16-acme.com',
            [string]$Start    = '2026-09-16T00:00:00Z',
            [string]$End      = '2026-09-16T23:59:59Z',
            $Policies
        )
        if (-not $Policies) {
            $Policies = @(
                @{
                    policy  = @{ 'policy-type' = 'sts'; 'policy-domain' = 'acme.com' }
                    summary = @{ 'total-successful-session-count' = 9812; 'total-failure-session-count' = 0 }
                }
            )
        }
        return [ordered]@{
            'organization-name' = $OrgName
            'date-range'        = [ordered]@{ 'start-datetime' = $Start; 'end-datetime' = $End }
            'contact-info'      = 'smtp-tls-reporting@google.com'
            'report-id'         = $ReportId
            'policies'          = $Policies
        }
    }
}

Describe 'ConvertTo-ReportDate' {
    # Regression cover: ConvertFrom-Json on PS7 turns an ISO-8601 string into a
    # [DateTime]. The old code assumed a string and produced "09/16/2026".

    It 'formats a coerced [DateTime] as yyyy-MM-dd' {
        ConvertTo-ReportDate ([datetime]'2026-09-16T00:00:00Z') | Should -Be '2026-09-16'
    }

    It 'formats a plain ISO string as yyyy-MM-dd' {
        ConvertTo-ReportDate '2026-09-16T23:59:59Z' | Should -Be '2026-09-16'
    }

    It 'is culture-invariant' {
        $original = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            foreach ($c in 'en-US','en-GB','de-DE','ja-JP','fr-FR') {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]::GetCultureInfo($c)
                ConvertTo-ReportDate ([datetime]'2026-09-16T00:00:00Z') |
                    Should -Be '2026-09-16' -Because "culture $c must not change the stored format"
            }
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $original
        }
    }

    It 'never emits a slash-separated date' {
        # The exact shape of the bug: "09/16/2026" sorts and compares wrong
        # against every other date in the working directory.
        ConvertTo-ReportDate ([datetime]'2026-09-16T00:00:00Z') | Should -Not -Match '/'
    }

    It 'returns empty for null rather than throwing' {
        ConvertTo-ReportDate $null | Should -Be ''
    }

    It 'passes through a short unparseable value without throwing' {
        { ConvertTo-ReportDate 'x' } | Should -Not -Throw
    }
}

Describe 'ConvertFrom-TLSRPTReport' {

    Context 'a clean report with no failures' {
        BeforeAll {
            $script:f = New-TlsRptFile -Report (New-TlsRptReport)
            $script:r = ConvertFrom-TLSRPTReport -FilePath $script:f
        }
        AfterAll { Remove-Item $script:f -Force -ErrorAction SilentlyContinue }

        It 'still emits one record so a clean day is recorded, not dropped' {
            $script:r.Count | Should -Be 1
        }

        It 'marks the result type as none' {
            $script:r[0].ResultType | Should -Be 'none'
        }

        It 'carries the reporter identity and report id' {
            $script:r[0].OrgName  | Should -Be 'Google Inc.'
            $script:r[0].ReportId | Should -Be 'tlsrpt-2026-09-16-acme.com'
        }

        It 'reduces the ISO datetimes to plain yyyy-MM-dd dates' {
            # Must match the format the DMARC parsers emit. If TLS-RPT stores
            # "09/16/2026" while DMARC stores "2026-09-16", the dashboard's
            # date-range filters compare them as strings and silently disagree.
            $script:r[0].ReportDate | Should -Be '2026-09-16'
            $script:r[0].ReportEnd  | Should -Be '2026-09-16'
        }

        It 'carries the policy domain, type and session counters' {
            $script:r[0].Domain       | Should -Be 'acme.com'
            $script:r[0].PolicyType   | Should -Be 'sts'
            $script:r[0].TotalSuccess | Should -Be 9812
            $script:r[0].TotalFailure | Should -Be 0
        }

        It 'zeroes the failure-specific fields rather than leaving them null' {
            $script:r[0].FailedSessionCount  | Should -Be 0
            $script:r[0].SendingMtaIP        | Should -Be ''
            $script:r[0].ReceivingMxHostname | Should -Be ''
        }
    }

    Context 'a report carrying failure details' {
        BeforeAll {
            $policies = @(
                @{
                    policy  = @{ 'policy-type' = 'sts'; 'policy-domain' = 'acme.com' }
                    summary = @{ 'total-successful-session-count' = 500; 'total-failure-session-count' = 17 }
                    'failure-details' = @(
                        @{
                            'result-type'           = 'certificate-expired'
                            'sending-mta-ip'        = '209.85.220.41'
                            'receiving-mx-hostname' = 'mx1.acme.com'
                            'receiving-ip'          = '203.0.113.10'
                            'failed-session-count'  = 12
                        },
                        @{
                            'result-type'            = 'starttls-not-supported'
                            'sending-mta-ip'         = '209.85.220.42'
                            'receiving-mx-hostname'  = 'mx2.acme.com'
                            'failed-session-count'   = 5
                            'additional-information' = 'https://report.example/details/abc'
                        }
                    )
                }
            )
            $script:f = New-TlsRptFile -Report (New-TlsRptReport -Policies $policies)
            $script:r = ConvertFrom-TLSRPTReport -FilePath $script:f
        }
        AfterAll { Remove-Item $script:f -Force -ErrorAction SilentlyContinue }

        It 'emits one record per failure detail' {
            $script:r.Count | Should -Be 2
        }

        It 'captures each distinct result type' {
            ($script:r.ResultType | Sort-Object) | Should -Be @('certificate-expired','starttls-not-supported')
        }

        It 'captures the sending and receiving endpoints' {
            $expired = $script:r | Where-Object ResultType -eq 'certificate-expired'
            $expired.SendingMtaIP        | Should -Be '209.85.220.41'
            $expired.ReceivingMxHostname | Should -Be 'mx1.acme.com'
            $expired.ReceivingIP         | Should -Be '203.0.113.10'
            $expired.FailedSessionCount  | Should -Be 12
        }

        It 'carries additional-information when the reporter supplies it' {
            $st = $script:r | Where-Object ResultType -eq 'starttls-not-supported'
            $st.AdditionalInfo | Should -Be 'https://report.example/details/abc'
        }

        It 'defaults missing optional fields to empty rather than null' {
            # The starttls entry has no receiving-ip. An empty string keeps the
            # CSV column aligned; $null would serialise inconsistently.
            $st = $script:r | Where-Object ResultType -eq 'starttls-not-supported'
            $st.ReceivingIP | Should -Be ''
        }

        It 'repeats the policy-level summary on every failure row' {
            # Each row is self-contained so the dashboard can group without
            # joining back to a parent record.
            foreach ($row in $script:r) {
                $row.TotalSuccess | Should -Be 500
                $row.TotalFailure | Should -Be 17
                $row.Domain       | Should -Be 'acme.com'
            }
        }
    }

    Context 'multiple policies in one report' {
        It 'fans out across every policy' {
            $policies = @(
                @{
                    policy  = @{ 'policy-type' = 'sts'; 'policy-domain' = 'acme.com' }
                    summary = @{ 'total-successful-session-count' = 100; 'total-failure-session-count' = 0 }
                },
                @{
                    policy  = @{ 'policy-type' = 'tlsa'; 'policy-domain' = 'mail.acme.com' }
                    summary = @{ 'total-successful-session-count' = 50; 'total-failure-session-count' = 2 }
                    'failure-details' = @(
                        @{ 'result-type' = 'dane-required'; 'failed-session-count' = 2 }
                    )
                },
                @{
                    policy  = @{ 'policy-type' = 'no-policy-found'; 'policy-domain' = 'old.acme.com' }
                    summary = @{ 'total-successful-session-count' = 3; 'total-failure-session-count' = 0 }
                }
            )
            $f = New-TlsRptFile -Report (New-TlsRptReport -Policies $policies)
            try {
                $r = ConvertFrom-TLSRPTReport -FilePath $f
                # 1 clean + 1 failure-detail + 1 clean
                $r.Count | Should -Be 3
                ($r.Domain | Sort-Object) | Should -Be @('acme.com','mail.acme.com','old.acme.com')
                ($r | Where-Object Domain -eq 'mail.acme.com').ResultType | Should -Be 'dane-required'
                ($r | Where-Object Domain -eq 'old.acme.com').PolicyType  | Should -Be 'no-policy-found'
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'policy types seen in the wild' {
        It 'passes through policy type <policyType>' -ForEach @(
            @{ policyType = 'sts'             }
            @{ policyType = 'tlsa'            }
            @{ policyType = 'no-policy-found' }
        ) {
            $policies = @(
                @{
                    policy  = @{ 'policy-type' = $policyType; 'policy-domain' = 'acme.com' }
                    summary = @{ 'total-successful-session-count' = 1; 'total-failure-session-count' = 0 }
                }
            )
            $f = New-TlsRptFile -Report (New-TlsRptReport -Policies $policies)
            try {
                (ConvertFrom-TLSRPTReport -FilePath $f)[0].PolicyType | Should -Be $policyType
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'malformed input' {
        It 'returns no records for invalid JSON without throwing' {
            $f = New-TempDmarcFile -Content '{ this is not json' -Extension '.json'
            try {
                { ConvertFrom-TLSRPTReport -FilePath $f } | Should -Not -Throw
                (ConvertFrom-TLSRPTReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'returns no records for valid JSON that is not a TLS-RPT report' {
            $f = New-TempDmarcFile -Content '{"hello":"world"}' -Extension '.json'
            try {
                { ConvertFrom-TLSRPTReport -FilePath $f } | Should -Not -Throw
                (ConvertFrom-TLSRPTReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'returns no records for an empty file without throwing' {
            $f = New-TempDmarcFile -Content '' -Extension '.json'
            try {
                { ConvertFrom-TLSRPTReport -FilePath $f } | Should -Not -Throw
                (ConvertFrom-TLSRPTReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }

        It 'does not throw on a non-existent path' {
            $missing = Join-Path ([System.IO.Path]::GetTempPath()) 'no-such-tlsrpt-55012.json'
            { ConvertFrom-TLSRPTReport -FilePath $missing } | Should -Not -Throw
        }

        It 'does not throw when policies is absent entirely' {
            $bare = [ordered]@{
                'organization-name' = 'Example'
                'date-range'        = [ordered]@{ 'start-datetime' = '2026-09-16T00:00:00Z'; 'end-datetime' = '2026-09-16T23:59:59Z' }
                'report-id'         = 'bare-1'
            }
            $f = New-TlsRptFile -Report $bare
            try {
                { ConvertFrom-TLSRPTReport -FilePath $f } | Should -Not -Throw
                (ConvertFrom-TLSRPTReport -FilePath $f).Count | Should -Be 0
            } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }
}
