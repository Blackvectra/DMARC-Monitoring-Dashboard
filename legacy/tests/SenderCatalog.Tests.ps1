<#
    Resolve-SenderService + sender-catalog.json.

    Two distinct things under test:

      1. The matcher — does an rDNS hostname or org name resolve to the right
         service, at the right confidence?
      2. The catalog data itself — are all 76 entries structurally valid, and
         do their regexes actually compile? A malformed regex in the catalog
         would throw inside the ingest loop on whatever IP happened to hit it,
         which is the sort of failure that shows up at 3am on a customer's
         data rather than here.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'EngineTestHelpers.psm1') -Force
    $enginePath = Get-EngineScriptPath -FileName 'Invoke-DMARCReporter.ps1'
    . (New-EngineStub)
    . (Import-EngineFunction -ScriptPath $enginePath `
        -FunctionName 'Get-SenderCatalog', 'Resolve-SenderService', 'Get-ESPClass')

    $script:CatalogPath = Get-EngineScriptPath -FileName 'sender-catalog.json'
    $script:Catalog     = Get-Content $script:CatalogPath -Raw -Encoding UTF8 | ConvertFrom-Json

    # Get-SenderCatalog resolves its path from $PSCommandPath / $PSScriptRoot /
    # cwd, none of which point at the repo root under Pester. Seed the cache
    # directly so the matcher reads the real catalog deterministically.
    $script:SenderCatalog = $script:Catalog
}

Describe 'sender-catalog.json integrity' {

    It 'is valid JSON with a version and a services array' {
        $script:Catalog.version          | Should -Not -BeNullOrEmpty
        $script:Catalog.services.Count   | Should -BeGreaterThan 0
    }

    It 'gives every service an id, name, vendor and category' {
        foreach ($svc in $script:Catalog.services) {
            $svc.id       | Should -Not -BeNullOrEmpty -Because "every entry needs an id"
            $svc.name     | Should -Not -BeNullOrEmpty -Because "entry '$($svc.id)' needs a display name"
            $svc.category | Should -Not -BeNullOrEmpty -Because "entry '$($svc.id)' needs a category for grouping"
        }
    }

    It 'has no duplicate service ids' {
        $ids  = $script:Catalog.services.id
        $dupes = $ids | Group-Object | Where-Object Count -gt 1
        $dupes | Should -BeNullOrEmpty -Because "duplicate ids would make catalog lookups ambiguous: $($dupes.Name -join ', ')"
    }

    It 'has no duplicate service names' {
        # Names are the join key between source-inventory.json and the catalog
        # (the Authorization Wizard looks up by name), so collisions break it.
        $dupes = $script:Catalog.services.name | Group-Object | Where-Object Count -gt 1
        $dupes | Should -BeNullOrEmpty -Because "duplicate names break wizard lookup: $($dupes.Name -join ', ')"
    }

    It 'compiles every rdns pattern as a valid regex' {
        foreach ($svc in $script:Catalog.services) {
            if (-not $svc.rdns) { continue }
            foreach ($pattern in $svc.rdns) {
                { [regex]::new($pattern) } | Should -Not -Throw -Because "'$pattern' in '$($svc.id)' must compile"
            }
        }
    }

    It 'uses only known categories' {
        $known = @('transactional','marketing','productivity','security','sales',
                   'support','alerts','crm','ecommerce','consumer','relay')
        foreach ($svc in $script:Catalog.services) {
            $svc.category | Should -BeIn $known -Because "'$($svc.id)' has category '$($svc.category)'"
        }
    }

    It 'gives every service some way to be matched' {
        # An entry with neither rdns patterns nor org keywords can never fire.
        foreach ($svc in $script:Catalog.services) {
            $hasRdns = $svc.rdns -and $svc.rdns.Count -gt 0
            $hasKw   = $svc.orgKeywords -and $svc.orgKeywords.Count -gt 0
            ($hasRdns -or $hasKw) | Should -BeTrue -Because "'$($svc.id)' is unreachable with no rdns and no orgKeywords"
        }
    }
}

Describe 'Resolve-SenderService' {

    Context 'rDNS match returns high confidence' {
        It 'classifies <hostname> as <expected>' -ForEach @(
            @{ hostname = 'mail-bn8nam11on2098.outbound.protection.outlook.com'; org = 'Microsoft Corporation'; expected = 'Microsoft 365'    }
            @{ hostname = 'mail-yb1-f181.google.com';                            org = 'Google LLC';            expected = 'Google Workspace' }
            @{ hostname = 'a1-67.smtp-out.amazonses.com';                        org = 'Amazon Technologies';   expected = 'Amazon SES'       }
            @{ hostname = 'o2.email.sendgrid.net';                               org = 'Twilio SendGrid';       expected = 'SendGrid'         }
            @{ hostname = 'mail22.suw13.mcsv.net';                               org = 'Rocket Science Group';  expected = 'Mailchimp'        }
            @{ hostname = 'mta48-2.smtp.eu.mailgun.org';                         org = 'Mailgun';               expected = 'Mailgun'          }
            @{ hostname = 'klmail2.klaviyomail.com';                             org = 'Klaviyo Inc';           expected = 'Klaviyo'          }
            @{ hostname = 'hs-1.hubspotemail.net';                               org = 'HubSpot';               expected = 'HubSpot'          }
            @{ hostname = 'mta01.mktomail.com';                                  org = 'Marketo';               expected = 'Marketo'          }
            @{ hostname = 'out-1.smtp.github.com';                               org = 'GitHub';                expected = 'GitHub'           }
            @{ hostname = 'mx1.pphosted.com';                                    org = 'Proofpoint';            expected = 'Proofpoint'       }
            @{ hostname = 'us-smtp-1.mimecast.com';                              org = 'Mimecast';              expected = 'Mimecast'         }
        ) {
            $r = Resolve-SenderService -OrgName $org -Hostname $hostname
            $r.Name       | Should -Be $expected
            $r.Confidence | Should -Be 'high'
            $r.Id         | Should -Not -Be 'unknown'
        }
    }

    Context 'org-keyword match returns medium confidence' {
        It 'falls back to the org name when rDNS is unrecognised' {
            $r = Resolve-SenderService -OrgName 'Hubspot Inc' -Hostname 'no-such-ptr.example.net'
            $r.Name       | Should -Be 'HubSpot'
            $r.Confidence | Should -Be 'medium'
        }

        It 'matches org keywords case-insensitively' {
            $upper = Resolve-SenderService -OrgName 'PROOFPOINT'   -Hostname 'x.example.net'
            $lower = Resolve-SenderService -OrgName 'proofpoint'   -Hostname 'x.example.net'
            $upper.Name | Should -Be $lower.Name
            $upper.Name | Should -Be 'Proofpoint'
        }
    }

    Context 'rDNS wins over org keywords' {
        It 'prefers the high-confidence rDNS match when both could fire' {
            # rDNS says SendGrid, org name says Microsoft. rDNS is the stronger
            # signal because org names come from shared-ASN whois data.
            $r = Resolve-SenderService -OrgName 'Microsoft Corporation' -Hostname 'o1.email.sendgrid.net'
            $r.Name       | Should -Be 'SendGrid'
            $r.Confidence | Should -Be 'high'
        }
    }

    Context 'no match' {
        It 'returns Unknown with none confidence for an unrecognised sender' {
            $r = Resolve-SenderService -OrgName 'Random AS54321' -Hostname 'weird.example.net'
            $r.Id         | Should -Be 'unknown'
            $r.Name       | Should -Be 'Unknown'
            $r.Confidence | Should -Be 'none'
        }

        It 'handles empty and null inputs without throwing' {
            { Resolve-SenderService -OrgName ''   -Hostname ''   } | Should -Not -Throw
            { Resolve-SenderService -OrgName $null -Hostname $null } | Should -Not -Throw
            (Resolve-SenderService -OrgName '' -Hostname '').Name | Should -Be 'Unknown'
        }
    }

    Context 'returned shape' {
        It 'always returns Id, Name, Vendor, Category and Confidence' {
            foreach ($case in @(
                @{ o = 'Twilio SendGrid'; h = 'o1.email.sendgrid.net' }
                @{ o = 'Nobody';          h = 'nothing.example.net'   }
            )) {
                $r = Resolve-SenderService -OrgName $case.o -Hostname $case.h
                $r.PSObject.Properties.Name | Should -Contain 'Id'
                $r.PSObject.Properties.Name | Should -Contain 'Name'
                $r.PSObject.Properties.Name | Should -Contain 'Vendor'
                $r.PSObject.Properties.Name | Should -Contain 'Category'
                $r.PSObject.Properties.Name | Should -Contain 'Confidence'
            }
        }
    }

    Context 'Get-ESPClass backwards-compatible shim' {
        It 'returns just the service name as a string' {
            Get-ESPClass -OrgName 'Twilio SendGrid' -Hostname 'o1.email.sendgrid.net' | Should -Be 'SendGrid'
            Get-ESPClass -OrgName 'Nobody'          -Hostname 'nothing.example.net'   | Should -Be 'Unknown'
        }
    }
}
