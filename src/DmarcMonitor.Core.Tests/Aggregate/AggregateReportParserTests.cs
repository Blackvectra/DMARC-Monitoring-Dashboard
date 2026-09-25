using DmarcMonitor.Core.Aggregate;

namespace DmarcMonitor.Core.Tests.Aggregate;

/// <summary>
/// Parsing real DMARC aggregate reports.
///
/// The prototype's parser was tested against XML written to match what the
/// parser expected, which proves very little. These tests are shaped around
/// how reports actually differ in the wild: missing optional elements,
/// namespaces, mixed case, multiple auth results, and hostile input, since
/// this XML arrives by email from anyone on the internet.
/// </summary>
public sealed class AggregateReportParserTests
{
    /// <summary>A report in the shape Google sends: complete, namespaced-free, epoch dates.</summary>
    private const string GoogleStyle = """
        <?xml version="1.0" encoding="UTF-8" ?>
        <feedback>
          <report_metadata>
            <org_name>google.com</org_name>
            <email>noreply-dmarc-support@google.com</email>
            <report_id>11748228325368922143</report_id>
            <date_range><begin>1772236800</begin><end>1772323199</end></date_range>
          </report_metadata>
          <policy_published>
            <domain>acme.com</domain>
            <adkim>r</adkim><aspf>r</aspf>
            <p>quarantine</p><sp>quarantine</sp><pct>100</pct>
          </policy_published>
          <record>
            <row>
              <source_ip>40.107.1.1</source_ip>
              <count>12400</count>
              <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
            </row>
            <identifiers><header_from>acme.com</header_from></identifiers>
            <auth_results>
              <dkim><domain>acme.com</domain><result>pass</result><selector>selector1</selector></dkim>
              <spf><domain>acme.com</domain><result>pass</result></spf>
            </auth_results>
          </record>
          <record>
            <row>
              <source_ip>149.72.40.10</source_ip>
              <count>3120</count>
              <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
            </row>
            <identifiers><header_from>acme.com</header_from></identifiers>
            <auth_results>
              <spf><domain>bounce.sendgrid.net</domain><result>pass</result></spf>
            </auth_results>
          </record>
        </feedback>
        """;

    [Fact]
    public void ParsesACompleteReport()
    {
        var result = AggregateReportParser.Parse(GoogleStyle);

        Assert.True(result.Success, result.Error);
        var report = result.Report!;
        Assert.Equal("google.com", report.Metadata.OrgName);
        Assert.Equal("11748228325368922143", report.Metadata.ReportId);
        Assert.Equal("acme.com", report.Policy.Domain);
        Assert.Equal(DmarcPolicy.Quarantine, report.Policy.P);
        Assert.Equal(2, report.Records.Count);
    }

    [Fact]
    public void SumsMessageCountsRatherThanCountingRows()
    {
        // One row routinely stands for thousands of messages.
        var report = AggregateReportParser.Parse(GoogleStyle).Report!;
        Assert.Equal(15520, report.TotalMessages);
        Assert.Equal(12400, report.PassingMessages);
        Assert.Equal(3120, report.FailingMessages);
    }

    [Fact]
    public void KeepsAuthenticationSeparateFromAlignment()
    {
        // The whole point. SPF authenticated for bounce.sendgrid.net, so the
        // raw result is a pass, but it did not align with acme.com so DMARC
        // recorded a failure. A parser that collapses these loses the only
        // information that explains the contradiction to an operator.
        var report = AggregateReportParser.Parse(GoogleStyle).Report!;
        var sendgrid = report.Records[1];

        Assert.Equal(DmarcResult.Fail, sendgrid.Spf);
        Assert.False(sendgrid.IsDmarcPass);

        var raw = Assert.Single(sendgrid.SpfResults);
        Assert.Equal("bounce.sendgrid.net", raw.Domain);
        Assert.True(raw.IsPass);
    }

    [Fact]
    public void ParsesEpochDateRange()
    {
        var report = AggregateReportParser.Parse(GoogleStyle).Report!;
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1772236800), report.Metadata.Begin);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1772323199), report.Metadata.End);
    }

    // ---- real-world variation ----------------------------------------------

    [Fact]
    public void ParsesAReportThatUsesADefaultNamespace()
    {
        // Matching on fully-qualified names would silently find nothing here,
        // and the receiver's entire view of the domain would vanish.
        const string xml = """
            <?xml version="1.0"?>
            <feedback xmlns="http://dmarc.org/dmarc-xml/0.1">
              <report_metadata><org_name>example.net</org_name><report_id>abc</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
              <record>
                <row><source_ip>203.0.113.1</source_ip><count>5</count>
                  <policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
              </record>
            </feedback>
            """;

        var result = AggregateReportParser.Parse(xml);
        Assert.True(result.Success, result.Error);
        Assert.Equal("acme.com", result.Report!.Policy.Domain);
        Assert.Single(result.Report.Records);
    }

    [Fact]
    public void ParsesAMinimalReportFromASmallReceiver()
    {
        // No email, no date range, no identifiers, no auth_results, no pct.
        const string xml = """
            <feedback>
              <report_metadata><org_name>tiny.example</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
              <record>
                <row><source_ip>198.51.100.7</source_ip><count>3</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
              </record>
            </feedback>
            """;

        var result = AggregateReportParser.Parse(xml);
        Assert.True(result.Success, result.Error);
        var rec = Assert.Single(result.Report!.Records);
        Assert.Equal("198.51.100.7", rec.SourceIp);
        Assert.Empty(rec.SpfResults);
        Assert.Equal("", rec.HeaderFrom);
    }

    /// <summary>
    /// A row whose address is not an address is dropped, like one with none.
    /// </summary>
    /// <remarks>
    /// Anybody can mail a report to an rua address, and the source address
    /// is what every page, the client report and the indicator export hang
    /// off. Stored as typed, "0.0.0.0/0" reached the file a firewall reads.
    /// </remarks>
    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("203.0.113.9&#10;198.51.100.1")]
    [InlineData("127.1")]
    [InlineData("010.0.0.1")]
    [InlineData("256.1.1.1")]
    [InlineData("fe80::1%eth0")]
    [InlineData("mail.example.com")]
    public void DropsARowWhoseAddressIsNotAnAddress(string sourceIp)
    {
        var xml = $"""
            <feedback>
              <report_metadata><org_name>tiny.example</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
              <record>
                <row><source_ip>{sourceIp}</source_ip><count>3</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
              </record>
              <record>
                <row><source_ip>198.51.100.7</source_ip><count>2</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
              </record>
            </feedback>
            """;

        var result = AggregateReportParser.Parse(xml);

        Assert.True(result.Success, result.Error);
        Assert.Equal("198.51.100.7", Assert.Single(result.Report!.Records).SourceIp);
    }

    [Theory]
    [InlineData("198.51.100.7")]
    [InlineData("2a01:111:f403:c112::5")]
    [InlineData("2603:10B6:408:10A::22")]
    [InlineData("::ffff:35.174.145.124")]
    public void KeepsEveryFormAReceiverActuallyWrites(string sourceIp)
    {
        Assert.True(IpText.TryParse(sourceIp, out _));
    }

    [Fact]
    public void DefaultsPctTo100WhenAbsent()
    {
        const string xml = """
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>reject</p></policy_published>
            </feedback>
            """;
        Assert.Equal(100, AggregateReportParser.Parse(xml).Report!.Policy.Pct);
    }

    [Fact]
    public void DistinguishesAbsentSpFromExplicitSpNone()
    {
        // Absent means subdomains inherit p. Explicit sp=none means they are
        // deliberately unprotected. Opposite meanings, so they are kept apart.
        const string withoutSp = """
            <feedback><report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
            <policy_published><domain>acme.com</domain><p>reject</p></policy_published></feedback>
            """;
        const string withSpNone = """
            <feedback><report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
            <policy_published><domain>acme.com</domain><p>reject</p><sp>none</sp></policy_published></feedback>
            """;

        Assert.Null(AggregateReportParser.Parse(withoutSp).Report!.Policy.Sp);
        Assert.Equal(DmarcPolicy.None, AggregateReportParser.Parse(withSpNone).Report!.Policy.Sp);
    }

    [Theory]
    [InlineData("PASS")]
    [InlineData("Pass")]
    [InlineData(" pass ")]
    public void TreatsResultCaseAndWhitespaceInsensitively(string value)
    {
        var xml = $"""
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
              <record><row><source_ip>1.2.3.4</source_ip><count>1</count>
                <policy_evaluated><dkim>{value}</dkim><spf>fail</spf></policy_evaluated></row></record>
            </feedback>
            """;
        Assert.Equal(DmarcResult.Pass, AggregateReportParser.Parse(xml).Report!.Records[0].Dkim);
    }

    [Theory]
    [InlineData("")]
    [InlineData("unknown")]
    [InlineData("softfail")]
    [InlineData("neutral")]
    public void TreatsAnythingThatIsNotAPassAsAFailure(string value)
    {
        // Counting a blank or unrecognized alignment result as a pass would
        // inflate the headline figure an operator repeats to other people.
        var xml = $"""
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
              <record><row><source_ip>1.2.3.4</source_ip><count>10</count>
                <policy_evaluated><dkim>{value}</dkim><spf>{value}</spf></policy_evaluated></row></record>
            </feedback>
            """;
        var rec = AggregateReportParser.Parse(xml).Report!.Records[0];
        Assert.False(rec.IsDmarcPass);
    }

    [Fact]
    public void ParsesMultipleAuthResultsOfTheSameKind()
    {
        // A message can carry several DKIM signatures. Keeping only the first
        // is how a multi-signature ESP gets misreported.
        const string xml = """
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
              <record>
                <row><source_ip>1.2.3.4</source_ip><count>1</count>
                  <policy_evaluated><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
                <auth_results>
                  <dkim><domain>acme.com</domain><result>pass</result><selector>s1</selector></dkim>
                  <dkim><domain>mailchimp.com</domain><result>pass</result><selector>k1</selector></dkim>
                </auth_results>
              </record>
            </feedback>
            """;
        var rec = AggregateReportParser.Parse(xml).Report!.Records[0];
        Assert.Equal(2, rec.DkimResults.Count);
        Assert.Contains(rec.DkimResults, r => r.Domain == "mailchimp.com");
    }

    [Fact]
    public void ParsesPolicyOverrides()
    {
        const string xml = """
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>reject</p></policy_published>
              <record>
                <row><source_ip>1.2.3.4</source_ip><count>88</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
                    <reason><type>mailing_list</type><comment>list detected</comment></reason>
                  </policy_evaluated></row>
              </record>
            </feedback>
            """;
        var rec = AggregateReportParser.Parse(xml).Report!.Records[0];
        Assert.True(rec.WasOverridden);
        Assert.Equal(OverrideReason.MailingList, rec.Overrides[0].Type);
    }

    [Fact]
    public void KeepsAnUnrecognizedOverrideTypeRatherThanFailing()
    {
        const string xml = """
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>reject</p></policy_published>
              <record><row><source_ip>1.2.3.4</source_ip><count>1</count>
                <policy_evaluated><dkim>fail</dkim><spf>fail</spf>
                  <reason><type>something_new</type></reason></policy_evaluated></row></record>
            </feedback>
            """;
        var rec = AggregateReportParser.Parse(xml).Report!.Records[0];
        Assert.Equal(OverrideReason.Unknown, rec.Overrides[0].Type);
        Assert.True(rec.WasOverridden);
    }

    // ---- bad input ----------------------------------------------------------

    [Fact]
    public void ReportsAnUnparseableReportAsAFailureRatherThanAnEmptyOne()
    {
        // Empty and unreadable mean opposite things to an operator: one is
        // "no mail was seen", the other is "we could not read this".
        var result = AggregateReportParser.Parse("<feedback><unclosed>");
        Assert.False(result.Success);
        Assert.NotEmpty(result.Error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void RejectsEmptyInput(string xml)
    {
        Assert.False(AggregateReportParser.Parse(xml).Success);
    }

    [Fact]
    public void RejectsXmlThatIsNotADmarcReport()
    {
        var result = AggregateReportParser.Parse("<html><body>hello</body></html>");
        Assert.False(result.Success);
        Assert.Contains("not a DMARC aggregate report", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsAReportWithNoDomainToAttributeItTo()
    {
        const string xml = """
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><p>none</p></policy_published>
            </feedback>
            """;
        Assert.False(AggregateReportParser.Parse(xml).Success);
    }

    [Fact]
    public void DropsARowWithNoSourceIp()
    {
        // Mail from nowhere cannot be attributed, acted on or explained.
        const string xml = """
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
              <record><row><count>5</count><policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record>
              <record><row><source_ip>1.2.3.4</source_ip><count>7</count>
                <policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record>
            </feedback>
            """;
        var report = AggregateReportParser.Parse(xml).Report!;
        Assert.Single(report.Records);
        Assert.Equal(7, report.TotalMessages);
    }

    [Theory]
    [InlineData("not-a-number")]
    [InlineData("")]
    [InlineData("-500")]
    public void NeverLetsAMalformedCountCorruptTheTotal(string count)
    {
        var xml = $"""
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
              <record><row><source_ip>1.1.1.1</source_ip><count>{count}</count>
                <policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record>
              <record><row><source_ip>2.2.2.2</source_ip><count>100</count>
                <policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record>
            </feedback>
            """;
        Assert.Equal(100, AggregateReportParser.Parse(xml).Report!.TotalMessages);
    }

    [Fact]
    public void ClampsAnOutOfRangePct()
    {
        const string xml = """
            <feedback>
              <report_metadata><org_name>x</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>reject</p><pct>500</pct></policy_published>
            </feedback>
            """;
        Assert.Equal(100, AggregateReportParser.Parse(xml).Report!.Policy.Pct);
    }

    // ---- hostile input ------------------------------------------------------
    // This XML arrives as an email attachment from anyone on the internet.

    [Fact]
    public void RefusesAnExternalEntityRatherThanReadingLocalFiles()
    {
        // Classic XXE. With DTD processing left on, this reads /etc/passwd
        // into the report. The PowerShell prototype used a bare [xml] cast,
        // which does not prohibit this.
        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE feedback [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <feedback>
              <report_metadata><org_name>&xxe;</org_name><report_id>1</report_id></report_metadata>
              <policy_published><domain>acme.com</domain><p>none</p></policy_published>
            </feedback>
            """;

        var result = AggregateReportParser.Parse(xxe);

        Assert.False(result.Success);
        Assert.DoesNotContain("root:", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesAnEntityExpansionBomb()
    {
        // A few hundred bytes that expand to gigabytes and hang the process.
        const string bomb = """
            <?xml version="1.0"?>
            <!DOCTYPE feedback [
              <!ENTITY a "aaaaaaaaaa">
              <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
              <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
              <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
            ]>
            <feedback><report_metadata><org_name>&d;</org_name></report_metadata></feedback>
            """;

        var result = AggregateReportParser.Parse(bomb);
        Assert.False(result.Success);
    }

    [Fact]
    public void NeverThrowsWhateverItIsGiven()
    {
        // A single malformed report must not take down a run that is working
        // through a backlog of thousands.
        string[] nasty =
        [
            "<feedback>", "not xml at all", "<?xml version='1.0'?>", "\0\0\0",
            "<feedback><record><row><source_ip></source_ip></row></record></feedback>",
            new string('<', 10000),
        ];

        foreach (var input in nasty)
        {
            var ex = Record.Exception(() => AggregateReportParser.Parse(input));
            Assert.Null(ex);
        }
    }
}
