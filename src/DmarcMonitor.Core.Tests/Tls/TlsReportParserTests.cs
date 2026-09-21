using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Core.Tests.Tls;

/// <summary>
/// Parsing TLS-RPT reports (RFC 8460).
///
/// Anchored on two real reports, from Google and Microsoft, for
/// nrgtechservices.com. They already disagree in shape: Google sends mx-host,
/// Microsoft omits it. That disagreement is the whole reason to test against
/// real files rather than the RFC's examples.
/// </summary>
public sealed class TlsReportParserTests
{
    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    // ---- the real reports ---------------------------------------------------

    [Fact]
    public void ParsesTheGoogleReport()
    {
        var result = TlsReportParser.Parse(Fixture("google-tlsrpt.json"));

        Assert.True(result.Success, result.Error);
        var report = result.Report!;
        Assert.Equal("Google Inc.", report.OrganizationName);
        Assert.Equal("smtp-tls-reporting@google.com", report.ContactInfo);
        Assert.Equal(28, report.SuccessfulSessions);
        Assert.Equal(0, report.FailedSessions);
        Assert.False(report.HasFailures);
    }

    [Fact]
    public void ParsesTheMicrosoftReport()
    {
        var result = TlsReportParser.Parse(Fixture("microsoft-tlsrpt.json"));

        Assert.True(result.Success, result.Error);
        var report = result.Report!;
        Assert.Equal("Microsoft Corporation", report.OrganizationName);
        Assert.Equal(57, report.SuccessfulSessions);
        Assert.Equal(0, report.FailedSessions);
    }

    [Fact]
    public void ReadsMxHostWhenPresentAndCopesWhenAbsent()
    {
        // Google sends mx-host as an array. Microsoft omits it entirely.
        // Neither should be an error, and the absent one must not become a
        // list containing an empty string.
        var google = TlsReportParser.Parse(Fixture("google-tlsrpt.json")).Report!;
        var microsoft = TlsReportParser.Parse(Fixture("microsoft-tlsrpt.json")).Report!;

        Assert.Equal(
            "nrgtechservices-com.mail.protection.outlook.com",
            Assert.Single(google.Policies[0].Policy.MxHosts));
        Assert.Empty(microsoft.Policies[0].Policy.MxHosts);
    }

    [Theory]
    [InlineData("google-tlsrpt.json")]
    [InlineData("microsoft-tlsrpt.json")]
    public void ReadsTheMtaStsModeOutOfThePolicyString(string fixture)
    {
        // The field that matters and that nothing surfaces. Both of these
        // report mode: testing, which means failures are reported and then
        // the mail is delivered over plaintext anyway.
        var report = TlsReportParser.Parse(Fixture(fixture)).Report!;
        var policy = report.Policies[0].Policy;

        Assert.Equal(TlsPolicyType.Sts, policy.Type);
        Assert.Equal(MtaStsMode.Testing, policy.Mode);
        Assert.False(policy.IsEnforcing);
    }

    [Theory]
    [InlineData("google-tlsrpt.json")]
    [InlineData("microsoft-tlsrpt.json")]
    public void AttributesTheReportToTheRightDomain(string fixture)
    {
        var report = TlsReportParser.Parse(Fixture(fixture)).Report!;
        Assert.Equal("nrgtechservices.com", report.Policies[0].Policy.Domain);
    }

    [Theory]
    [InlineData("google-tlsrpt.json")]
    [InlineData("microsoft-tlsrpt.json")]
    public void ParsesTheIso8601DateRange(string fixture)
    {
        var report = TlsReportParser.Parse(Fixture(fixture)).Report!;

        Assert.Equal(new DateTimeOffset(2026, 9, 15, 0, 0, 0, TimeSpan.Zero), report.Begin);
        Assert.True(report.End > report.Begin);
    }

    [Theory]
    [InlineData("google-tlsrpt.json")]
    [InlineData("microsoft-tlsrpt.json")]
    public void ReportsNoFailureDetailWhenThereWereNoFailures(string fixture)
    {
        // failure-details is absent entirely when nothing failed, which must
        // read as "nothing failed" rather than as a malformed report.
        var report = TlsReportParser.Parse(Fixture(fixture)).Report!;
        Assert.Empty(report.Policies[0].Failures);
    }

    // ---- enforcement mode ---------------------------------------------------

    [Theory]
    [InlineData("enforce", MtaStsMode.Enforce)]
    [InlineData("testing", MtaStsMode.Testing)]
    [InlineData("none", MtaStsMode.None)]
    [InlineData("ENFORCE", MtaStsMode.Enforce)]
    [InlineData(" testing ", MtaStsMode.Testing)]
    public void ReadsEveryDefinedMode(string mode, MtaStsMode expected)
    {
        var json = $$$"""
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com",
                "policy-string":["version: STSv1","mode: {{{mode}}}","max_age: 86400"]},
               "summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}
            """;
        Assert.Equal(expected, TlsReportParser.Parse(json).Report!.Policies[0].Policy.Mode);
    }

    [Fact]
    public void OnlyEnforceModeCountsAsEnforcing()
    {
        // Testing mode generates clean reports while protecting nothing. A
        // domain can sit there for years believing it is covered.
        foreach (var mode in new[] { "testing", "none" })
        {
            var json = $$$"""
                {"organization-name":"x","report-id":"1","policies":[
                  {"policy":{"policy-type":"sts","policy-domain":"acme.com",
                    "policy-string":["mode: {{{mode}}}"]},
                   "summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}
                """;
            Assert.False(TlsReportParser.Parse(json).Report!.Policies[0].Policy.IsEnforcing);
        }
    }

    [Fact]
    public void ReportsAnUnknownModeRatherThanGuessingAtOne()
    {
        const string json = """
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com","policy-string":["version: STSv1"]},
               "summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}
            """;
        Assert.Equal(MtaStsMode.Unknown, TlsReportParser.Parse(json).Report!.Policies[0].Policy.Mode);
    }

    // ---- failures -----------------------------------------------------------

    [Fact]
    public void ParsesFailureDetail()
    {
        const string json = """
            {"organization-name":"Example","report-id":"1",
             "date-range":{"start-datetime":"2026-09-15T00:00:00Z","end-datetime":"2026-09-15T23:59:59Z"},
             "policies":[{"policy":{"policy-type":"sts","policy-domain":"acme.com","policy-string":["mode: enforce"]},
               "summary":{"total-successful-session-count":100,"total-failure-session-count":7},
               "failure-details":[{
                 "result-type":"starttls-not-supported",
                 "sending-mta-ip":"203.0.113.9",
                 "receiving-mx-hostname":"mx.acme.com",
                 "receiving-ip":"198.51.100.4",
                 "failed-session-count":7,
                 "additional-information":"https://example.com/more"}]}]}
            """;

        var report = TlsReportParser.Parse(json).Report!;
        var f = Assert.Single(report.Policies[0].Failures);

        Assert.Equal(TlsFailureType.StartTlsNotSupported, f.ResultType);
        Assert.Equal("203.0.113.9", f.SendingMtaIp);
        Assert.Equal(7, f.FailedSessionCount);
        Assert.True(report.HasFailures);
    }

    [Theory]
    [InlineData("starttls-not-supported", true)]
    [InlineData("certificate-host-mismatch", true)]
    [InlineData("validation-failure", true)]
    [InlineData("certificate-expired", false)]
    [InlineData("certificate-not-trusted", false)]
    public void DistinguishesInterceptionFromForgettingToRenew(string resultType, bool suspicious)
    {
        // STARTTLS being stripped is what an active downgrade looks like. An
        // expired certificate is somebody missing a renewal. Both need
        // fixing; only one is worth waking somebody for, and a report that
        // treats them identically trains people to ignore it.
        var json = $$$"""
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com","policy-string":["mode: enforce"]},
               "summary":{"total-successful-session-count":0,"total-failure-session-count":1},
               "failure-details":[{"result-type":"{{{resultType}}}","failed-session-count":1}]}]}
            """;

        var f = TlsReportParser.Parse(json).Report!.Policies[0].Failures[0];
        Assert.Equal(suspicious, f.SuggestsInterception);
    }

    [Fact]
    public void KeepsAnUnrecognizedResultTypeVerbatim()
    {
        // A value the RFC does not define must not be silently discarded:
        // it is still the only description of what went wrong.
        const string json = """
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com","policy-string":["mode: enforce"]},
               "summary":{"total-successful-session-count":0,"total-failure-session-count":1},
               "failure-details":[{"result-type":"something-new","failed-session-count":1}]}]}
            """;

        var f = TlsReportParser.Parse(json).Report!.Policies[0].Failures[0];
        Assert.Equal(TlsFailureType.Unknown, f.ResultType);
        Assert.Equal("something-new", f.RawResultType);
    }

    // ---- shape variance -----------------------------------------------------

    [Fact]
    public void AcceptsMxHostAsABareStringAsWellAsAnArray()
    {
        const string json = """
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com","mx-host":"mx.acme.com",
                "policy-string":["mode: enforce"]},
               "summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}
            """;
        Assert.Equal("mx.acme.com", Assert.Single(TlsReportParser.Parse(json).Report!.Policies[0].Policy.MxHosts));
    }

    [Fact]
    public void AcceptsAQuotedSessionCount()
    {
        // A count read as zero would report a failing domain as having sent
        // no mail at all.
        const string json = """
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com","policy-string":["mode: enforce"]},
               "summary":{"total-successful-session-count":"42","total-failure-session-count":"3"}}]}
            """;
        var report = TlsReportParser.Parse(json).Report!;
        Assert.Equal(42, report.SuccessfulSessions);
        Assert.Equal(3, report.FailedSessions);
    }

    [Fact]
    public void SumsAcrossSeveralPolicies()
    {
        const string json = """
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com","policy-string":["mode: enforce"]},
               "summary":{"total-successful-session-count":10,"total-failure-session-count":1}},
              {"policy":{"policy-type":"tlsa","policy-domain":"acme.com"},
               "summary":{"total-successful-session-count":5,"total-failure-session-count":2}}]}
            """;
        var report = TlsReportParser.Parse(json).Report!;
        Assert.Equal(15, report.SuccessfulSessions);
        Assert.Equal(3, report.FailedSessions);
        Assert.Equal(18, report.TotalSessions);
    }

    [Fact]
    public void ReadsTheOtherPolicyTypes()
    {
        const string json = """
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"tlsa","policy-domain":"acme.com"},
               "summary":{"total-successful-session-count":1,"total-failure-session-count":0}},
              {"policy":{"policy-type":"no-policy-found","policy-domain":"acme.com"},
               "summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}
            """;
        var policies = TlsReportParser.Parse(json).Report!.Policies;
        Assert.Equal(TlsPolicyType.Tlsa, policies[0].Policy.Type);
        Assert.Equal(TlsPolicyType.NoPolicyFound, policies[1].Policy.Type);
    }

    [Fact]
    public void ReportsZeroSuccessRateForNoSessionsRatherThanDividingByZero()
    {
        const string json = """
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com"},
               "summary":{"total-successful-session-count":0,"total-failure-session-count":0}}]}
            """;
        var report = TlsReportParser.Parse(json).Report!;
        Assert.Equal(0, report.TotalSessions);
        Assert.Equal(0, report.SuccessRate);
    }

    [Fact]
    public void ComputesSuccessRate()
    {
        const string json = """
            {"organization-name":"x","report-id":"1","policies":[
              {"policy":{"policy-type":"sts","policy-domain":"acme.com"},
               "summary":{"total-successful-session-count":75,"total-failure-session-count":25}}]}
            """;
        Assert.Equal(75.0, TlsReportParser.Parse(json).Report!.SuccessRate);
    }

    // ---- bad input ----------------------------------------------------------

    [Fact]
    public void ReportsUnreadableJsonAsAFailureRatherThanAnEmptyReport()
    {
        var result = TlsReportParser.Parse("{\"organization-name\": ");
        Assert.False(result.Success);
        Assert.NotEmpty(result.Error);
    }

    [Fact]
    public void RejectsJsonThatIsNotATlsReport()
    {
        var result = TlsReportParser.Parse("""{"hello":"world"}""");
        Assert.False(result.Success);
        Assert.Contains("policies", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsATopLevelArray()
    {
        Assert.False(TlsReportParser.Parse("[1,2,3]").Success);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void RejectsEmptyInput(string json) => Assert.False(TlsReportParser.Parse(json).Success);

    [Fact]
    public void NeverThrowsWhateverItIsGiven()
    {
        // One malformed report must not stop a run working through a backlog.
        string[] nasty =
        [
            "{", "null", "\"just a string\"", "{\"policies\":\"not an array\"}",
            "{\"policies\":[null,1,\"x\"]}",
            "{\"policies\":[{\"summary\":{\"total-successful-session-count\":null}}]}",
            new string('[', 500),
        ];

        foreach (var input in nasty)
        {
            Assert.Null(Record.Exception(() => TlsReportParser.Parse(input)));
        }
    }

    [Fact]
    public void RefusesJsonNestedDeeplyEnoughToBeAnAttack()
    {
        var bomb = new string('[', 5000) + new string(']', 5000);
        var result = TlsReportParser.Parse(bomb);
        Assert.False(result.Success);
    }
}
