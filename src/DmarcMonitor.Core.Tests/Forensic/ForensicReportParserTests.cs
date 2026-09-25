using DmarcMonitor.Core.Forensic;
using Xunit;

namespace DmarcMonitor.Core.Tests.Forensic;

/// <summary>
/// Reading a DMARC failure report, RFC 6591.
///
/// The report type the product could not read at all, and the only one that is
/// an email rather than a document. So these tests are mostly about the shapes
/// real mail arrives in - folded header lines, comments in the middle of a
/// value, a receiver that sent the whole original message - and about the one
/// rule that is not a parsing rule: the body of the reported message is
/// dropped here, and nothing downstream is given the chance to store it.
/// </summary>
public sealed class ForensicReportParserTests
{
    /// <summary>
    /// A complete report, in the shape a receiver really sends one.
    /// </summary>
    /// <remarks>
    /// Three parts under a multipart/report boundary: something a person can
    /// read, the feedback fields, and the message that failed.
    /// </remarks>
    private const string Sample = """
        From: dmarc-reports@receiver.example
        To: dmarc@nrgtechservices.com
        Subject: FW: Auth Failure Report for ndaco.org
        Date: Tue, 15 Sep 2026 09:14:33 +0000
        MIME-Version: 1.0
        Content-Type: multipart/report; report-type=feedback-report;
        	boundary="pt-2609-1a"

        --pt-2609-1a
        Content-Type: text/plain; charset="US-ASCII"

        This is an authentication failure report for an email message
        received from IP 203.0.113.44 on Tue, 15 Sep 2026 09:12:02 +0000.

        --pt-2609-1a
        Content-Type: message/feedback-report

        Feedback-Type: auth-failure
        User-Agent: Receiver-Feedback/1.0
        Version: 1
        Original-Mail-From: <billing@ndaco.org>
        Original-Rcpt-To: <accounts@example.net>
        Arrival-Date: Tue, 15 Sep 2026 09:12:02 +0000
        Source-IP: 203.0.113.44
        Reported-Domain: ndaco.org
        Auth-Failure: dmarc
        Delivery-Result: reject
        Authentication-Results: mx.receiver.example;
        	dkim=fail (body hash did not verify) header.d=ndaco.org;
        	spf=fail smtp.mailfrom=ndaco.org;
        	dmarc=fail header.from=ndaco.org

        --pt-2609-1a
        Content-Type: message/rfc822

        From: "Accounts Payable" <billing@ndaco.org>
        To: accounts@example.net
        Subject: Updated remittance details
        Message-ID: <20260915091202.9f3a@ndaco.org>
        Date: Tue, 15 Sep 2026 09:12:00 +0000

        Please update our bank details before the next payment run.
        Account 12345678, sort code 00-00-00.
        --pt-2609-1a--
        """;

    [Fact]
    public void ReadsACompleteReport()
    {
        var parsed = ForensicReportParser.Parse(Sample);

        Assert.True(parsed.Success, parsed.Error);
        var report = parsed.Report!;

        Assert.Equal("ndaco.org", report.Domain);
        Assert.Equal("203.0.113.44", report.SourceIp);
        Assert.Equal("billing@ndaco.org", report.ReturnPath);
        Assert.Equal("\"Accounts Payable\" <billing@ndaco.org>", report.HeaderFrom);
        Assert.Equal("Updated remittance details", report.Subject);
        Assert.Equal("20260915091202.9f3a@ndaco.org", report.MessageId);
        Assert.Equal("dmarc", report.AuthFailureType);
        Assert.Equal("reject", report.DeliveryResult);
        Assert.Equal("Receiver-Feedback/1.0", report.ReportedBy);
        Assert.Equal(
            new DateTimeOffset(2026, 9, 15, 9, 12, 2, TimeSpan.Zero),
            report.ArrivalDate);
    }

    /// <summary>
    /// The one rule here that is not about parsing.
    /// </summary>
    /// <remarks>
    /// RFC 6591 lets a receiver attach the whole original message, and the
    /// sample's body is exactly the kind of thing that arrives in one: bank
    /// details, in a message somebody was trying to impersonate. Keeping a
    /// customer's correspondence on an MSP's server for thirty days because
    /// somebody published a ruf address is not a decision to make by accident,
    /// so the body never leaves this parser.
    /// </remarks>
    [Fact]
    public void TheBodyOfTheReportedMessageIsNeverKept()
    {
        var report = ForensicReportParser.Parse(Sample).Report!;

        Assert.Contains("Subject: Updated remittance details", report.ReportedHeaders, StringComparison.Ordinal);
        Assert.DoesNotContain("bank details", report.ReportedHeaders, StringComparison.Ordinal);
        Assert.DoesNotContain("12345678", report.ReportedHeaders, StringComparison.Ordinal);
    }

    /// <summary>
    /// Authentication-Results is folded across three lines and has a comment
    /// in the middle of the dkim result, both of which are ordinary.
    /// </summary>
    [Fact]
    public void ReadsAuthenticationResultsThroughFoldingAndComments()
    {
        var report = ForensicReportParser.Parse(Sample).Report!;

        Assert.Equal("fail", report.DkimResult);
        Assert.Equal("fail", report.SpfResult);
        Assert.Equal("ndaco.org", report.DkimDomain);
    }

    /// <summary>
    /// The difference between a finding and a reassurance.
    /// </summary>
    /// <remarks>
    /// The same forgery reported twice: once refused, once delivered. The
    /// second is somebody's inbox having received it, and the two must not
    /// read the same way.
    /// </remarks>
    [Theory]
    [InlineData("reject", false)]
    [InlineData("quarantine", false)]
    [InlineData("delivered", true)]
    [InlineData("none", true)]
    [InlineData("", true)]
    public void SaysWhetherTheForgeryReachedSomebody(string result, bool delivered)
    {
        var report = ForensicReportParser.Parse(
            Sample.Replace("Delivery-Result: reject", $"Delivery-Result: {result}", StringComparison.Ordinal)).Report!;

        Assert.Equal(delivered, report.WasDelivered);
    }

    /// <summary>
    /// A bare feedback part, which is what a mailbox export writes out rather
    /// than the whole message.
    /// </summary>
    [Fact]
    public void ReadsAFeedbackPartOnItsOwn()
    {
        var parsed = ForensicReportParser.Parse("""
            Feedback-Type: auth-failure
            User-Agent: Receiver-Feedback/1.0
            Version: 1
            Source-IP: 198.51.100.7
            Reported-Domain: dmvwrr.com
            Auth-Failure: spf
            """);

        Assert.True(parsed.Success, parsed.Error);
        Assert.Equal("dmvwrr.com", parsed.Report!.Domain);
        Assert.Equal("198.51.100.7", parsed.Report.SourceIp);
        Assert.Equal("spf", parsed.Report.AuthFailureType);
    }

    /// <summary>
    /// An abuse report is the same envelope carrying a different thing: a
    /// person at a large provider pressing "this is spam".
    /// </summary>
    /// <remarks>
    /// It arrives at the same mailbox and must not be filed as an
    /// authentication failure for the domain, which would have an operator
    /// investigating a forgery that nobody reported.
    /// </remarks>
    [Fact]
    public void AnAbuseReportIsNotAFailureReport()
    {
        var parsed = ForensicReportParser.Parse("""
            Feedback-Type: abuse
            User-Agent: SomeISP/1.0
            Version: 1
            Reported-Domain: ndaco.org
            """);

        Assert.False(parsed.Success);
        Assert.Contains("'abuse'", parsed.Error, StringComparison.Ordinal);
    }

    /// <summary>
    /// Falls back to the From address when the receiver did not name the
    /// domain, which some do not.
    /// </summary>
    [Fact]
    public void TakesTheDomainFromTheReportedMessageWhenItIsNotStated()
    {
        var report = ForensicReportParser.Parse(
            Sample.Replace("Reported-Domain: ndaco.org\n", "", StringComparison.Ordinal)).Report!;

        Assert.Equal("ndaco.org", report.Domain);
    }

    /// <summary>
    /// A report that names no domain is refused rather than filed somewhere.
    /// </summary>
    /// <remarks>
    /// These are filed per customer and they carry real subjects, so a guess
    /// that lands wrong is one client reading another client's mail. Refusing
    /// leaves it in the unrecognized folder for somebody to look at, which is
    /// the correct outcome for a report nobody can attribute.
    /// </remarks>
    [Fact]
    public void AReportThatNamesNoDomainIsRefused()
    {
        var parsed = ForensicReportParser.Parse("""
            Feedback-Type: auth-failure
            User-Agent: SomeISP/1.0
            Version: 1
            Source-IP: 198.51.100.7
            """);

        Assert.False(parsed.Success);
        Assert.Contains("does not say which domain", parsed.Error, StringComparison.Ordinal);
    }

    /// <summary>
    /// A day name that does not match the date does not cost the timestamp.
    /// </summary>
    /// <remarks>
    /// .NET rejects the whole value over the weekday, and the value is
    /// perfectly good: 15 September 2026 at 09:12:02 UTC is unambiguous and
    /// the day name is decoration the sender's own code got wrong. Losing it
    /// would have every report in the list read as having happened at the
    /// moment somebody imported it - which is how this was noticed, on two
    /// sample reports written by hand.
    /// </remarks>
    [Fact]
    public void AWrongDayNameDoesNotLoseTheArrivalTime()
    {
        // 15 September 2026 is a Tuesday.
        var report = ForensicReportParser.Parse(
            Sample.Replace("Arrival-Date: Tue, 15", "Arrival-Date: Sun, 15", StringComparison.Ordinal)).Report!;

        Assert.Equal(new DateTimeOffset(2026, 9, 15, 9, 12, 2, TimeSpan.Zero), report.ArrivalDate);
    }

    /// <summary>A trailing comment is legal and .NET will not take it either.</summary>
    [Fact]
    public void ATrailingTimeZoneCommentDoesNotLoseTheArrivalTime()
    {
        var report = ForensicReportParser.Parse(
            Sample.Replace(
                "Arrival-Date: Tue, 15 Sep 2026 09:12:02 +0000",
                "Arrival-Date: Tue, 15 Sep 2026 09:12:02 +0000 (UTC)",
                StringComparison.Ordinal)).Report!;

        Assert.Equal(new DateTimeOffset(2026, 9, 15, 9, 12, 2, TimeSpan.Zero), report.ArrivalDate);
    }

    /// <summary>
    /// A date nobody can read is null rather than a guess. Inventing "now"
    /// would file a message from last month under today.
    /// </summary>
    [Fact]
    public void ADateThatCannotBeReadIsNotInvented()
    {
        var report = ForensicReportParser.Parse(
            Sample
                .Replace("Arrival-Date: Tue, 15 Sep 2026 09:12:02 +0000", "Arrival-Date: whenever", StringComparison.Ordinal)
                .Replace("Date: Tue, 15 Sep 2026 09:12:00 +0000", "Date: also whenever", StringComparison.Ordinal))
            .Report!;

        Assert.Null(report.ArrivalDate);
    }

    [Fact]
    public void AnEmptyFileIsAFailureWithAReason()
    {
        Assert.False(ForensicReportParser.Parse("").Success);
        Assert.False(ForensicReportParser.Parse("   \n  ").Success);
    }

    [Fact]
    public void SomethingThatIsNotAReportIsNotReadAsOne()
    {
        var parsed = ForensicReportParser.Parse("""
            From: somebody@example.com
            Subject: lunch?

            Are you free at one?
            """);

        Assert.False(parsed.Success);
    }

    /// <summary>
    /// text/rfc822-headers, which is what a receiver sends when it has
    /// deliberately not included the body. The commonest shape in practice,
    /// and the one that would be missed by looking only for message/rfc822.
    /// </summary>
    [Fact]
    public void ReadsHeadersOnlyReports()
    {
        var parsed = ForensicReportParser.Parse(
            Sample.Replace("Content-Type: message/rfc822", "Content-Type: text/rfc822-headers", StringComparison.Ordinal));

        Assert.True(parsed.Success, parsed.Error);
        Assert.Equal("Updated remittance details", parsed.Report!.Subject);
    }

    /// <summary>
    /// Windows line endings, which is how half of this mail arrives.
    /// </summary>
    [Fact]
    public void ReadsAReportWithCarriageReturns()
    {
        var parsed = ForensicReportParser.Parse(Sample.Replace("\n", "\r\n", StringComparison.Ordinal));

        Assert.True(parsed.Success, parsed.Error);
        Assert.Equal("ndaco.org", parsed.Report!.Domain);
        Assert.Equal("Updated remittance details", parsed.Report.Subject);
        Assert.Equal("fail", parsed.Report.DkimResult);
    }

    /// <summary>
    /// A receiver that attached a very long message does not get to decide how
    /// much is stored.
    /// </summary>
    [Fact]
    public void TheStoredHeadersAreBounded()
    {
        var long_ = string.Join("\n", Enumerable.Range(0, 5_000).Select(i => $"X-Padding-{i}: {new string('x', 200)}"));

        var parsed = ForensicReportParser.Parse(
            Sample.Replace(
                "From: \"Accounts Payable\" <billing@ndaco.org>",
                long_ + "\nFrom: \"Accounts Payable\" <billing@ndaco.org>",
                StringComparison.Ordinal));

        Assert.True(parsed.Success, parsed.Error);
        Assert.True(
            parsed.Report!.ReportedHeaders.Length <= ForensicReportParser.MaxHeaderBytes,
            $"kept {parsed.Report.ReportedHeaders.Length} bytes of headers");
    }
}
