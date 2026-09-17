using DmarcMonitor.Core.Remediation;

namespace DmarcMonitor.Core.Tests.Remediation;

public sealed class SpfIncludePlannerTests
{
    [Fact]
    public void RemovesOnlyTheNamedIncludeAndKeepsTheRestAsWritten()
    {
        // Qualifiers and order are the operator's. The -all at the end in
        // particular must survive, or the record goes from strict to
        // neutral in the same write that was meant to tidy it.
        var plan = SpfIncludePlanner.RemoveDeadInclude("acme.com",
            "v=spf1 include:spf.protection.outlook.com include:retired.example.net ip4:203.0.113.0/24 -all",
            "retired.example.net");

        Assert.True(plan.IsSafe);
        Assert.Equal("v=spf1 include:spf.protection.outlook.com ip4:203.0.113.0/24 -all", plan.ProposedValue);
        Assert.Equal(2, plan.LookupsBefore);
        Assert.Equal(1, plan.LookupsAfter);
        Assert.Equal("acme.com", plan.RecordName);
    }

    [Fact]
    public void AnIncludeThatIsNotThereIsANoop()
    {
        var plan = SpfIncludePlanner.RemoveDeadInclude("acme.com", "v=spf1 include:a.example -all", "b.example");

        Assert.True(plan.IsNoop);
    }

    [Fact]
    public void RefusesToEditARecordThatIsNotSpf()
    {
        var plan = SpfIncludePlanner.RemoveDeadInclude("acme.com", "MS=ms12345", "b.example");

        Assert.False(plan.IsSafe);
    }

    [Fact]
    public void MatchesTheIncludeRegardlessOfCaseAndTrailingDot()
    {
        var plan = SpfIncludePlanner.RemoveDeadInclude("acme.com", "v=spf1 include:Retired.Example.NET. -all", "retired.example.net");

        Assert.Equal("v=spf1 -all", plan.ProposedValue);
    }
}
