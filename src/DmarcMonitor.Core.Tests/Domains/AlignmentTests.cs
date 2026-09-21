using DmarcMonitor.Core.Domains;

namespace DmarcMonitor.Core.Tests.Domains;

/// <summary>
/// The rule that decides whether a valid signature counts for anything.
/// </summary>
public sealed class AlignmentTests
{
    [Theory]
    [InlineData("acme.com", "acme.com")]
    [InlineData("ACME.com", "acme.com")]
    [InlineData("acme.com.", "acme.com")]
    [InlineData("  acme.com  ", "acme.com")]
    public void AnExactMatchAlignsInEitherMode(string auth, string from)
    {
        Assert.Equal(AlignmentVerdict.Exact, Alignment.Classify(auth, from));
        Assert.True(Alignment.Aligns(auth, from, strict: true));
        Assert.True(Alignment.Aligns(auth, from, strict: false));
    }

    [Theory]
    [InlineData("mail.acme.com", "acme.com")]
    [InlineData("acme.com", "mail.acme.com")]
    [InlineData("a.b.acme.com", "acme.com")]
    public void ASubdomainAlignsOnlyWhenAlignmentIsRelaxed(string auth, string from)
    {
        Assert.Equal(AlignmentVerdict.Organizational, Alignment.Classify(auth, from));
        Assert.False(Alignment.Aligns(auth, from, strict: true));
        Assert.True(Alignment.Aligns(auth, from, strict: false));
    }

    [Theory]
    [InlineData("training.knowbe4.com", "nrgtechservices.com")]
    [InlineData("mailchimpapp.net", "acme.com")]
    [InlineData("sendgrid.net", "acme.com")]
    public void ADifferentOrganizationNeverAligns(string auth, string from)
    {
        Assert.Equal(AlignmentVerdict.Unrelated, Alignment.Classify(auth, from));
        Assert.False(Alignment.Aligns(auth, from, strict: true));
        Assert.False(Alignment.Aligns(auth, from, strict: false));
    }

    [Theory]
    [InlineData("notacme.com")]
    [InlineData("evilacme.com")]
    [InlineData("acme.com.attacker.net")]
    public void ALookalikeIsNotTreatedAsASubdomain(string auth)
    {
        // The whole reason the suffix test checks for a label boundary.
        // "notacme.com" ends with "acme.com", and a lookalike described as the
        // customer's own infrastructure is the one mistake here that helps an
        // attacker rather than merely confusing an operator.
        Assert.Equal(AlignmentVerdict.Unrelated, Alignment.Classify(auth, "acme.com"));
    }

    [Theory]
    [InlineData("", "acme.com")]
    [InlineData("acme.com", "")]
    [InlineData("   ", "acme.com")]
    public void NothingToCompareIsNotAMatch(string auth, string from)
    {
        // A report row with no signing domain proves nothing, and defaulting
        // to "aligned" would turn missing evidence into a pass.
        Assert.Equal(AlignmentVerdict.Unrelated, Alignment.Classify(auth, from));
        Assert.False(Alignment.Aligns(auth, from, strict: false));
    }
}
