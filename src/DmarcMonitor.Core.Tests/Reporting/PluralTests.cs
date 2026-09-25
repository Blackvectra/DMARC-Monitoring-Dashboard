using DmarcMonitor.Core.Reporting;
using Xunit;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// Counts and the nouns they count, in the words a client reads.
/// </summary>
public sealed class PluralTests
{
    [Theory]
    [InlineData(0, "0 messages")]
    [InlineData(1, "1 message")]
    [InlineData(2, "2 messages")]
    [InlineData(1204, "1,204 messages")]
    public void CountsAgreeWithTheirNoun(long count, string expected)
    {
        Assert.Equal(expected, Plural.Count(count, "message"));
    }

    [Fact]
    public void ANounThatDoesNotTakeAnSIsGivenItsPlural()
    {
        Assert.Equal("1 address", Plural.Count(1, "address", "addresses"));
        Assert.Equal("40 addresses", Plural.Count(40, "address", "addresses"));
    }

    [Fact]
    public void VerbsAndPronounsAgreeToo()
    {
        Assert.Equal("was", Plural.Of(1, "was", "were"));
        Assert.Equal("were", Plural.Of(0, "was", "were"));
        Assert.Equal("them", Plural.Of(36, "it", "them"));
    }
}
