using System.Security.Cryptography;
using DmarcMonitor.Core.Dns;
using Xunit;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// Reading the key published at a DKIM selector.
///
/// Real records are the awkward part. They arrive split across several TXT
/// strings, wrapped by a provider's control panel, sometimes in the older of
/// two encodings, and occasionally with a verification token sitting at a
/// name that looks like a selector. Each of those reads as a broken key if it
/// is parsed naively, and a broken key here is reported to an operator as
/// mail that is failing DKIM - which sends them to rotate a key that was
/// fine.
/// </summary>
public sealed class DkimKeyTests
{
    /// <summary>A real key of a given size, because a made-up base64 blob is not one.</summary>
    private static string PublicKey(int bits, bool pkcs1 = false)
    {
        using var rsa = RSA.Create(bits);
        return Convert.ToBase64String(pkcs1
            ? rsa.ExportRSAPublicKey()
            : rsa.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void ReadsAnOrdinaryKey()
    {
        var key = DkimKey.Parse("selector1", $"v=DKIM1; k=rsa; p={PublicKey(2048)}");

        Assert.Equal("selector1", key.Selector);
        Assert.Equal("rsa", key.Algorithm);
        Assert.Equal(2048, key.Bits);
        Assert.Equal(DkimKeyStrength.Strong, key.Strength);
        Assert.True(key.Usable);
    }

    [Fact]
    public void TakesTheOtherEncodingToo()
    {
        // RFC 6376 specifies SubjectPublicKeyInfo and nearly everybody emits
        // it, but a minority publish the bare PKCS#1 key. Real verifiers
        // accept both, so reading only the first would report a working key
        // as unreadable and send somebody to rotate it.
        var key = DkimKey.Parse("s", $"v=DKIM1; p={PublicKey(2048, pkcs1: true)}");

        Assert.Equal(2048, key.Bits);
        Assert.Equal(DkimKeyStrength.Strong, key.Strength);
    }

    [Fact]
    public void AVersionTagIsOptional()
    {
        // Plenty of records in the wild have none, and RFC 6376 allows it.
        var key = DkimKey.Parse("s", $"k=rsa; p={PublicKey(2048)}");

        Assert.Equal(DkimKeyStrength.Strong, key.Strength);
    }

    [Fact]
    public void SomethingElseAtASelectorNameIsNotABrokenKey()
    {
        var key = DkimKey.Parse("s", "v=spf1 -all");

        Assert.Equal(DkimKeyStrength.Invalid, key.Strength);
        Assert.Contains("not a DKIM key", key.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyPTagIsRevokedRatherThanBroken()
    {
        // RFC 6376 section 3.6.1: this is the correct way to retire a
        // selector, and it is deliberate. Reporting it as a fault would have
        // somebody republish a key they meant to withdraw.
        var key = DkimKey.Parse("old", "v=DKIM1; k=rsa; p=");

        Assert.Equal(DkimKeyStrength.Revoked, key.Strength);
        Assert.False(key.Usable);
    }

    [Fact]
    public void NothingAtTheSelectorIsSaidPlainly()
    {
        var key = DkimKey.Parse("s", null);

        Assert.Equal(DkimKeyStrength.Invalid, key.Strength);
        Assert.Contains("nothing published", key.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ARecordWithNoKeyInItIsNotAKey()
    {
        var key = DkimKey.Parse("s", "v=DKIM1; k=rsa; t=y");

        Assert.Equal(DkimKeyStrength.Invalid, key.Strength);
        Assert.Contains("no p= tag", key.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void WhitespaceInsideTheKeySurvives()
    {
        // A key longer than 255 characters arrives as several TXT strings,
        // and a control panel that wrapped it leaves the wrapping behind.
        // Base64 decoders elsewhere ignore that; this one has to strip it
        // first or every long key reads as corrupt.
        var material = PublicKey(2048);
        var wrapped = string.Join("\n  ", Enumerable.Range(0, (material.Length / 64) + 1)
            .Select(i => material.Skip(i * 64).Take(64))
            .Select(chunk => new string([.. chunk]))
            .Where(s => s.Length > 0));

        var key = DkimKey.Parse("s", $"v=DKIM1; p={wrapped}");

        Assert.Equal(2048, key.Bits);
        Assert.Equal(DkimKeyStrength.Strong, key.Strength);
    }

    [Fact]
    public void GibberishInPIsReportedAsThat()
    {
        var key = DkimKey.Parse("s", "v=DKIM1; p=not-base-64-at-all!!!");

        Assert.Equal(DkimKeyStrength.Invalid, key.Strength);
        Assert.Contains("base64", key.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidBase64ThatIsNotAKeyIsReportedAsThat()
    {
        var key = DkimKey.Parse("s", "v=DKIM1; p=" + Convert.ToBase64String([1, 2, 3, 4]));

        Assert.Equal(DkimKeyStrength.Invalid, key.Strength);
        Assert.Contains("not a public key", key.Problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(512, DkimKeyStrength.Weak)]
    [InlineData(1024, DkimKeyStrength.Acceptable)]
    [InlineData(2048, DkimKeyStrength.Strong)]
    public void SizeDecidesStrength(int bits, DkimKeyStrength expected)
    {
        Assert.Equal(expected, DkimKey.Parse("s", $"v=DKIM1; p={PublicKey(bits)}").Strength);
    }

    [Fact]
    public void AnEd25519KeyIsStrongAtThirtyTwoBytes()
    {
        var key = DkimKey.Parse("s", "v=DKIM1; k=ed25519; p=" + Convert.ToBase64String(new byte[32]));

        Assert.Equal("ed25519", key.Algorithm);
        Assert.Equal(256, key.Bits);
        Assert.Equal(DkimKeyStrength.Strong, key.Strength);
    }

    [Fact]
    public void AnEd25519KeyOfTheWrongLengthIsNotOne()
    {
        var key = DkimKey.Parse("s", "v=DKIM1; k=ed25519; p=" + Convert.ToBase64String(new byte[16]));

        Assert.Equal(DkimKeyStrength.Invalid, key.Strength);
        Assert.Contains("32 bytes", key.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ATrailingEmptyPDoesNotRevokeAKeyThatIsThere()
    {
        // A record carrying two p= tags is malformed, and taking the last of
        // them would read a real key as withdrawn - which is reported as mail
        // failing DKIM at every receiver. The first tag wins.
        var key = DkimKey.Parse("s", $"v=DKIM1; p={PublicKey(2048)}; p=");

        Assert.Equal(DkimKeyStrength.Strong, key.Strength);
    }

    [Fact]
    public void TheSelectorIsNormalized()
    {
        Assert.Equal("sel", DkimKey.Parse("  SEL  ", "v=DKIM1; p=").Selector);
    }

    [Fact]
    public void StatusTextMatchesTheColumnItIsStoredIn()
    {
        Assert.Equal("strong", DkimKey.Parse("s", $"v=DKIM1; p={PublicKey(2048)}").StatusText);
        Assert.Equal("revoked", DkimKey.Parse("s", "v=DKIM1; p=").StatusText);
        Assert.Equal("invalid", DkimKey.Parse("s", "").StatusText);
    }
}
