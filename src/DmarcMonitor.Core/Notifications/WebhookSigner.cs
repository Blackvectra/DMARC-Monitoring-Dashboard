using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace DmarcMonitor.Core.Notifications;

/// <summary>
/// How a receiver knows an event came from this product and was not replayed.
/// </summary>
/// <remarks>
/// <para>
/// HMAC-SHA256 over <c>{timestamp}.{body}</c> with a secret both ends were
/// given out of band, sent as <c>X-Dmarc-Signature: v1=&lt;hex&gt;</c>. The
/// timestamp is inside the signature, so a captured request cannot be
/// re-sent later with a fresh one; the receiver refuses a timestamp more than
/// a few minutes from its own clock and remembers event ids it has seen.
/// </para>
/// <para>
/// The same scheme Stripe and GitHub use, deliberately: anybody writing a
/// receiver has seen it, and every language has the two primitives it needs.
/// "v1=" leaves room to change the algorithm without a flag day.
/// </para>
/// </remarks>
public static class WebhookSigner
{
    public const string SignatureHeader = "X-Dmarc-Signature";
    public const string TimestampHeader = "X-Dmarc-Timestamp";
    public const string EventIdHeader = "X-Dmarc-Event-Id";

    /// <summary>
    /// Shorter is refused when the secret is set. 32 characters of anything
    /// a person would generate for this - hex, base64 - is past guessing.
    /// </summary>
    public const int MinimumSecretLength = 32;

    public static string Sign(string secret, long timestamp, string body)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        ArgumentNullException.ThrowIfNull(body);

        var signed = Encoding.UTF8.GetBytes(timestamp.ToString(CultureInfo.InvariantCulture) + "." + body);
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), signed);
        return "v1=" + Convert.ToHexStringLower(mac);
    }

    /// <summary>Whether a signature is this body's, compared in constant time.</summary>
    public static bool Verify(string secret, long timestamp, string body, string? signature)
    {
        if (string.IsNullOrEmpty(signature)) { return false; }

        var expected = Encoding.ASCII.GetBytes(Sign(secret, timestamp, body));
        var given = Encoding.ASCII.GetBytes(signature.Trim());
        return CryptographicOperations.FixedTimeEquals(expected, given);
    }
}
