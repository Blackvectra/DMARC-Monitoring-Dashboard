using System.Security.Cryptography;

namespace DmarcMonitor.Core.Dns;

/// <summary>How much a published DKIM key is worth.</summary>
public enum DkimKeyStrength
{
    /// <summary>The TXT record is not a DKIM key at all.</summary>
    Invalid,

    /// <summary>
    /// <c>p=</c> with nothing after it, which RFC 6376 section 3.6.1 defines
    /// as revoked.
    /// </summary>
    /// <remarks>
    /// Deliberate, and the correct way to retire a selector: the record stays
    /// so that a verifier gets "this key is withdrawn" rather than "I cannot
    /// find this key", which are treated differently. So a revoked selector is
    /// a finding only when mail is still being signed with it.
    /// </remarks>
    Revoked,

    /// <summary>Under 1024 bits, which large receivers have refused since 2018.</summary>
    Weak,

    /// <summary>1024 bits: still accepted everywhere, no longer what to publish.</summary>
    Acceptable,

    /// <summary>2048 bits or better, or an Ed25519 key.</summary>
    Strong,
}

/// <summary>
/// A DKIM public key as published at <c>&lt;selector&gt;._domainkey.&lt;domain&gt;</c>.
/// </summary>
/// <remarks>
/// <para>
/// Only ever read for selectors the reports have already named. DNS offers no
/// way to ask a domain which selectors it has - there is no list to enumerate
/// and no wildcard to walk - so guessing at common names ("default",
/// "selector1", "google") would produce confident findings about keys that
/// were never used and miss every key with a name nobody guessed. The reports
/// say which selectors really signed; that is the only honest input.
/// </para>
/// <para>
/// The key material itself is not stored. What matters afterwards is the
/// algorithm, the size and whether the record still resolves, and keeping
/// several kilobytes of base64 per selector in a table nobody reads buys
/// nothing.
/// </para>
/// </remarks>
public sealed record DkimKey
{
    public required string Selector { get; init; }

    /// <summary>rsa or ed25519. Empty when the record did not say, which means rsa.</summary>
    public string Algorithm { get; init; } = "rsa";

    /// <summary>Bits, or null when the key could not be read at all.</summary>
    public int? Bits { get; init; }

    public DkimKeyStrength Strength { get; init; } = DkimKeyStrength.Invalid;

    /// <summary>Why the record is not a usable key, or empty when it is one.</summary>
    public string Problem { get; init; } = "";

    /// <summary>
    /// True when there was a record at this selector to read at all.
    /// </summary>
    /// <remarks>
    /// The absent-against-broken distinction, at the selector. Both come back
    /// as <see cref="DkimKeyStrength.Invalid"/> and they lead opposite ways: a
    /// name with nothing at it is a selector that was removed or never
    /// existed, and a name carrying a record that will not parse is a key
    /// somebody published wrongly and believes is working. Telling the second
    /// to publish a key, or the first that its key is malformed, sends the
    /// operator to the wrong screen.
    /// </remarks>
    public bool Published { get; init; }

    /// <summary>True when there is a key here a verifier could use today.</summary>
    public bool Usable => Strength is DkimKeyStrength.Weak
        or DkimKeyStrength.Acceptable or DkimKeyStrength.Strong;

    /// <summary>
    /// Reads the TXT record at a selector.
    /// </summary>
    /// <param name="selector">The selector this record was found at.</param>
    /// <param name="text">The record, already joined if DNS split it.</param>
    public static DkimKey Parse(string selector, string? text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selector);

        var raw = (text ?? string.Empty).Trim();
        var name = selector.Trim().ToLowerInvariant();

        if (raw.Length == 0)
        {
            return new DkimKey
            {
                Selector = name,
                Strength = DkimKeyStrength.Invalid,
                Problem = "nothing published at this selector",
            };
        }

        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var equals = part.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0) { continue; }

            // Only the first occurrence counts, and p= is the one that matters:
            // a record carrying two of them is malformed, and taking the last
            // would let a trailing empty p= read as a revocation of a key that
            // is not revoked.
            var tag = part[..equals].Trim();
            if (!tags.ContainsKey(tag)) { tags[tag] = part[(equals + 1)..].Trim(); }
        }

        // v= is optional in RFC 6376 - a record without it is still a key, and
        // plenty in the wild have none - but when it is there it has to say
        // DKIM1, or this is somebody else's TXT record sitting at a name that
        // happens to look like a selector.
        if (tags.TryGetValue("v", out var version) &&
            !version.Equals("DKIM1", StringComparison.OrdinalIgnoreCase))
        {
            return new DkimKey
            {
                Selector = name,
                Strength = DkimKeyStrength.Invalid,
                Problem = $"a TXT record that is not a DKIM key (v={version})",
                Published = true,
            };
        }

        if (!tags.TryGetValue("p", out var material))
        {
            return new DkimKey
            {
                Selector = name,
                Strength = DkimKeyStrength.Invalid,
                Problem = "no p= tag, so there is no key in it",
                Published = true,
            };
        }

        var algorithm = tags.TryGetValue("k", out var k) && k.Length > 0
            ? k.ToLowerInvariant()
            : "rsa";

        if (material.Length == 0)
        {
            return new DkimKey
            {
                Selector = name,
                Algorithm = algorithm,
                Strength = DkimKeyStrength.Revoked,
                Problem = "p= is empty, which publishes the selector as revoked",
                Published = true,
            };
        }

        // Providers wrap long keys, and a record reassembled from several TXT
        // strings can carry the whitespace that was between them. Base64
        // ignores it in every other decoder; this one has to strip it first.
        var base64 = string.Concat(material.Where(c => !char.IsWhiteSpace(c)));

        byte[] der;
        try
        {
            der = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            return new DkimKey
            {
                Selector = name,
                Algorithm = algorithm,
                Strength = DkimKeyStrength.Invalid,
                Problem = "p= is not valid base64, so no verifier can read it",
                Published = true,
            };
        }

        if (algorithm == "ed25519")
        {
            // Fixed at 256 bits by the curve. RFC 8463 publishes the raw
            // 32-byte point rather than wrapping it, so the length is the
            // whole check there is to make.
            return der.Length == 32
                ? new DkimKey
                {
                    Selector = name,
                    Algorithm = algorithm,
                    Bits = 256,
                    Strength = DkimKeyStrength.Strong,
                    Published = true,
                }
                : new DkimKey
                {
                    Selector = name,
                    Algorithm = algorithm,
                    Strength = DkimKeyStrength.Invalid,
                    Problem = $"an Ed25519 key is 32 bytes; this is {der.Length}",
                    Published = true,
                };
        }

        var bits = RsaBits(der);
        if (bits is null)
        {
            return new DkimKey
            {
                Selector = name,
                Algorithm = algorithm,
                Strength = DkimKeyStrength.Invalid,
                Problem = "p= decoded, but is not a public key any verifier could import",
                Published = true,
            };
        }

        return new DkimKey
        {
            Selector = name,
            Algorithm = algorithm,
            Bits = bits,
            Published = true,
            Strength = bits switch
            {
                >= 2048 => DkimKeyStrength.Strong,
                >= 1024 => DkimKeyStrength.Acceptable,
                _ => DkimKeyStrength.Weak,
            },
        };
    }

    /// <summary>
    /// The key a verifier would end up using out of whatever is published at
    /// one selector.
    /// </summary>
    /// <remarks>
    /// A selector's name holds one key and, in practice, other TXT records
    /// almost never. Where there is more than one, the DKIM record is the one
    /// that parses as a key: picking the first blindly would report a
    /// verification token, or a record somebody replaced and left behind, as
    /// this selector's broken key.
    ///
    /// Which one a real verifier picks out of several is unspecified - RFC
    /// 6376 §3.6.2.1 leaves it open - so this is the best case rather than the
    /// certain one, and a selector carrying more than one record is a finding
    /// in its own right.
    /// </remarks>
    public static DkimKey Choose(string selector, IReadOnlyList<string> records)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(selector);
        ArgumentNullException.ThrowIfNull(records);

        var keys = records.Select(t => Parse(selector, t)).ToList();

        return keys.Find(k => k.Usable)
            ?? keys.Find(k => k.Strength == DkimKeyStrength.Revoked)
            ?? (keys.Count > 0 ? keys[0] : Parse(selector, null));
    }

    /// <summary>
    /// The modulus size of an RSA public key, whichever of the two encodings
    /// it was published in.
    /// </summary>
    /// <remarks>
    /// RFC 6376 specifies SubjectPublicKeyInfo, and that is what nearly every
    /// provider emits. A minority publish the bare PKCS#1 RSAPublicKey
    /// instead. Both are accepted by real verifiers, so reading only the first
    /// would report a working key as unreadable.
    /// </remarks>
    private static int? RsaBits(byte[] der)
    {
        using var rsa = RSA.Create();

        try
        {
            rsa.ImportSubjectPublicKeyInfo(der, out _);
            return rsa.KeySize;
        }
        catch (CryptographicException)
        {
            // Not SPKI. Try the other encoding before giving up.
        }

        try
        {
            rsa.ImportRSAPublicKey(der, out _);
            return rsa.KeySize;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>The value stored in <c>dkim_selectors.key_status</c>.</summary>
    public string StatusText => Strength switch
    {
        DkimKeyStrength.Strong => "strong",
        DkimKeyStrength.Acceptable => "acceptable",
        DkimKeyStrength.Weak => "weak",
        DkimKeyStrength.Revoked => "revoked",
        _ => "invalid",
    };
}
