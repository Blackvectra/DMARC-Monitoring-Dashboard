using System.Globalization;

namespace DmarcMonitor.Core.Reporting;

/// <summary>
/// A count and the noun it counts, agreeing.
/// </summary>
/// <remarks>
/// The client report wrote "1 message(s)" and "36 message(s)" on every page,
/// about 180 times across a month's reports. It is the convention of a log
/// file, and in a document a client pays for it reads as a form nobody
/// finished filling in. The verb has to agree as well - "1 source were" is
/// worse than the brackets were - so this does verbs and pronouns too.
/// </remarks>
public static class Plural
{
    /// <summary>"1 message", "2 messages", "1,204 messages".</summary>
    /// <param name="plural">For a noun that is not made plural by adding "s": "address", "addresses".</param>
    public static string Count(long count, string singular, string? plural = null) =>
        $"{count.ToString("N0", CultureInfo.InvariantCulture)} {Of(count, singular, plural ?? singular + "s")}";

    /// <summary>The singular form for exactly one, the plural otherwise: nouns, verbs and pronouns alike.</summary>
    public static string Of(long count, string one, string many) => count == 1 ? one : many;
}
