using System.Net;

namespace DmarcMonitor.Core.Dns;

/// <summary>One address range an SPF include authorises.</summary>
public sealed record AuthorisedRange(IPNetwork Network);

/// <summary>What an include is for, and whether anything has used it.</summary>
public sealed record IncludeUsage
{
    /// <summary>The include target as written in the record.</summary>
    public required string Target { get; init; }

    /// <summary>
    /// The service this most likely is.
    /// </summary>
    /// <remarks>
    /// Derived from the target's own registrable domain rather than a table of
    /// known providers. A table is wrong the month after it is written -
    /// spf.protection.outlook.com was several nested includes until Microsoft
    /// flattened it - and a stale label on a DNS recommendation is worse than
    /// no label, because somebody acts on it.
    /// </remarks>
    public string Service => Registrable(Target);

    /// <summary>Address ranges this include ends up authorising.</summary>
    public IReadOnlyList<AuthorisedRange> Ranges { get; init; } = [];

    /// <summary>Messages seen from those ranges in the window examined.</summary>
    public long Messages { get; init; }

    /// <summary>The most recent day mail was seen from it.</summary>
    public DateTimeOffset? LastSeen { get; init; }

    /// <summary>True when the include resolved to no usable ranges at all.</summary>
    public bool ResolvedNothing => Ranges.Count == 0;

    /// <summary>Nothing has been seen from it in the window examined.</summary>
    public bool Unused => Messages == 0;

    /// <summary>
    /// "spf.protection.outlook.com" becomes "outlook.com".
    /// </summary>
    /// <remarks>
    /// Two labels only, which is right for the common case and wrong for a
    /// handful of multi-part suffixes such as co.uk. It is used to give an
    /// operator something recognisable to look at, never to decide anything,
    /// so being occasionally imprecise costs nothing.
    /// </remarks>
    private static string Registrable(string host)
    {
        var parts = host.Trim('.').Split('.');
        return parts.Length <= 2 ? host : string.Join('.', parts[^2..]);
    }
}
