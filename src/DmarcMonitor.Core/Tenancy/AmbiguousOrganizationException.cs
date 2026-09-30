namespace DmarcMonitor.Core.Tenancy;

/// <summary>
/// A name that more than one organization holds was given without saying
/// which organization is meant.
/// </summary>
/// <remarks>
/// Domain names and client slugs are unique inside an organization, not across
/// them, so on a shared install the same name can be a normal thing to hold in
/// two places. The only wrong answer is to pick one: a DNS write made with the
/// other organization's provider token, or a credential filed under the other
/// organization's client, is exactly what the separation between organizations
/// exists to prevent.
///
/// Its own type so a command line can say which organizations and how to name
/// one, rather than printing a stack trace, and so that a broad catch around a
/// provider call cannot mistake it for a provider failure.
/// </remarks>
public sealed class AmbiguousOrganizationException(string kind, string name, IReadOnlyList<string> organizations)
    : Exception($"The {kind} '{name}' exists in more than one organization: {string.Join(", ", organizations)}. "
                + "Say which one is meant; nothing was changed.")
{
    /// <summary>What was named: "domain" or "client".</summary>
    public string Kind { get; } = kind;

    public string Name { get; } = name;

    public IReadOnlyList<string> Organizations { get; } = organizations;
}
