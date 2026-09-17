using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// Where a provider credential actually lives.
///
/// The database never holds a secret. A dns_provider_configs row holds a
/// credential_ref, an opaque pointer minted here, and the token it points at
/// lives behind this interface. That is what keeps a copied database, a
/// screenshot of a settings page and a support ticket from carrying the key
/// to a customer's zone.
///
/// The rule that matters: when the backend is unavailable, every operation
/// fails loudly. A store that silently returns nothing looks exactly like
/// "not configured yet" and sends an operator re-entering a token that is
/// already there.
/// </summary>
public interface ISecretStore
{
    /// <summary>Whether secrets can be read and written here at all.</summary>
    bool IsAvailable { get; }

    /// <summary>One sentence for an operator on what this store is and where it keeps things.</summary>
    string Description { get; }

    Task SetAsync(string credentialRef, string secret, CancellationToken ct = default);

    /// <summary>The secret, or null when nothing is stored under the ref.</summary>
    Task<string?> GetAsync(string credentialRef, CancellationToken ct = default);

    Task RemoveAsync(string credentialRef, CancellationToken ct = default);
}

/// <summary>
/// The shape of a credential reference: dmarc.&lt;tenant&gt;.&lt;purpose&gt;.&lt;random&gt;.
///
/// Tenant-namespaced so two tenants cannot collide, and validated before use
/// because a ref becomes a key in the backend's own namespace and must not be
/// able to name anything else there.
/// </summary>
public static partial class CredentialRef
{
    [GeneratedRegex(@"^dmarc\.[a-z0-9-]{1,40}\.[a-z0-9-]{1,40}\.[0-9a-f]{16}$")]
    private static partial Regex Shape();

    public static string New(string tenantSlug, string purpose)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantSlug);
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);

        var random = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var value = $"dmarc.{Clean(tenantSlug)}.{Clean(purpose)}.{random}";

        return IsValid(value) ? value : throw new ArgumentException($"Could not build a credential ref from '{tenantSlug}' and '{purpose}'.");
    }

    public static bool IsValid(string? value) => value is not null && Shape().IsMatch(value);

    public static void Assert(string? value)
    {
        if (!IsValid(value))
        {
            throw new ArgumentException($"'{value}' is not a credential reference this tool minted.", nameof(value));
        }
    }

    private static string Clean(string text) =>
        new([.. text.Trim().ToLowerInvariant().Where(c => char.IsAsciiLetterOrDigit(c) || c == '-')]);
}

/// <summary>A store for tests, and for a dry run that needs a provider without a machine to keep a key on.</summary>
public sealed class InMemorySecretStore : ISecretStore
{
    private readonly Dictionary<string, string> _secrets = new(StringComparer.Ordinal);

    public bool IsAvailable => true;
    public string Description => "In memory: gone when the process ends.";

    public Task SetAsync(string credentialRef, string secret, CancellationToken ct = default)
    {
        CredentialRef.Assert(credentialRef);
        _secrets[credentialRef] = secret;
        return Task.CompletedTask;
    }

    public Task<string?> GetAsync(string credentialRef, CancellationToken ct = default)
    {
        CredentialRef.Assert(credentialRef);
        return Task.FromResult(_secrets.GetValueOrDefault(credentialRef));
    }

    public Task RemoveAsync(string credentialRef, CancellationToken ct = default)
    {
        CredentialRef.Assert(credentialRef);
        _secrets.Remove(credentialRef);
        return Task.CompletedTask;
    }
}
