using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DmarcMonitor.Core.Remediation;

/// <summary>
/// Secrets kept on this machine, encrypted to the account that runs the tool.
///
/// On Windows that is DPAPI in current-user scope: the blob can only be read
/// by the same account on the same machine, which is the property wanted for
/// a self-hosted install and the reason a secret saved by an administrator at
/// a desk cannot be read by the service account. Anywhere else there is no
/// DPAPI, so a key file is created beside the secrets with permissions that
/// let only the owner read it, and AES-GCM does the rest. Both are stated on
/// the settings page so nobody has to guess which one is in play.
///
/// The file holds refs and ciphertext only. Copying it somewhere else copies
/// nothing that can be used there.
/// </summary>
public sealed class LocalSecretStore : ISecretStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private readonly string _directory;
    private readonly string _file;
    private readonly string _keyFile;
    private readonly object _gate = new();

    public LocalSecretStore(string? directory = null)
    {
        _directory = directory ?? DefaultDirectory();
        _file = Path.Combine(_directory, "secrets.json");
        _keyFile = Path.Combine(_directory, "secrets.key");
    }

    public static string DefaultDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolderOption.Create), "DmarcMonitor");

    public bool IsAvailable
    {
        get
        {
            try
            {
                Directory.CreateDirectory(_directory);
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    public string Description => OperatingSystem.IsWindows()
        ? $"DPAPI, current user, in {_file}. Readable only by this Windows account on this machine."
        : $"AES-GCM with the key in {_keyFile} (owner-only permissions), secrets in {_file}.";

    // The file is a few hundred bytes and read whole, so the work is done
    // synchronously under one lock; the async surface is the interface's,
    // shared with stores that really do go somewhere.

    public Task SetAsync(string credentialRef, string secret, CancellationToken ct = default)
    {
        CredentialRef.Assert(credentialRef);
        ArgumentNullException.ThrowIfNull(secret);
        RequireAvailable();

        lock (_gate)
        {
            var all = Load();
            all[credentialRef] = Protect(Encoding.UTF8.GetBytes(secret));
            Save(all);
        }
        return Task.CompletedTask;
    }

    public Task<string?> GetAsync(string credentialRef, CancellationToken ct = default)
    {
        CredentialRef.Assert(credentialRef);
        RequireAvailable();

        lock (_gate)
        {
            var all = Load();
            if (!all.TryGetValue(credentialRef, out var blob)) { return Task.FromResult<string?>(null); }

            try
            {
                return Task.FromResult<string?>(Encoding.UTF8.GetString(Unprotect(blob)));
            }
            catch (CryptographicException ex)
            {
                // Present but unreadable is not the same as absent. Returning
                // null here would read as "not configured" and have somebody
                // paste the token in again, under a new ref, leaving this one.
                throw new InvalidOperationException(
                    $"A secret is stored for {credentialRef} but could not be decrypted. It was saved by a different "
                    + "account or on a different machine. Re-enter it as the account that runs the tool.", ex);
            }
        }
    }

    public Task RemoveAsync(string credentialRef, CancellationToken ct = default)
    {
        CredentialRef.Assert(credentialRef);
        RequireAvailable();

        lock (_gate)
        {
            var all = Load();
            if (all.Remove(credentialRef)) { Save(all); }
        }
        return Task.CompletedTask;
    }

    private void RequireAvailable()
    {
        if (!IsAvailable)
        {
            throw new InvalidOperationException($"The secret store at {_directory} cannot be used, so the secret was not touched. {Description}");
        }
    }

    private Dictionary<string, string> Load()
    {
        if (!File.Exists(_file)) { return new Dictionary<string, string>(StringComparer.Ordinal); }

        return JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_file))
            ?? new Dictionary<string, string>(StringComparer.Ordinal);
    }

    private void Save(Dictionary<string, string> all)
    {
        Directory.CreateDirectory(_directory);

        // Written beside and moved over, so a crash mid-write leaves the old
        // file rather than half of a new one.
        var temp = _file + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(all, Json));
        RestrictToOwner(temp);
        File.Move(temp, _file, overwrite: true);
    }

    private string Protect(byte[] plain)
    {
        if (OperatingSystem.IsWindows())
        {
            return "dpapi:" + Convert.ToBase64String(Dpapi.Protect(plain));
        }

        var key = Key();
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var cipher = new byte[plain.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, plain, cipher, tag);

        return "aesgcm:" + Convert.ToBase64String(nonce) + ":" + Convert.ToBase64String(cipher) + ":" + Convert.ToBase64String(tag);
    }

    private byte[] Unprotect(string blob)
    {
        if (blob.StartsWith("dpapi:", StringComparison.Ordinal))
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new CryptographicException("This secret was protected with DPAPI on Windows and cannot be read here.");
            }
            return Dpapi.Unprotect(Convert.FromBase64String(blob["dpapi:".Length..]));
        }

        if (blob.StartsWith("aesgcm:", StringComparison.Ordinal))
        {
            var parts = blob["aesgcm:".Length..].Split(':');
            if (parts.Length != 3) { throw new CryptographicException("The stored blob is not in the expected shape."); }

            var nonce = Convert.FromBase64String(parts[0]);
            var cipher = Convert.FromBase64String(parts[1]);
            var tag = Convert.FromBase64String(parts[2]);
            var plain = new byte[cipher.Length];

            using var aes = new AesGcm(Key(), tag.Length);
            aes.Decrypt(nonce, cipher, tag, plain);
            return plain;
        }

        throw new CryptographicException("The stored blob was not written by this tool.");
    }

    private byte[] Key()
    {
        if (File.Exists(_keyFile))
        {
            return Convert.FromBase64String(File.ReadAllText(_keyFile).Trim());
        }

        Directory.CreateDirectory(_directory);
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(_keyFile, Convert.ToBase64String(key));
        RestrictToOwner(_keyFile);
        return key;
    }

    private static void RestrictToOwner(string path)
    {
        if (OperatingSystem.IsWindows()) { return; }   // the profile directory already is

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    /// <summary>Isolated so the Windows-only API is only ever reached behind an OS check.</summary>
    private static class Dpapi
    {
        [SupportedOSPlatform("windows")]
        public static byte[] Protect(byte[] plain) =>
            ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);

        [SupportedOSPlatform("windows")]
        public static byte[] Unprotect(byte[] blob) =>
            ProtectedData.Unprotect(blob, Entropy, DataProtectionScope.CurrentUser);

        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("DmarcMonitor.LocalSecretStore.v1");
    }
}
