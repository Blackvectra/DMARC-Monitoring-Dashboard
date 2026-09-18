using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace DmarcMonitor.Core.Updates;

/// <summary>An update somebody asked for from the app.</summary>
public sealed record UpdateRequest
{
    public required string Version { get; init; }
    public required string RequestedBy { get; init; }
    public required DateTimeOffset RequestedAt { get; init; }
}

/// <summary>How far the helper got with it.</summary>
public enum UpdateState
{
    /// <summary>Nobody has asked for anything.</summary>
    Idle,

    /// <summary>Written down, and the helper has not picked it up yet.</summary>
    Requested,

    /// <summary>The helper is working.</summary>
    Running,

    Succeeded,
    Failed,
}

/// <summary>
/// How far an update has got.
/// </summary>
/// <remarks>
/// Distinct from UpdateStatus, which is about what EXISTS to install. This is
/// about an install that was asked for.
/// </remarks>
public sealed record UpdateProgress
{
    public UpdateState State { get; init; } = UpdateState.Idle;
    public string Version { get; init; } = "";
    public string Message { get; init; } = "";
    public DateTimeOffset? At { get; init; }

    /// <summary>The stamp of the install kept aside, for rolling back.</summary>
    public string Stamp { get; init; } = "";
}

/// <summary>
/// How the app asks to be updated without being able to update itself.
///
/// The app runs as an unprivileged account and cannot replace its own files -
/// deliberately, because it holds credentials that rewrite customers' DNS and
/// a web application that can also install software is a much larger thing to
/// compromise. So it writes down a version, and a separate unit running as
/// root notices, checks, and does the work.
///
/// The only thing that crosses the boundary is a VERSION STRING. Not a URL,
/// not a path, not a command. It is validated on the way out and again by the
/// helper on the way in, and the helper additionally refuses any version that
/// is not a real published release. So the worst an attacker who owned the web
/// app could achieve here is installing a genuine release of this product.
/// </summary>
public sealed partial class UpdateSpool(string directory)
{
    /// <summary>
    /// A version tag, and nothing else that could be one.
    /// </summary>
    /// <remarks>
    /// Anchored, and deliberately narrow: digits, dots, and an optional
    /// prerelease suffix of letters and digits. No slashes, no spaces, no
    /// shell metacharacters, nothing that could climb out of a directory or
    /// end up being interpreted rather than compared.
    /// </remarks>
    [GeneratedRegex(@"^v?[0-9]{1,4}(\.[0-9]{1,4}){1,3}(-[A-Za-z0-9.]{1,32})?$")]
    private static partial Regex VersionShape();

    public static bool IsValidVersion(string? version) =>
        version is not null && VersionShape().IsMatch(version);

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,

        // Names, not numbers. The other end of this file is a shell script,
        // which writes "Succeeded" because that is what a human reading the
        // file would expect - and the default here would look for 3.
        Converters = { new JsonStringEnumConverter() },
    };

    public string RequestPath { get; } = Path.Combine(directory, "requested.json");
    public string StatusPath { get; } = Path.Combine(directory, "status.json");

    /// <summary>
    /// Writes down that somebody wants this version installed.
    /// </summary>
    /// <remarks>
    /// Refuses anything that is not shaped like a version before it reaches
    /// the file, so the helper is never handed something it has to be clever
    /// about. The helper checks again anyway: a file on disk is not a promise
    /// about what wrote it.
    /// </remarks>
    public async Task RequestAsync(string version, string by, CancellationToken ct = default)
    {
        if (!IsValidVersion(version))
        {
            throw new ArgumentException($"'{version}' is not a version number.", nameof(version));
        }

        Directory.CreateDirectory(Path.GetDirectoryName(RequestPath)!);

        var request = new UpdateRequest
        {
            Version = version.StartsWith('v') ? version : "v" + version,
            RequestedBy = by,
            RequestedAt = DateTimeOffset.UtcNow,
        };

        // Written beside and moved over, so the helper cannot be woken by a
        // half-written file and read a truncated version.
        var temp = RequestPath + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(request, Json), ct).ConfigureAwait(false);
        File.Move(temp, RequestPath, overwrite: true);

        await WriteStatusAsync(new UpdateProgress
        {
            State = UpdateState.Requested,
            Version = request.Version,
            Message = $"Asked for by {by}. Waiting for the update service to pick it up.",
            At = request.RequestedAt,
        }, ct).ConfigureAwait(false);
    }

    /// <summary>What the helper last said, or Idle when it has never said anything.</summary>
    public async Task<UpdateProgress> ReadStatusAsync(CancellationToken ct = default)
    {
        if (!File.Exists(StatusPath)) { return new UpdateProgress(); }

        try
        {
            var text = await File.ReadAllTextAsync(StatusPath, ct).ConfigureAwait(false);
            return JsonSerializer.Deserialize<UpdateProgress>(text, Json) ?? new UpdateProgress();
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            // Mid-write, or written by something else. Not knowing is a
            // normal answer here and not worth an error page.
            return new UpdateProgress { State = UpdateState.Idle, Message = "The update status could not be read." };
        }
    }

    /// <summary>Whether the machinery is even set up for this.</summary>
    /// <remarks>
    /// The app can always write a request; whether anything is listening is a
    /// different question, and telling somebody an update is under way when
    /// no helper exists would leave them waiting for nothing.
    /// </remarks>
    public bool IsAvailable => Directory.Exists(Path.GetDirectoryName(RequestPath)!);

    public async Task WriteStatusAsync(UpdateProgress status, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(status);

        Directory.CreateDirectory(Path.GetDirectoryName(StatusPath)!);

        var temp = StatusPath + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(status, Json), ct).ConfigureAwait(false);
        File.Move(temp, StatusPath, overwrite: true);
    }
}
