using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace DmarcMonitor.Core.Updates;

/// <summary>A release that exists, as GitHub describes it.</summary>
public sealed record Release(string Version, string Name, DateTimeOffset PublishedAt, string Url, bool IsPrerelease);

/// <summary>Where this instance stands against what has been released.</summary>
public sealed record UpdateStatus
{
    public required string Running { get; init; }

    /// <summary>The newest release on the channel, or null when none could be read.</summary>
    public Release? Latest { get; init; }

    /// <summary>True only when a newer version is definitely available.</summary>
    public bool UpdateAvailable { get; init; }

    /// <summary>Why nothing could be said, when nothing could be.</summary>
    public string? Problem { get; init; }

    /// <summary>What an operator should read. One sentence, always populated.</summary>
    public required string Summary { get; init; }
}

/// <summary>
/// What has been released, so a deployed instance knows whether it is behind.
///
/// The shape this exists to support: development happens on branches and
/// lands on main, and none of that reaches the server. Tagging a version
/// builds the artifacts, and the server tracks TAGS - so work in progress
/// cannot arrive on a machine that is managing customers' DNS just because
/// somebody merged something.
///
/// It only ever reports. Nothing here downloads or installs: an instance that
/// can rewrite its own code is a much larger thing to trust than one that
/// tells you a version exists, and the update is a command somebody runs when
/// they have decided to.
///
/// Off unless configured, and when on it makes one outbound request to
/// GitHub's API asking what the newest release is. It sends nothing about the
/// instance, its customers or its data - but it is still an outbound call from
/// a machine holding other people's mail records, so it is a decision rather
/// than a default.
/// </summary>
public sealed class ReleaseChannel(HttpClient? client = null)
{
    /// <summary>Releases marked prerelease are skipped.</summary>
    public const string Stable = "stable";

    /// <summary>Prereleases count too, for a box being used to test one.</summary>
    public const string Preview = "preview";

    private readonly HttpClient _http = client ?? Default();

    private static HttpClient Default() => new() { Timeout = TimeSpan.FromSeconds(15) };

    /// <summary>
    /// Asks what the newest release is and compares it with what is running.
    /// </summary>
    /// <param name="repository">"owner/name" on GitHub.</param>
    /// <param name="token">
    /// Needed only for a private repository. A read-only token: this reads a
    /// release list and nothing else.
    /// </param>
    public async Task<UpdateStatus> CheckAsync(
        string repository,
        string running,
        string channel = Stable,
        string? token = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repository);
        ArgumentException.ThrowIfNullOrWhiteSpace(running);

        var releases = await ListAsync(repository, token, ct).ConfigureAwait(false);

        if (releases.Problem is not null)
        {
            return new UpdateStatus
            {
                Running = running,
                Problem = releases.Problem,
                Summary = $"Running {running}. Could not check for updates: {releases.Problem}",
            };
        }

        IReadOnlyList<Release> wanted = string.Equals(channel, Preview, StringComparison.OrdinalIgnoreCase)
            ? releases.Releases
            : [.. releases.Releases.Where(r => !r.IsPrerelease)];

        var latest = wanted.Count > 0 ? wanted[0] : null;

        if (latest is null)
        {
            return new UpdateStatus
            {
                Running = running,
                Summary = $"Running {running}. Nothing has been released on the {channel} channel yet.",
            };
        }

        // A development build is not behind a release, it is beside one.
        // Saying "update available" to somebody running their own build would
        // be telling them to overwrite it.
        //
        // Decided from the version passed in, not from what this assembly
        // happens to be stamped with. They are usually the same and the
        // difference matters: the caller knows what is deployed, and a
        // library consulting its own stamp would override them with it.
        if (string.Equals(running, BuildInfo.DevelopmentVersion, StringComparison.Ordinal))
        {
            return new UpdateStatus
            {
                Running = running,
                Latest = latest,
                Summary = $"Running a development build. The newest release is {latest.Version}, "
                        + $"published {latest.PublishedAt:yyyy-MM-dd}.",
            };
        }

        var newer = IsNewer(latest.Version, running);

        return new UpdateStatus
        {
            Running = running,
            Latest = latest,
            UpdateAvailable = newer,
            Summary = newer
                ? $"{latest.Version} is available, published {latest.PublishedAt:yyyy-MM-dd}. Running {running}."
                : $"Running {running}, which is the newest release on the {channel} channel.",
        };
    }

    /// <summary>
    /// Whether one version is newer than another.
    /// </summary>
    /// <remarks>
    /// Refuses rather than guesses. Anything that does not parse as a plain
    /// numeric version returns false, because the cost of the two mistakes is
    /// not equal: failing to mention an update is a missed line on a page, and
    /// wrongly announcing one sends somebody to replace a working install.
    /// </remarks>
    internal static bool IsNewer(string candidate, string running)
    {
        if (!TryParse(candidate, out var left) || !TryParse(running, out var right)) { return false; }

        return left > right;
    }

    private static bool TryParse(string text, out Version version)
    {
        version = new Version(0, 0);

        var trimmed = (text ?? "").Trim().TrimStart('v', 'V');

        // A prerelease suffix is dropped for the comparison: 1.3.0-rc1 and
        // 1.3.0 order the same way against 1.2.0, which is all this decides.
        var core = trimmed.Split('-', '+')[0];

        return Version.TryParse(core, out version!) || Version.TryParse(core + ".0", out version!);
    }

    private async Task<(IReadOnlyList<Release> Releases, string? Problem)> ListAsync(
        string repository, string? token, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"https://api.github.com/repos/{repository.Trim('/')}/releases?per_page=20");

        // GitHub rejects requests with no User-Agent outright.
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("DmarcMonitor", BuildInfo.Version));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        if (!string.IsNullOrWhiteSpace(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());
        }

        try
        {
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

            if (response.StatusCode is HttpStatusCode.NotFound)
            {
                // The same answer for "no such repository" and "private, and
                // this token cannot see it", because that is what GitHub
                // returns for both - so the message names both.
                return ([], string.IsNullOrWhiteSpace(token)
                    ? $"{repository} was not found. If it is private, an access token is needed."
                    : $"{repository} was not found, or the token cannot see it.");
            }

            if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
            {
                return ([], "GitHub is rate-limiting these requests. An access token raises the limit.");
            }

            if (!response.IsSuccessStatusCode)
            {
                return ([], $"GitHub answered {(int)response.StatusCode}.");
            }

            var payload = await response.Content
                .ReadFromJsonAsync<List<GitHubRelease>>(cancellationToken: ct).ConfigureAwait(false) ?? [];

            return ([.. payload
                .Where(r => !r.Draft && !string.IsNullOrWhiteSpace(r.TagName))
                .OrderByDescending(r => r.PublishedAt)
                .Select(r => new Release(
                    r.TagName!.TrimStart('v', 'V'),
                    string.IsNullOrWhiteSpace(r.Name) ? r.TagName! : r.Name!,
                    r.PublishedAt,
                    r.HtmlUrl ?? "",
                    r.Prerelease))], null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return ([], "GitHub could not be reached.");
        }
    }

    private sealed class GitHubRelease
    {
        [JsonPropertyName("tag_name")] public string? TagName { get; set; }
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("html_url")] public string? HtmlUrl { get; set; }
        [JsonPropertyName("draft")] public bool Draft { get; set; }
        [JsonPropertyName("prerelease")] public bool Prerelease { get; set; }
        [JsonPropertyName("published_at")] public DateTimeOffset PublishedAt { get; set; }
    }
}
