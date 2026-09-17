using System.Net;

namespace DmarcMonitor.Core.Graph;

/// <summary>
/// Honours Microsoft Graph throttling.
/// </summary>
/// <remarks>
/// Graph throttles hard, and a first run against a mailbox holding months of
/// reports is exactly the shape of traffic that triggers it. Ignoring a 429
/// turns one slow run into a failed one, and retrying immediately makes the
/// throttling worse and longer.
///
/// Retry-After is obeyed when Graph sends it, because Graph knows how long it
/// wants to be left alone better than any backoff curve does. Only when it
/// does not is an exponential delay used.
/// </remarks>
public sealed class GraphThrottleHandler : DelegatingHandler
{
    private readonly int _maxRetries;
    private readonly TimeSpan _maxDelay;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    /// <param name="delay">Injectable so tests do not actually sleep.</param>
    public GraphThrottleHandler(
        int maxRetries = 5,
        TimeSpan? maxDelay = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _maxRetries = maxRetries < 0 ? 0 : maxRetries;
        _maxDelay = maxDelay ?? TimeSpan.FromSeconds(60);
        _delay = delay ?? ((d, ct) => Task.Delay(d, ct));
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        HttpResponseMessage? response = null;

        for (var attempt = 0; ; attempt++)
        {
            response?.Dispose();
            response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (!ShouldRetry(response.StatusCode) || attempt >= _maxRetries)
            {
                return response;
            }

            var wait = GetDelay(response, attempt, _maxDelay);
            await _delay(wait, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Whether a status is worth retrying.
    /// </summary>
    /// <remarks>
    /// Deliberately narrow. A 401 or 403 is a configuration problem and
    /// retrying it wastes time and hides the real cause behind a delay.
    /// </remarks>
    public static bool ShouldRetry(HttpStatusCode status) => status is
        HttpStatusCode.TooManyRequests or
        HttpStatusCode.ServiceUnavailable or
        HttpStatusCode.BadGateway or
        HttpStatusCode.GatewayTimeout;

    /// <summary>
    /// How long to wait: Graph's own Retry-After when present, otherwise an
    /// exponential backoff, always bounded.
    /// </summary>
    public static TimeSpan GetDelay(HttpResponseMessage response, int attempt, TimeSpan maxDelay)
    {
        ArgumentNullException.ThrowIfNull(response);

        var retryAfter = response.Headers.RetryAfter;
        if (retryAfter is not null)
        {
            if (retryAfter.Delta is { } delta && delta > TimeSpan.Zero)
            {
                return Clamp(delta, maxDelay);
            }
            if (retryAfter.Date is { } date)
            {
                var wait = date - DateTimeOffset.UtcNow;
                if (wait > TimeSpan.Zero) { return Clamp(wait, maxDelay); }
            }
        }

        // 1s, 2s, 4s, 8s... Attempt is clamped before shifting because a
        // large attempt count would overflow into a negative delay.
        var exponent = Math.Min(attempt, 10);
        return Clamp(TimeSpan.FromSeconds(Math.Pow(2, exponent)), maxDelay);
    }

    private static TimeSpan Clamp(TimeSpan value, TimeSpan max) => value > max ? max : value;
}
