using System.Net;
using System.Text;

namespace DmarcMonitor.Core.Tests.Graph;

/// <summary>
/// Answers HTTP requests from a script, and records what was asked.
///
/// Lets the Graph client's paging, error translation and folder handling be
/// tested without a tenant, which is the whole reason HttpClient is injected
/// rather than constructed.
/// </summary>
public sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly List<Func<HttpRequestMessage, HttpResponseMessage?>> _rules = [];

    public List<HttpRequestMessage> Requests { get; } = [];

    /// <summary>Responds to any request whose URL contains <paramref name="match"/>.</summary>
    public StubHttpMessageHandler When(string match, HttpStatusCode status, string body, string contentType = "application/json")
    {
        _rules.Add(req =>
            req.RequestUri!.ToString().Contains(match, StringComparison.OrdinalIgnoreCase)
                ? new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, contentType) }
                : null);
        return this;
    }

    /// <summary>Responds with raw bytes, for attachment content.</summary>
    public StubHttpMessageHandler WhenBytes(string match, byte[] content)
    {
        _rules.Add(req =>
            req.RequestUri!.ToString().Contains(match, StringComparison.OrdinalIgnoreCase)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(content) }
                : null);
        return this;
    }

    /// <summary>Responds differently on each successive matching call.</summary>
    public StubHttpMessageHandler WhenSequence(string match, params (HttpStatusCode Status, string Body)[] responses)
    {
        var index = 0;
        _rules.Add(req =>
        {
            if (!req.RequestUri!.ToString().Contains(match, StringComparison.OrdinalIgnoreCase)) { return null; }
            var (status, body) = responses[Math.Min(index++, responses.Length - 1)];
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        });
        return this;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);

        foreach (var rule in _rules)
        {
            var response = rule(request);
            if (response is not null) { return Task.FromResult(response); }
        }

        // An unmatched request is a test that does not describe reality, so it
        // fails loudly rather than returning a plausible empty result.
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotImplemented)
        {
            Content = new StringContent(
                $$$"""{"error":{"code":"StubUnmatched","message":"No stub rule for {{{request.RequestUri}}}"}}""",
                Encoding.UTF8, "application/json"),
        });
    }
}
