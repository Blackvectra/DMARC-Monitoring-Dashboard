using System.Net;
using System.Net.Http.Headers;
using DmarcMonitor.Core.Graph;

namespace DmarcMonitor.Core.Tests.Graph;

/// <summary>
/// Throttle handling.
///
/// A first run against a mailbox holding months of reports is exactly the
/// shape of traffic Graph throttles. Ignoring a 429 turns one slow run into a
/// failed one; retrying immediately makes the throttling longer.
/// </summary>
public sealed class GraphThrottleHandlerTests
{
    private static HttpResponseMessage WithRetryAfter(TimeSpan? delta = null, DateTimeOffset? date = null)
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        if (delta is { } d) { response.Headers.RetryAfter = new RetryConditionHeaderValue(d); }
        if (date is { } dt) { response.Headers.RetryAfter = new RetryConditionHeaderValue(dt); }
        return response;
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests, true)]
    [InlineData(HttpStatusCode.ServiceUnavailable, true)]
    [InlineData(HttpStatusCode.BadGateway, true)]
    [InlineData(HttpStatusCode.GatewayTimeout, true)]
    [InlineData(HttpStatusCode.Unauthorized, false)]
    [InlineData(HttpStatusCode.Forbidden, false)]
    [InlineData(HttpStatusCode.NotFound, false)]
    [InlineData(HttpStatusCode.OK, false)]
    public void RetriesOnlyWhatIsWorthRetrying(HttpStatusCode status, bool expected)
    {
        // A 401 or 403 is a configuration problem. Retrying it wastes time and
        // hides the real cause behind a delay.
        Assert.Equal(expected, GraphThrottleHandler.ShouldRetry(status));
    }

    [Fact]
    public void ObeysRetryAfterInSeconds()
    {
        // Graph knows how long it wants to be left alone better than any
        // backoff curve does.
        using var response = WithRetryAfter(delta: TimeSpan.FromSeconds(17));
        Assert.Equal(TimeSpan.FromSeconds(17), GraphThrottleHandler.GetDelay(response, 0, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void ObeysRetryAfterGivenAsADate()
    {
        using var response = WithRetryAfter(date: DateTimeOffset.UtcNow.AddSeconds(30));
        var delay = GraphThrottleHandler.GetDelay(response, 0, TimeSpan.FromMinutes(5));
        Assert.InRange(delay, TimeSpan.FromSeconds(25), TimeSpan.FromSeconds(31));
    }

    [Fact]
    public void BacksOffExponentiallyWhenGraphSaysNothing()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        var max = TimeSpan.FromMinutes(5);

        Assert.Equal(TimeSpan.FromSeconds(1), GraphThrottleHandler.GetDelay(response, 0, max));
        Assert.Equal(TimeSpan.FromSeconds(2), GraphThrottleHandler.GetDelay(response, 1, max));
        Assert.Equal(TimeSpan.FromSeconds(4), GraphThrottleHandler.GetDelay(response, 2, max));
        Assert.Equal(TimeSpan.FromSeconds(8), GraphThrottleHandler.GetDelay(response, 3, max));
    }

    [Fact]
    public void NeverWaitsLongerThanTheCap()
    {
        // Graph can ask for a very long wait. A run that sleeps for an hour
        // inside a twenty-five minute window achieves nothing.
        using var response = WithRetryAfter(delta: TimeSpan.FromHours(2));
        Assert.Equal(TimeSpan.FromSeconds(60), GraphThrottleHandler.GetDelay(response, 0, TimeSpan.FromSeconds(60)));
    }

    [Fact]
    public void DoesNotOverflowIntoANegativeDelayOnALargeAttemptCount()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        var delay = GraphThrottleHandler.GetDelay(response, 1000, TimeSpan.FromSeconds(60));
        Assert.True(delay > TimeSpan.Zero);
        Assert.True(delay <= TimeSpan.FromSeconds(60));
    }

    [Fact]
    public void IgnoresARetryAfterInThePast()
    {
        using var response = WithRetryAfter(date: DateTimeOffset.UtcNow.AddMinutes(-5));
        Assert.True(GraphThrottleHandler.GetDelay(response, 0, TimeSpan.FromMinutes(1)) > TimeSpan.Zero);
    }

    [Fact]
    public async Task RetriesAThrottledRequestAndEventuallySucceeds()
    {
        var stub = new StubHttpMessageHandler()
            .WhenSequence("/messages",
                (HttpStatusCode.TooManyRequests, "{}"),
                (HttpStatusCode.TooManyRequests, "{}"),
                (HttpStatusCode.OK, """{"value":[]}"""));

        var handler = new GraphThrottleHandler(maxRetries: 5, delay: (_, _) => Task.CompletedTask)
        {
            InnerHandler = stub,
        };
        using var http = new HttpClient(handler);

        using var response = await http.GetAsync(new Uri("https://graph.microsoft.com/v1.0/messages"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(3, stub.Requests.Count);
    }

    [Fact]
    public async Task GivesUpAfterTheRetryLimitRatherThanLoopingForever()
    {
        var stub = new StubHttpMessageHandler().When("/messages", HttpStatusCode.TooManyRequests, "{}");

        var handler = new GraphThrottleHandler(maxRetries: 3, delay: (_, _) => Task.CompletedTask)
        {
            InnerHandler = stub,
        };
        using var http = new HttpClient(handler);

        using var response = await http.GetAsync(new Uri("https://graph.microsoft.com/v1.0/messages"));

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal(4, stub.Requests.Count);   // the original plus three retries
    }

    [Fact]
    public async Task DoesNotRetryAConfigurationError()
    {
        var stub = new StubHttpMessageHandler().When("/messages", HttpStatusCode.Forbidden, "{}");

        var handler = new GraphThrottleHandler(maxRetries: 5, delay: (_, _) => Task.CompletedTask)
        {
            InnerHandler = stub,
        };
        using var http = new HttpClient(handler);

        using var response = await http.GetAsync(new Uri("https://graph.microsoft.com/v1.0/messages"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Single(stub.Requests);
    }
}
