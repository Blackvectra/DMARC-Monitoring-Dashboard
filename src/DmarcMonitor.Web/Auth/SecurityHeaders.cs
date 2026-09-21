namespace DmarcMonitor.Web.Auth;

/// <summary>
/// The response headers a browser needs in order to defend the pages it is
/// given.
/// </summary>
/// <remarks>
/// None of these were being sent. They are defense in depth rather than a fix
/// for a known hole - Blazor escapes what it renders, and the client report
/// escapes every field it takes from a DMARC report - but this app shows one
/// customer's mail data to people who must not see another's, and the cost of
/// a header is nothing.
///
/// The content security policy is honest about what this app does rather than
/// aspirational. <c>script-src</c> has to allow inline script, because the
/// shell's menu and theme buttons carry <c>onclick</c> attributes: the layout
/// has no render mode, so a Blazor handler there is never wired up, and plain
/// JavaScript is what works. It still forbids script from anywhere but this
/// origin, which is the injection that matters for an app installed on
/// somebody else's server. Tightening it further means moving three handlers
/// to addEventListener and hashing the boot script, which is a change to
/// behavior rather than a header, so it is not done here.
/// </remarks>
public static class SecurityHeaders
{
    /// <summary>
    /// What the app itself may load: nothing from anywhere but here, except
    /// images, which include an organization's logo as a data: URL.
    /// </summary>
    private const string AppPolicy =
        "default-src 'self'; " +
        "img-src 'self' data:; " +
        "style-src 'self' 'unsafe-inline'; " +      // charts and the brand accent are inline styles
        "script-src 'self' 'unsafe-inline'; " +     // the shell's onclick handlers
        "connect-src 'self'; " +                    // Blazor's circuit, same origin
        "font-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'";

    /// <summary>
    /// What a client report may do: draw itself, and nothing else.
    /// </summary>
    /// <remarks>
    /// The report is a standalone document built to open with no network at
    /// all - that is already a test - so it can be held to a policy the app
    /// cannot be. It is also the one page here rendered from data a stranger
    /// supplied: anybody can send a report to a customer's rua address, and
    /// every field of it lands in this document. The escaping is tested and
    /// holds; this is the second lock.
    /// </remarks>
    private const string ReportPolicy =
        "default-src 'none'; " +
        "img-src data:; " +
        "style-src 'unsafe-inline'; " +
        "script-src 'none'; " +
        "object-src 'none'; " +
        "base-uri 'none'; " +
        "form-action 'none'; " +
        "frame-ancestors 'none'";

    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use(async (context, next) =>
        {
            // Set before the response starts, because headers cannot be added
            // once the first byte has gone.
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;

                // A report is data from strangers rendered as a document, and
                // needs none of what the app needs.
                var isReport = context.Request.Path.StartsWithSegments("/reports/download");

                // Only set what is not already there: a proxy in front, or a
                // later change here, should win rather than be duplicated.
                if (!headers.ContainsKey("Content-Security-Policy"))
                {
                    headers["Content-Security-Policy"] = isReport ? ReportPolicy : AppPolicy;
                }

                // Stops a browser deciding for itself that something is script.
                headers["X-Content-Type-Options"] = "nosniff";

                // Every URL here names a customer: /domains/acme.com says who
                // this provider looks after. It does not leave this app.
                headers["Referrer-Policy"] = "no-referrer";

                // Nothing embeds this, and framing it is how a click gets
                // stolen. frame-ancestors above says the same to anything
                // recent; this is for what is not.
                headers["X-Frame-Options"] = "DENY";

                return Task.CompletedTask;
            });

            await next().ConfigureAwait(false);
        });
    }
}
