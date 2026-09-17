using System.Net;
using System.Text.Json;

namespace DmarcMonitor.Core.Graph;

/// <summary>
/// A Graph call that failed, translated into something an operator can act on.
/// </summary>
/// <remarks>
/// Raised rather than swallowed. The failure mode to avoid above all others
/// is a misconfigured deployment that returns zero messages and looks like a
/// quiet mailbox: an operator would wait days for reports that were never
/// going to arrive, and nothing would say why.
/// </remarks>
public sealed class GraphException : Exception
{
    public HttpStatusCode StatusCode { get; }

    /// <summary>Graph's own error code, when it sent one.</summary>
    public string GraphCode { get; }

    public GraphException(HttpStatusCode statusCode, string graphCode, string message)
        : base(message)
    {
        StatusCode = statusCode;
        GraphCode = graphCode;
    }

    public GraphException(HttpStatusCode statusCode, string graphCode, string message, Exception inner)
        : base(message, inner)
    {
        StatusCode = statusCode;
        GraphCode = graphCode;
    }
}

/// <summary>
/// Turns a Graph error response into a sentence that names the likely cause
/// and what to check.
/// </summary>
public static class GraphError
{
    /// <summary>
    /// Builds the exception for a failed response.
    /// </summary>
    /// <param name="mailbox">Included in the message, because most of these failures are per-mailbox.</param>
    public static GraphException Translate(HttpStatusCode status, string? body, string mailbox)
    {
        var (code, detail) = Parse(body);

        var explanation = status switch
        {
            HttpStatusCode.Unauthorized =>
                "Authentication to Microsoft Graph failed. The certificate, its thumbprint, the application id or the "
                + "tenant id is wrong, or the certificate has expired. Check that the certificate in the store matches "
                + "the one uploaded to the app registration.",

            HttpStatusCode.Forbidden when code.Contains("AccessDenied", StringComparison.OrdinalIgnoreCase) =>
                $"Microsoft Graph refused access to {mailbox}. The app registration needs the Mail.ReadWrite "
                + "APPLICATION permission with admin consent granted, and if an application access policy is in place "
                + "it must include this mailbox. A policy that excludes the mailbox produces exactly this error even "
                + "when the permission is correct.",

            HttpStatusCode.Forbidden =>
                $"Microsoft Graph refused access to {mailbox}. The most likely cause is a missing Mail.ReadWrite "
                + "application permission or missing admin consent.",

            HttpStatusCode.NotFound =>
                $"Microsoft Graph could not find {mailbox}, or the folder being read. Check the mailbox address is "
                + "exactly right and that the mailbox still exists.",

            HttpStatusCode.TooManyRequests =>
                "Microsoft Graph is throttling this application. The run backed off and retried, and still could not "
                + "get through. It will make progress on the next run, because processed mail is moved out of the way.",

            HttpStatusCode.ServiceUnavailable or HttpStatusCode.BadGateway or HttpStatusCode.GatewayTimeout =>
                "Microsoft Graph is temporarily unavailable. Nothing is wrong with the configuration; the next "
                + "scheduled run will continue from where this one stopped.",

            HttpStatusCode.RequestEntityTooLarge =>
                "Microsoft Graph refused the request as too large. This usually means an unusually large attachment.",

            _ => $"Microsoft Graph returned {(int)status} {status}.",
        };

        var full = string.IsNullOrWhiteSpace(detail)
            ? explanation
            : $"{explanation} Graph said: {detail}";

        return new GraphException(status, code, full);
    }

    /// <summary>
    /// Pulls the code and message out of Graph's error envelope.
    /// </summary>
    /// <remarks>
    /// Returns empty strings rather than throwing on anything unexpected. A
    /// parse failure while building an error message would replace a useful
    /// diagnostic with a useless one.
    /// </remarks>
    public static (string Code, string Message) Parse(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) { return ("", ""); }

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) { return ("", ""); }
            if (!doc.RootElement.TryGetProperty("error", out var err) || err.ValueKind != JsonValueKind.Object)
            {
                return ("", "");
            }

            var code = err.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String
                ? c.GetString() ?? "" : "";
            var message = err.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String
                ? m.GetString() ?? "" : "";

            return (code, message);
        }
        catch (JsonException)
        {
            return ("", "");
        }
    }
}
