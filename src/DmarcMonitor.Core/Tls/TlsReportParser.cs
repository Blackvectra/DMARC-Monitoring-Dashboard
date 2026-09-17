using System.Globalization;
using System.Text.Json;

namespace DmarcMonitor.Core.Tls;

/// <summary>
/// Parses a TLS-RPT report (RFC 8460).
///
/// JSON rather than XML, so a different set of real-world hazards from the
/// DMARC parser: fields that are sometimes a string and sometimes an array,
/// counts that arrive quoted, and whole sections omitted when there is
/// nothing to report.
///
/// Same contract as the DMARC parser: tolerant of shape, never of meaning. A
/// report that cannot be read is a failure with a reason, never an
/// empty-but-successful result, because "no sessions" and "unreadable" would
/// otherwise render identically to an operator.
/// </summary>
public static class TlsReportParser
{
    public static TlsParseResult Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return TlsParseResult.Failed("The report was empty.");
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
                // Deep nesting is the JSON equivalent of an entity bomb, and
                // this arrives as an email attachment from anyone.
                MaxDepth = 64,
            });
        }
        catch (JsonException ex)
        {
            return TlsParseResult.Failed($"The report is not valid JSON: {ex.Message}");
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return TlsParseResult.Failed(
                    $"The report's top level is {root.ValueKind}, not an object, so it is not a TLS report.");
            }

            // policies is what makes this a TLS report rather than arbitrary
            // JSON that happens to have a report-id.
            if (!TryGet(root, "policies", out var policiesEl) || policiesEl.ValueKind != JsonValueKind.Array)
            {
                return TlsParseResult.Failed(
                    "The file is JSON but not a TLS report: it has no 'policies' array.");
            }

            var policies = new List<TlsPolicyResult>();
            foreach (var pEl in policiesEl.EnumerateArray())
            {
                var parsed = ParsePolicyResult(pEl);
                if (parsed is not null) { policies.Add(parsed); }
            }

            var (begin, end) = ParseDateRange(root);

            return TlsParseResult.Succeeded(new TlsReport
            {
                OrganizationName = Str(root, "organization-name"),
                ContactInfo = Str(root, "contact-info"),
                ReportId = Str(root, "report-id"),
                Begin = begin,
                End = end,
                Policies = policies,
            });
        }
    }

    private static TlsPolicyResult? ParsePolicyResult(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object) { return null; }

        var policyEl = TryGet(el, "policy", out var p) ? p : default;
        var policyStrings = StringList(policyEl, "policy-string");

        var policy = new TlsPolicy
        {
            Type = ParsePolicyType(Str(policyEl, "policy-type")),
            Domain = Str(policyEl, "policy-domain").Trim().TrimEnd('.').ToLowerInvariant(),
            PolicyStrings = policyStrings,
            // Sometimes an array, sometimes a bare string, sometimes absent.
            MxHosts = StringList(policyEl, "mx-host"),
            Mode = ParseMode(policyStrings),
        };

        var summaryEl = TryGet(el, "summary", out var s) ? s : default;

        var failures = new List<TlsFailureDetail>();
        if (TryGet(el, "failure-details", out var fdEl) && fdEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var f in fdEl.EnumerateArray())
            {
                if (f.ValueKind != JsonValueKind.Object) { continue; }
                var raw = Str(f, "result-type");
                failures.Add(new TlsFailureDetail
                {
                    ResultType = ParseFailureType(raw),
                    RawResultType = raw,
                    SendingMtaIp = Str(f, "sending-mta-ip"),
                    ReceivingMxHostname = Str(f, "receiving-mx-hostname"),
                    ReceivingMxHelo = Str(f, "receiving-mx-helo"),
                    ReceivingIp = Str(f, "receiving-ip"),
                    FailedSessionCount = Num(f, "failed-session-count"),
                    AdditionalInformation = Str(f, "additional-information"),
                    FailureReasonCode = Str(f, "failure-reason-code"),
                });
            }
        }

        return new TlsPolicyResult
        {
            Policy = policy,
            SuccessfulSessionCount = Num(summaryEl, "total-successful-session-count"),
            FailedSessionCount = Num(summaryEl, "total-failure-session-count"),
            Failures = failures,
        };
    }

    /// <summary>
    /// Reads the MTA-STS mode out of the policy the receiver actually fetched.
    /// </summary>
    /// <remarks>
    /// The policy arrives as lines of "key: value". Read from here rather than
    /// from live DNS, because the report describes what was in force during
    /// the window, which is not necessarily what is published today.
    /// </remarks>
    private static MtaStsMode ParseMode(IReadOnlyList<string> policyStrings)
    {
        foreach (var line in policyStrings)
        {
            var idx = line.IndexOf(':', StringComparison.Ordinal);
            if (idx < 0) { continue; }

            var key = line[..idx].Trim();
            if (!string.Equals(key, "mode", StringComparison.OrdinalIgnoreCase)) { continue; }

            return line[(idx + 1)..].Trim().ToLowerInvariant() switch
            {
                "enforce" => MtaStsMode.Enforce,
                "testing" => MtaStsMode.Testing,
                "none" => MtaStsMode.None,
                _ => MtaStsMode.Unknown,
            };
        }
        return MtaStsMode.Unknown;
    }

    private static (DateTimeOffset Begin, DateTimeOffset End) ParseDateRange(JsonElement root)
    {
        if (!TryGet(root, "date-range", out var dr) || dr.ValueKind != JsonValueKind.Object)
        {
            return (DateTimeOffset.MinValue, DateTimeOffset.MinValue);
        }
        return (Date(dr, "start-datetime"), Date(dr, "end-datetime"));
    }

    // ---- value access -------------------------------------------------------

    private static bool TryGet(JsonElement parent, string name, out JsonElement value)
    {
        if (parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out value))
        {
            return true;
        }
        value = default;
        return false;
    }

    private static string Str(JsonElement parent, string name)
    {
        if (!TryGet(parent, name, out var el)) { return ""; }
        return el.ValueKind switch
        {
            JsonValueKind.String => el.GetString()?.Trim() ?? "",
            JsonValueKind.Number => el.ToString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => "",
        };
    }

    /// <summary>
    /// A count, accepting both a JSON number and a quoted one. Implementations
    /// differ, and a session count silently read as zero would report a
    /// failing domain as having sent no mail.
    /// </summary>
    private static long Num(JsonElement parent, string name)
    {
        if (!TryGet(parent, name, out var el)) { return 0; }

        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt64(out var n))
        {
            return n < 0 ? 0 : n;
        }
        if (el.ValueKind == JsonValueKind.String &&
            long.TryParse(el.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var s))
        {
            return s < 0 ? 0 : s;
        }
        return 0;
    }

    /// <summary>
    /// A field that is an array of strings, a single string, or absent.
    /// Microsoft omits mx-host where Google sends an array, and the RFC's
    /// examples are not consistent either.
    /// </summary>
    private static List<string> StringList(JsonElement parent, string name)
    {
        if (!TryGet(parent, name, out var el)) { return []; }

        if (el.ValueKind == JsonValueKind.String)
        {
            var single = el.GetString()?.Trim();
            return string.IsNullOrEmpty(single) ? [] : [single];
        }

        if (el.ValueKind != JsonValueKind.Array) { return []; }

        var list = new List<string>();
        foreach (var item in el.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) { continue; }
            var v = item.GetString()?.Trim();
            if (!string.IsNullOrEmpty(v)) { list.Add(v); }
        }
        return list;
    }

    private static DateTimeOffset Date(JsonElement parent, string name)
    {
        var raw = Str(parent, name);
        if (DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
        {
            return dto;
        }
        return DateTimeOffset.MinValue;
    }

    private static TlsPolicyType ParsePolicyType(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "sts" => TlsPolicyType.Sts,
        "tlsa" => TlsPolicyType.Tlsa,
        "no-policy-found" => TlsPolicyType.NoPolicyFound,
        _ => TlsPolicyType.Unknown,
    };

    private static TlsFailureType ParseFailureType(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "starttls-not-supported" => TlsFailureType.StartTlsNotSupported,
        "certificate-host-mismatch" => TlsFailureType.CertificateHostMismatch,
        "certificate-expired" => TlsFailureType.CertificateExpired,
        "certificate-not-trusted" => TlsFailureType.CertificateNotTrusted,
        "validation-failure" => TlsFailureType.ValidationFailure,
        "tlsa-invalid" => TlsFailureType.TlsaInvalid,
        "dnssec-invalid" => TlsFailureType.DnssecInvalid,
        "dane-required" => TlsFailureType.DaneRequired,
        "sts-policy-fetch-error" => TlsFailureType.StsPolicyFetchError,
        "sts-policy-invalid" => TlsFailureType.StsPolicyInvalid,
        "sts-webpki-invalid" => TlsFailureType.StsWebpkiInvalid,
        _ => TlsFailureType.Unknown,
    };
}

public sealed record TlsParseResult
{
    public bool Success { get; private init; }
    public TlsReport? Report { get; private init; }
    public string Error { get; private init; } = "";

    public static TlsParseResult Succeeded(TlsReport report) => new() { Success = true, Report = report };
    public static TlsParseResult Failed(string error) => new() { Success = false, Error = error };
}
