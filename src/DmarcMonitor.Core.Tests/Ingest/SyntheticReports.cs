using System.IO.Compression;
using System.Text;

namespace DmarcMonitor.Core.Tests.Ingest;

/// <summary>
/// Reports, archives and damaged archives, made up in the test.
/// </summary>
/// <remarks>
/// Made up rather than copied from the fixtures, so that what is broken, and
/// how, is written down beside the tests that depend on it, and so no real
/// customer's report has to be committed to prove a zip can be damaged.
/// Domains are the ones RFC 2606 keeps for examples.
/// </remarks>
internal static class SyntheticReports
{
    /// <summary>A DMARC aggregate report the parser and the store both accept.</summary>
    public static string AggregateXml(string reportId, string domain = "example.org") => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <feedback>
          <report_metadata>
            <org_name>receiver.example</org_name>
            <email>noreply@receiver.example</email>
            <report_id>{reportId}</report_id>
            <date_range><begin>1757894400</begin><end>1757980799</end></date_range>
          </report_metadata>
          <policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>
          <record>
            <row><source_ip>192.0.2.25</source_ip><count>5</count>
              <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
            <identifiers><header_from>{domain}</header_from></identifiers>
            <auth_results><dkim><domain>{domain}</domain><result>pass</result></dkim><spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
          </record>
        </feedback>
        """;

    /// <summary>One MTA-STS policy for the domain, for <see cref="TlsJson"/>.</summary>
    public static string TlsPolicy(string domain = "example.org") => $$$"""
        [{"policy":{"policy-type":"sts","policy-string":["version: STSv1","mode: testing"],"policy-domain":"{{{domain}}}"},
          "summary":{"total-successful-session-count":10,"total-failure-session-count":0}}]
        """;

    /// <summary>A TLS report; pass "[]" as the policies for one naming no domain.</summary>
    public static string TlsJson(string reportId, string? policies = null) => $$$"""
        {"organization-name":"receiver.example","report-id":"{{{reportId}}}",
         "date-range":{"start-datetime":"2026-09-15T00:00:00Z","end-datetime":"2026-09-15T23:59:59Z"},
         "policies":{{{policies ?? TlsPolicy()}}}}
        """;

    public static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    public static byte[] Gzip(string text)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(Bytes(text));
        }
        return ms.ToArray();
    }

    /// <summary>The first half of a gzip file, as a transfer cut off part way leaves it.</summary>
    public static byte[] CutShort(byte[] content) => content[..(content.Length / 2)];

    public static byte[] Zip(params (string Name, byte[] Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(content);
            }
        }
        return ms.ToArray();
    }

    /// <summary>
    /// A zip that opens and then throws when its entries are read: the end
    /// record is intact, and the list of contents it points at is not.
    /// </summary>
    public static byte[] WithDamagedListOfContents(byte[] zip)
    {
        var copy = zip.ToArray();
        var at = copy.AsSpan().IndexOf([(byte)0x50, (byte)0x4B, (byte)0x01, (byte)0x02]);
        if (at < 0) { throw new InvalidOperationException("the zip has no list of contents to damage"); }
        copy[at + 2] = 0x09;
        return copy;
    }
}
