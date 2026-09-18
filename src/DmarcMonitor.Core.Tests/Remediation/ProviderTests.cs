using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using DmarcMonitor.Core.Remediation;

namespace DmarcMonitor.Core.Tests.Remediation;

/// <summary>
/// The two real providers, against a recorded HTTP conversation.
///
/// What matters is the shape of what goes over the wire: Cloudflare's quoted
/// TXT content, Azure's whole-set writes. Both are places a write that looks
/// right in a unit test deletes something in a customer's zone.
/// </summary>
public sealed class ProviderTests
{
    /// <summary>Answers each request from a script and keeps what was sent.</summary>
    private sealed class Script : HttpMessageHandler
    {
        private readonly Queue<(HttpStatusCode Status, string Body)> _answers = new();
        public List<(HttpMethod Method, string Path, string Body)> Sent { get; } = [];

        /// <summary>Headers per request, so a conditional write can be checked.</summary>
        public List<Dictionary<string, string[]>> Headers { get; } = [];

        public Script Then(HttpStatusCode status, string body)
        {
            _answers.Enqueue((status, body));
            return this;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            Sent.Add((request.Method, request.RequestUri!.PathAndQuery, body));
            Headers.Add(request.Headers.ToDictionary(h => h.Key, h => h.Value.ToArray(), StringComparer.OrdinalIgnoreCase));

            var (status, answer) = _answers.Count > 0 ? _answers.Dequeue() : (HttpStatusCode.InternalServerError, "{}");
            return new HttpResponseMessage(status) { Content = new StringContent(answer, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class FakeCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext ctx, CancellationToken ct) => new("token", DateTimeOffset.MaxValue);
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext ctx, CancellationToken ct) => new(GetToken(ctx, ct));
    }

    // ---- Cloudflare -----------------------------------------------------------

    [Theory]
    [InlineData("\"v=spf1 -all\"", "v=spf1 -all")]
    [InlineData("v=spf1 -all", "v=spf1 -all")]
    [InlineData("\"v=spf1 include:a.example\" \"include:b.example -all\"", "v=spf1 include:a.exampleinclude:b.example -all")]
    [InlineData("\"say \\\"hi\\\"\"", "say \"hi\"")]
    public void CloudflareContentIsUnquoted(string wire, string expected)
    {
        // Cloudflare returns TXT content quoted. Stored quoted, no snapshot
        // ever equals what a resolver returns, and every rollback target
        // looks stale.
        Assert.Equal(expected, CloudflareDnsProvider.Unquote(wire));
    }

    [Fact]
    public async Task CloudflareReplacesByIdWithAPut()
    {
        var script = new Script()
            .Then(HttpStatusCode.OK, """{"success":true,"errors":[],"result":{"id":"rec1","type":"TXT","name":"_dmarc.acme.com","content":"\"v=DMARC1; p=quarantine\"","ttl":300}}""");
        var provider = new CloudflareDnsProvider(new HttpClient(script), "zone1", "token");

        var result = await provider.SetRecordAsync(new DnsRecordWrite("_dmarc.acme.com", "TXT", "v=DMARC1; p=quarantine", ReplacesId: "rec1"));

        Assert.True(result.Success);
        Assert.Equal("rec1", result.Id);
        var (method, path, body) = Assert.Single(script.Sent);
        Assert.Equal(HttpMethod.Put, method);
        Assert.Equal("/client/v4/zones/zone1/dns_records/rec1", path);
        Assert.Contains("\"content\":\"v=DMARC1; p=quarantine\"", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CloudflareAddsWithAPostWhenNothingIsReplaced()
    {
        var script = new Script()
            .Then(HttpStatusCode.OK, """{"success":true,"errors":[],"result":{"id":"new1","type":"TXT","name":"_dmarc.acme.com","content":"x","ttl":300}}""");
        var provider = new CloudflareDnsProvider(new HttpClient(script), "zone1", "token");

        var result = await provider.SetRecordAsync(new DnsRecordWrite("_dmarc.acme.com", "TXT", "v=DMARC1; p=none"));

        Assert.True(result.Success);
        Assert.Equal(HttpMethod.Post, script.Sent[0].Method);
        Assert.Equal("/client/v4/zones/zone1/dns_records", script.Sent[0].Path);
    }

    [Fact]
    public async Task CloudflareSaysWhyARefusalHappened()
    {
        // The reason is in the body. "HTTP 403" tells an operator nothing;
        // "token lacks permission" tells them what to fix.
        var script = new Script()
            .Then(HttpStatusCode.Forbidden, """{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}""");
        var provider = new CloudflareDnsProvider(new HttpClient(script), "zone1", "token");

        var result = await provider.SetRecordAsync(new DnsRecordWrite("_dmarc.acme.com", "TXT", "x"));

        Assert.False(result.Success);
        Assert.Contains("Authentication error", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CloudflareReadsAreUnquotedAndCarryTheId()
    {
        var script = new Script()
            .Then(HttpStatusCode.OK, """{"success":true,"errors":[],"result":[{"id":"rec1","type":"TXT","name":"_dmarc.acme.com","content":"\"v=DMARC1; p=none\"","ttl":1}]}""");
        var provider = new CloudflareDnsProvider(new HttpClient(script), "zone1", "token");

        var records = await provider.GetRecordsAsync("_dmarc.acme.com", "TXT");

        var only = Assert.Single(records);
        Assert.Equal("v=DMARC1; p=none", only.Value);
        Assert.Equal("rec1", only.Id);
        Assert.Contains("type=TXT&name=_dmarc.acme.com", script.Sent[0].Path, StringComparison.Ordinal);
    }

    // ---- Azure -------------------------------------------------------------------

    [Theory]
    [InlineData("acme.com", "acme.com", "@")]
    [InlineData("_dmarc.acme.com", "acme.com", "_dmarc")]
    [InlineData("_dmarc.acme.com.", "ACME.com", "_dmarc")]
    public void AzureAddressesRecordsRelativeToTheZone(string name, string zone, string expected)
    {
        Assert.Equal(expected, AzureDnsProvider.Relative(name, zone));
    }

    [Fact]
    public void AzureRefusesANameOutsideTheZone()
    {
        Assert.Throws<ArgumentException>(() => AzureDnsProvider.Relative("_dmarc.other.com", "acme.com"));
    }

    [Fact]
    public void AzureSplitsLongValuesAt255()
    {
        var chunks = AzureDnsProvider.Chunk(new string('a', 300));

        Assert.Equal(2, chunks.Count);
        Assert.Equal(255, chunks[0].Length);
        Assert.Equal(45, chunks[1].Length);
    }

    [Fact]
    public async Task AzureReplacesOneValueAndWritesTheWholeSetBack()
    {
        // The apex holds the SPF record and two verification tokens in one
        // record set. Replacing the SPF must write back all three, or the
        // tokens are gone and two services stop trusting the domain.
        var existing = """{"properties":{"TTL":3600,"TXTRecords":[{"value":["v=spf1 include:a.example -all"]},{"value":["MS=ms1"]},{"value":["google-site-verification=x"]}]}}""";
        var script = new Script().Then(HttpStatusCode.OK, existing).Then(HttpStatusCode.OK, "{}");
        var provider = new AzureDnsProvider(new HttpClient(script), new FakeCredential(), "sub", "rg", "acme.com");

        var result = await provider.SetRecordAsync(new DnsRecordWrite("acme.com", "TXT", "v=spf1 -all", ReplacesValue: "v=spf1 include:a.example -all"));

        Assert.True(result.Success);
        var put = script.Sent[1];
        Assert.Equal(HttpMethod.Put, put.Method);
        Assert.Contains("/dnsZones/acme.com/TXT/@?api-version=", put.Path, StringComparison.Ordinal);

        var body = JsonDocument.Parse(put.Body).RootElement.GetProperty("properties");
        Assert.Equal(3600, body.GetProperty("TTL").GetInt32());
        var values = body.GetProperty("TXTRecords").EnumerateArray().Select(e => string.Concat(e.GetProperty("value").EnumerateArray().Select(v => v.GetString()))).ToList();
        Assert.Equal(["v=spf1 -all", "MS=ms1", "google-site-verification=x"], values);
    }

    [Fact]
    public async Task AzureRefusesToReplaceAValueThatIsNoLongerThere()
    {
        var script = new Script().Then(HttpStatusCode.OK, """{"properties":{"TTL":300,"TXTRecords":[{"value":["v=spf1 -all"]}]}}""");
        var provider = new AzureDnsProvider(new HttpClient(script), new FakeCredential(), "sub", "rg", "acme.com");

        var result = await provider.SetRecordAsync(new DnsRecordWrite("acme.com", "TXT", "new", ReplacesValue: "old"));

        Assert.False(result.Success);
        Assert.Single(script.Sent);   // read only; nothing written
    }

    [Fact]
    public async Task AzureNotFoundIsAnEmptyNameNotAnError()
    {
        var script = new Script().Then(HttpStatusCode.NotFound, "{}");
        var provider = new AzureDnsProvider(new HttpClient(script), new FakeCredential(), "sub", "rg", "acme.com");

        Assert.Empty(await provider.GetRecordsAsync("_dmarc.acme.com", "TXT"));
    }

    [Fact]
    public async Task AzureReadsJoinSplitStrings()
    {
        var script = new Script().Then(HttpStatusCode.OK, """{"properties":{"TTL":300,"TXTRecords":[{"value":["v=spf1 include:a.example ","-all"]}]}}""");
        var provider = new AzureDnsProvider(new HttpClient(script), new FakeCredential(), "sub", "rg", "acme.com");

        var records = await provider.GetRecordsAsync("acme.com", "TXT");

        Assert.Equal("v=spf1 include:a.example -all", Assert.Single(records).Value);
    }

    // ---- manual ---------------------------------------------------------------

    [Fact]
    public async Task ManualProviderNeverReportsAWriteAsDone()
    {
        var manual = new ManualDnsProvider();

        Assert.False(manual.CanWrite);
        var result = await manual.SetRecordAsync(new DnsRecordWrite("_dmarc.acme.com", "TXT", "v=DMARC1; p=none"));
        Assert.False(result.Success);
        Assert.Contains("Publish this yourself", result.Error, StringComparison.Ordinal);
    }

    // ---- Azure's whole-set write, and what guards it -------------------------

    [Fact]
    public async Task AzureConditionsTheWriteOnTheSetNotHavingChanged()
    {
        // Azure keeps every TXT value at a name in one record set, so changing
        // one means writing all of them back. Unconditional, that is a lost
        // update with teeth: a verification token somebody else added between
        // the read and the write is not overwritten, it is deleted, and the
        // service that issued it stops trusting the domain. Azure reports
        // success, because as far as it is concerned the write worked.
        var existing = """{"etag":"W/\"abc123\"","properties":{"TTL":3600,"TXTRecords":[{"value":["v=spf1 -all"]}]}}""";
        var script = new Script().Then(HttpStatusCode.OK, existing).Then(HttpStatusCode.OK, "{}");
        var provider = new AzureDnsProvider(new HttpClient(script), new FakeCredential(), "sub", "rg", "acme.com");

        var result = await provider.SetRecordAsync(
            new DnsRecordWrite("acme.com", "TXT", "v=spf1 include:new.example -all", ReplacesValue: "v=spf1 -all"));

        Assert.True(result.Success);
        Assert.Equal(2, script.Sent.Count);
        Assert.Equal(["W/\"abc123\""], script.Headers[1]["If-Match"]);
    }

    [Fact]
    public async Task AzureRefusesToCreateOverASetThatAppearedMeanwhile()
    {
        // Nothing was there when it was read. If a set exists by the time of
        // the write, it holds records this one has never seen, and replacing
        // it with a set of one would delete them.
        var script = new Script().Then(HttpStatusCode.NotFound, "{}").Then(HttpStatusCode.OK, "{}");
        var provider = new AzureDnsProvider(new HttpClient(script), new FakeCredential(), "sub", "rg", "acme.com");

        await provider.SetRecordAsync(new DnsRecordWrite("_dmarc.acme.com", "TXT", "v=DMARC1; p=none"));

        Assert.Equal(["*"], script.Headers[1]["If-None-Match"]);
        Assert.False(script.Headers[1].ContainsKey("If-Match"));
    }

    [Fact]
    public async Task AzureSaysWhatHappenedWhenTheSetChangedUnderIt()
    {
        // A 412 is not a fault to retry blindly: the set is no longer what it
        // was, so the values being written back are no longer the right ones.
        var existing = """{"etag":"W/\"abc123\"","properties":{"TTL":300,"TXTRecords":[{"value":["v=spf1 -all"]}]}}""";
        var script = new Script().Then(HttpStatusCode.OK, existing).Then(HttpStatusCode.PreconditionFailed, "{}");
        var provider = new AzureDnsProvider(new HttpClient(script), new FakeCredential(), "sub", "rg", "acme.com");

        var result = await provider.SetRecordAsync(
            new DnsRecordWrite("acme.com", "TXT", "v=spf1 -all2", ReplacesValue: "v=spf1 -all"));

        Assert.False(result.Success);
        Assert.Contains("changed while this was being written", result.Error, StringComparison.Ordinal);
        Assert.Contains("nothing was changed", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AzureConditionsARemovalTheSameWay()
    {
        // Removing one value from a set is the same read-modify-write, and
        // loses the same neighbours if it is not conditioned.
        var existing = """{"etag":"W/\"xyz\"","properties":{"TTL":300,"TXTRecords":[{"value":["v=spf1 -all"]},{"value":["MS=ms1"]}]}}""";
        var script = new Script().Then(HttpStatusCode.OK, existing).Then(HttpStatusCode.OK, "{}");
        var provider = new AzureDnsProvider(new HttpClient(script), new FakeCredential(), "sub", "rg", "acme.com");

        await provider.RemoveRecordAsync(new DnsProviderRecord("acme.com", "TXT", "MS=ms1", 300, "id"));

        Assert.Equal(["W/\"xyz\""], script.Headers[1]["If-Match"]);
    }
}
