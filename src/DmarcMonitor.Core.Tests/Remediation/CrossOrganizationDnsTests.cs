using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using DmarcMonitor.Core.Tests.Ingest;
using DmarcMonitor.Core.Tests.Storage;

namespace DmarcMonitor.Core.Tests.Remediation;

/// <summary>
/// The same domain name in two organizations.
///
/// Names are unique inside an organization, not across them, so an install
/// that holds a customer under two MSPs holds the same domain twice. The DNS
/// apply path used to look a domain up by name alone and take the first row:
/// the audit entry went into one client's file and the write was made with
/// another organization's provider token. Now a lookup names its organization,
/// or the name is held by exactly one; a name held by several and given no
/// organization is refused.
///
/// Every name here is one RFC 2606 keeps for examples.
/// </summary>
public sealed class CrossOrganizationDnsTests : IDisposable
{
    private const string Shared = "shared.example";
    private const string AlphaOnly = "alpha-only.example";
    private const string Name = "_dmarc.shared.example";
    private const string Before = "v=DMARC1; p=none; rua=mailto:d@msp.example";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-crossorg-{Guid.NewGuid():N}.db");
    private readonly RemediationService _service;
    private readonly DnsProviderConfigs _configs;
    private readonly InMemoryDnsProvider _zone = new();
    private readonly string _alpha;
    private readonly string _beta;

    public CrossOrganizationDnsTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();

        // Both organizations hold a client called "shared-client", and both
        // file the domain "shared.example" under it. Alpha also holds one the
        // other does not.
        Onboard("alpha", Shared, AlphaOnly);
        Onboard("beta", Shared);

        var organizations = new OrganizationStore(_dbPath);
        _alpha = organizations.GetAsync("alpha").GetAwaiter().GetResult()!.Id;
        _beta = organizations.GetAsync("beta").GetAwaiter().GetResult()!.Id;

        _service = new RemediationService(_dbPath);
        _configs = new DnsProviderConfigs(_dbPath, new InMemorySecretStore());
        _configs.SetAsync("shared-client", null, "cloudflare", new Dictionary<string, string> { ["zone_id"] = "zone-alpha" }, "token-alpha", _alpha)
            .GetAwaiter().GetResult();
        _configs.SetAsync("shared-client", null, "cloudflare", new Dictionary<string, string> { ["zone_id"] = "zone-beta" }, "token-beta", _beta)
            .GetAwaiter().GetResult();

        _zone.Add(Name, "TXT", Before);
    }

    public void Dispose() => SingleDatabase.Delete(_dbPath);

    // ---- the provider a domain is written with -------------------------------------------------

    [Fact]
    public async Task TheProviderIsTheCallersOwnOrganizations()
    {
        Assert.Equal("zone-alpha", (await _configs.ForDomainAsync(Shared, _alpha))!.Settings["zone_id"]);
        Assert.Equal("zone-beta", (await _configs.ForDomainAsync(Shared, _beta))!.Settings["zone_id"]);
    }

    [Fact]
    public async Task ANameTwoOrganizationsHoldIsRefusedWhenNeitherIsNamed()
    {
        var ex = await Assert.ThrowsAsync<AmbiguousOrganizationException>(() => _configs.ForDomainAsync(Shared));

        Assert.Equal("domain", ex.Kind);
        Assert.Equal(Shared, ex.Name);
        Assert.Equal(["alpha", "beta"], ex.Organizations);
        Assert.Contains("nothing was changed", ex.Message, StringComparison.Ordinal);

        // And building a provider says the same thing rather than picking one:
        // this is the call a write is made through.
        await Assert.ThrowsAsync<AmbiguousOrganizationException>(() => _configs.ProviderForAsync(Shared));
    }

    [Fact]
    public async Task ANameOneOrganizationHoldsNeedsNoOrganization()
    {
        // Every install with one organization, and every name only one holds.
        Assert.Equal("zone-alpha", (await _configs.ForDomainAsync(AlphaOnly))!.Settings["zone_id"]);
    }

    [Fact]
    public async Task ANamedOrganizationNeverLendsAnotherOnesProvider()
    {
        // Naming the wrong organization finds no domain, not the other one's.
        Assert.Null(await _configs.ForDomainAsync(AlphaOnly, _beta));
    }

    [Fact]
    public async Task AClientSlugTwoOrganizationsHoldIsRefusedWhenNeitherIsNamed()
    {
        await Assert.ThrowsAsync<AmbiguousOrganizationException>(
            () => _configs.SetAsync("shared-client", null, "manual", new Dictionary<string, string>(), null));
        await Assert.ThrowsAsync<AmbiguousOrganizationException>(
            () => _configs.RemoveAsync("shared-client", null));

        // Both organizations' credentials are where they were.
        Assert.Equal(2, (await _configs.ListAsync()).Count);
        Assert.Equal("token-alpha", await _configs.Secrets.GetAsync((await _configs.ForDomainAsync(Shared, _alpha))!.CredentialRef!));
        Assert.Equal("token-beta", await _configs.Secrets.GetAsync((await _configs.ForDomainAsync(Shared, _beta))!.CredentialRef!));

        // Named, it acts on that organization's client alone.
        Assert.True(await _configs.RemoveAsync("shared-client", null, _beta));
        Assert.Null(await _configs.ForDomainAsync(Shared, _beta));
        Assert.NotNull(await _configs.ForDomainAsync(Shared, _alpha));
    }

    // ---- the change and where it is filed -----------------------------------------------------

    [Fact]
    public async Task AChangeIsFiledUnderTheOrganizationItWasMadeFor()
    {
        var plan = DmarcPolicyPlanner.Advance(Shared, Before, "quarantine");

        var outcome = await _service.ApplyAsync(plan, _zone, confirm: true, "tester", "because", _beta);

        Assert.True(outcome.Applied, outcome.Message);
        var beta = Assert.Single(await _service.HistoryAsync(tenantId: _beta));
        Assert.Equal(_beta, beta.TenantId);
        Assert.Equal(Shared, beta.Domain);
        Assert.Empty(await _service.HistoryAsync(tenantId: _alpha));
    }

    [Fact]
    public async Task ApplyingToANameTwoOrganizationsHoldIsRefusedBeforeAnythingIsWritten()
    {
        var plan = DmarcPolicyPlanner.Advance(Shared, Before, "quarantine");

        var outcome = await _service.ApplyAsync(plan, _zone, confirm: true, "tester", "because");

        Assert.False(outcome.Applied);
        Assert.Contains("more than one organization", outcome.Error, StringComparison.Ordinal);
        Assert.StartsWith("Not applied:", outcome.Message, StringComparison.Ordinal);
        Assert.Equal([Before], _zone.ValuesAt(Name));
        Assert.Empty(_zone.Log);
        Assert.Empty(await _service.HistoryAsync());
    }

    [Fact]
    public async Task ARollbackFindsOnlyTheCallersOwnChange()
    {
        var plan = DmarcPolicyPlanner.Advance(Shared, Before, "quarantine");
        var applied = await _service.ApplyAsync(plan, _zone, confirm: true, "tester", "because", _alpha);
        Assert.True(applied.Applied, applied.Message);
        var changeId = applied.ChangeId!;
        var written = _zone.ValuesAt(Name);

        // The other organization cannot see it, let alone undo it.
        Assert.Null(await _service.GetChangeAsync(changeId, _beta));
        await Assert.ThrowsAsync<ArgumentException>(
            () => _service.RollBackAsync(changeId, _zone, "tester", "not mine", _beta));
        Assert.Equal(written, _zone.ValuesAt(Name));

        // The owner can, and the change says which organization owns it, which
        // is how a caller chooses the provider to undo it with.
        var change = await _service.GetChangeAsync(changeId, _alpha);
        Assert.Equal(_alpha, change!.TenantId);

        var undone = await _service.RollBackAsync(changeId, _zone, "tester", "changed my mind", _alpha);
        Assert.True(undone.Applied, undone.Message);
        Assert.Equal([Before], _zone.ValuesAt(Name));
    }

    // ---- the MTA-STS policy the internet is served ---------------------------------------------

    [Fact]
    public async Task AnMtaStsPolicyIsWrittenForTheNamedOrganizationOnly()
    {
        var policies = new MtaStsStore(_dbPath);

        await Assert.ThrowsAsync<AmbiguousOrganizationException>(
            () => policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.alpha.example"], "tester"));
        Assert.Null(await policies.GetAsync(Shared, _alpha));

        await policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.alpha.example"], "tester", tenantId: _alpha);

        Assert.Equal(["mx.alpha.example"], (await policies.GetAsync(Shared, _alpha))!.Mx);
        Assert.Null(await policies.GetAsync(Shared, _beta));
    }

    [Fact]
    public async Task ThePublicEndpointServesNothingForANameTwoOrganizationsHavePoliciesFor()
    {
        var policies = new MtaStsStore(_dbPath);
        await policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.alpha.example"], "tester", tenantId: _alpha);

        // One holder: an unambiguous name needs no organization, as before.
        Assert.Equal(["mx.alpha.example"], (await policies.GetAsync(Shared))!.Mx);

        await policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.beta.example"], "tester", tenantId: _beta);

        // Two holders: a sender cannot say whose policy it means, and an
        // arbitrary one would publish one organization's mail servers for the
        // other's domain. Nothing is served until it is settled.
        Assert.Null(await policies.GetAsync(Shared));
        Assert.Equal(["mx.alpha.example"], (await policies.GetAsync(Shared, _alpha))!.Mx);
        Assert.Equal(["mx.beta.example"], (await policies.GetAsync(Shared, _beta))!.Mx);
    }

    [Fact]
    public async Task RemovingAPolicyRemovesOneOrganizationsAndNeverBoth()
    {
        var policies = new MtaStsStore(_dbPath);
        await policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.alpha.example"], "tester", tenantId: _alpha);
        await policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.beta.example"], "tester", tenantId: _beta);

        await Assert.ThrowsAsync<AmbiguousOrganizationException>(() => policies.RemoveAsync(Shared));
        Assert.NotNull(await policies.GetAsync(Shared, _alpha));
        Assert.NotNull(await policies.GetAsync(Shared, _beta));

        Assert.True(await policies.RemoveAsync(Shared, _alpha));
        Assert.Null(await policies.GetAsync(Shared, _alpha));
        Assert.NotNull(await policies.GetAsync(Shared, _beta));
    }

    [Fact]
    public async Task AnUnchangedPolicyKeepsItsOwnIdNotAStrangers()
    {
        var policies = new MtaStsStore(_dbPath);
        var alpha = await policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.alpha.example"], "tester", tenantId: _alpha);
        await policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.beta.example"], "tester", tenantId: _beta);

        // "Unchanged means unchanged, id included" has to be judged against this
        // organization's own policy for the name.
        var again = await policies.SetAsync(Shared, MtaStsMode.Testing, ["mx.alpha.example"], "tester", tenantId: _alpha);

        Assert.Equal(alpha.Id, again.Id);
    }

    /// <summary>A first report files the domains; a client is made and they are filed under it.</summary>
    private void Onboard(string organization, params string[] domains)
    {
        var store = new ReportStore(_dbPath, organization);
        foreach (var domain in domains)
        {
            var xml = SyntheticReports.AggregateXml($"{organization}-{domain}", domain);
            store.SaveAggregateAsync(AggregateReportParser.Parse(xml).Report!, xml, $"msg-{organization}-{domain}").GetAwaiter().GetResult();
        }

        // The organization is named when filing, as every caller that is not the
        // master account does: without it "shared-client" means whichever
        // organization's client the database reaches first.
        var tenantId = new OrganizationStore(_dbPath).GetAsync(organization).GetAwaiter().GetResult()!.Id;
        var slug = store.CreateClientAsync("Shared Client").GetAwaiter().GetResult()!;
        foreach (var domain in domains) { store.AssignDomainAsync(domain, slug, tenantId).GetAwaiter().GetResult(); }
    }
}
