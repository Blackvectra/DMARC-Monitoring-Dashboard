using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Tenancy;

public sealed class OrganizationStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-orgs-{Guid.NewGuid():N}.db");
    private readonly OrganizationStore _store;

    public OrganizationStoreTests()
    {
        new ReportStore(_dbPath).InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        _store = new OrganizationStore(_dbPath);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task CreatesListsAndFindsAnOrganization()
    {
        var created = await _store.CreateAsync("NextLayerSec", entraGroupId: "  22222222-2222-2222-2222-222222222222 ");

        Assert.NotNull(created);
        Assert.Equal("nextlayersec", created.Slug);
        Assert.Equal("22222222-2222-2222-2222-222222222222", created.EntraGroupId);

        var listed = Assert.Single(await _store.ListAsync());
        Assert.Equal(created.Id, listed.Id);
        Assert.Equal(0, listed.Clients);
        Assert.Equal(0, listed.Domains);

        Assert.Equal(created.Id, (await _store.GetAsync("NextLayerSec"))?.Id);
        Assert.Null(await _store.GetAsync("no-such"));
    }

    [Fact]
    public async Task ASlugIsTakenOnce()
    {
        Assert.NotNull(await _store.CreateAsync("NextLayerSec"));
        Assert.Null(await _store.CreateAsync("Next Layer Sec", slug: "nextlayersec"));
        Assert.Null(await _store.CreateAsync("!!!"));
    }

    [Fact]
    public async Task TheGroupAndTheNameCanChangeButTheSlugCannot()
    {
        await _store.CreateAsync("Local", slug: "local");

        Assert.True(await _store.SetGroupAsync("local", "11111111-1111-1111-1111-111111111111"));
        Assert.True(await _store.RenameAsync("local", "NRG Tech Services"));

        var org = await _store.GetAsync("local");
        Assert.NotNull(org);
        Assert.Equal("NRG Tech Services", org.Name);
        Assert.Equal("11111111-1111-1111-1111-111111111111", org.EntraGroupId);

        // Clearing the group is a deliberate act with a deliberate meaning:
        // only the master group sees it now.
        Assert.True(await _store.SetGroupAsync("local", null));
        Assert.Null((await _store.GetAsync("local"))?.EntraGroupId);

        Assert.False(await _store.RenameAsync("nobody", "x"));
    }

    [Fact]
    public async Task ClientsAndDomainsAreCountedPerOrganization()
    {
        var nls = await _store.CreateAsync("NextLayerSec");
        var reports = new ReportStore(_dbPath, "nextlayersec");
        await reports.CreateClientAsync("Corner Post");

        var org = Assert.Single(await _store.ListAsync());
        Assert.Equal(nls!.Id, org.Id);
        Assert.Equal(1, org.Clients);   // Unassigned is not a client
    }

    [Fact]
    public async Task EachRoleHasItsOwnGroupAndTheyDoNotOverwriteEachOther()
    {
        await _store.CreateAsync("NRG Tech Services", slug: "nrg");

        Assert.True(await _store.SetGroupAsync("nrg", OrganizationRole.Admin, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        Assert.True(await _store.SetGroupAsync("nrg", OrganizationRole.Engineer, "44444444-4444-4444-4444-444444444444"));
        Assert.True(await _store.SetGroupAsync("nrg", OrganizationRole.Tech, "11111111-1111-1111-1111-111111111111"));
        Assert.True(await _store.SetGroupAsync("nrg", OrganizationRole.Viewer, " bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb "));

        var org = await _store.GetAsync("nrg");
        Assert.NotNull(org);
        Assert.Equal("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", org.AdminGroupId);

        // Reading this back is what proves the column is selected and mapped
        // at the right position. A misplaced index here would not fail to
        // compile; it would hand one role's group to another, which is the
        // quietest way a permission gate can be wrong.
        Assert.Equal("44444444-4444-4444-4444-444444444444", org.EngineerGroupId);
        Assert.Equal("11111111-1111-1111-1111-111111111111", org.EntraGroupId);
        Assert.Equal("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", org.ViewerGroupId);

        Assert.True(await _store.SetGroupAsync("nrg", OrganizationRole.Viewer, null));
        org = await _store.GetAsync("nrg");
        Assert.Null(org!.ViewerGroupId);
        Assert.Equal("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", org.AdminGroupId);
        Assert.Equal("44444444-4444-4444-4444-444444444444", org.EngineerGroupId);

        // And clearing the engineer group is the supported way back to one
        // working role, so it must not take the tech group with it.
        Assert.True(await _store.SetGroupAsync("nrg", OrganizationRole.Engineer, null));
        org = await _store.GetAsync("nrg");
        Assert.Null(org!.EngineerGroupId);
        Assert.Equal("11111111-1111-1111-1111-111111111111", org.EntraGroupId);
    }

    [Fact]
    public async Task BrandingRoundTripsAndClears()
    {
        await _store.CreateAsync("NextLayerSec", slug: "nls");

        var brand = new OrganizationBrand(
            "#0F766E",
            "data:image/png;base64,iVBORw0KGgo=",
            "NextLayerSec",
            "dmarc@nextlayersec.io\n+1 555 0100");
        await _store.SetBrandAsync("nls", brand);

        var org = await _store.GetAsync("nls");
        Assert.NotNull(org);
        Assert.Equal("#0f766e", org.Brand.PrimaryColor);   // stored lowercase, so the CSS is stable
        Assert.Equal("NextLayerSec", org.Brand.ProviderName);
        Assert.StartsWith("data:image/png;base64,", org.Brand.Logo);
        Assert.Contains("+1 555 0100", org.Brand.ContactBlock);

        await _store.SetBrandAsync("nls", OrganizationBrand.None);
        Assert.True((await _store.GetAsync("nls"))!.Brand.IsEmpty);
    }

    [Fact]
    public async Task ABrandThatWouldEscapeIntoTheMarkupIsRefused()
    {
        // The color lands in a style attribute and the logo in an img src,
        // so neither is taken on trust.
        await _store.CreateAsync("NextLayerSec", slug: "nls");

        await Assert.ThrowsAsync<ArgumentException>(
            () => _store.SetBrandAsync("nls", new OrganizationBrand("red; background:url(x)", null, null, null)));
        await Assert.ThrowsAsync<ArgumentException>(
            () => _store.SetBrandAsync("nls", new OrganizationBrand("#abc", null, null, null)));
        await Assert.ThrowsAsync<ArgumentException>(
            () => _store.SetBrandAsync("nls", new OrganizationBrand(null, "javascript:alert(1)", null, null)));
        await Assert.ThrowsAsync<ArgumentException>(
            () => _store.SetBrandAsync("nls", new OrganizationBrand(null, "data:text/html;base64,PHNjcmlwdD4=", null, null)));
        await Assert.ThrowsAsync<ArgumentException>(
            () => _store.SetBrandAsync("nls", new OrganizationBrand(null, "data:image/png;base64," + new string('A', OrganizationBrand.MaxLogoLength), null, null)));

        Assert.True((await _store.GetAsync("nls"))!.Brand.IsEmpty);
    }

    [Fact]
    public async Task ACustomerLoginGroupIsListedAgainstItsClientAndOrganization()
    {
        await _store.CreateAsync("NRG Tech Services", slug: "nrg");
        var reports = new ReportStore(_dbPath, "nrg");
        await reports.CreateClientAsync("Morton, ND", "morton-nd");

        Assert.True(await reports.SetClientGroupAsync("morton-nd", " cccccccc-cccc-cccc-cccc-cccccccccccc "));

        var group = Assert.Single(await _store.ClientGroupsAsync());
        Assert.Equal("nrg", group.OrganizationSlug);
        Assert.Equal("morton-nd", group.ClientSlug);
        Assert.Equal("cccccccc-cccc-cccc-cccc-cccccccccccc", group.EntraGroupId);

        Assert.True(await reports.SetClientGroupAsync("morton-nd", null));
        Assert.Empty(await _store.ClientGroupsAsync());
    }

    [Fact]
    public async Task AClientCreatedForAnUnknownOrganizationBringsItIntoBeing()
    {
        // Named after its slug until somebody renames it: a report is never
        // refused for want of a row, and the name is one command away.
        await new ReportStore(_dbPath).CreateClientAsync("Acme", organization: "acme-msp");

        var org = Assert.Single(await _store.ListAsync());
        Assert.Equal("acme-msp", org.Slug);
        Assert.Equal("acme-msp", org.Name);
    }
}
