using DmarcMonitor.Core.Storage;
using DmarcMonitor.Core.Tenancy;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Tenancy;

public sealed class OrganisationStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-orgs-{Guid.NewGuid():N}.db");
    private readonly OrganisationStore _store;

    public OrganisationStoreTests()
    {
        new ReportStore(_dbPath).InitialiseAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
        _store = new OrganisationStore(_dbPath);
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
    public async Task CreatesListsAndFindsAnOrganisation()
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
    public async Task ClientsAndDomainsAreCountedPerOrganisation()
    {
        var nls = await _store.CreateAsync("NextLayerSec");
        var reports = new ReportStore(_dbPath, "nextlayersec");
        await reports.CreateClientAsync("Corner Post");

        var org = Assert.Single(await _store.ListAsync());
        Assert.Equal(nls!.Id, org.Id);
        Assert.Equal(1, org.Clients);   // Unassigned is not a client
    }

    [Fact]
    public async Task AClientCreatedForAnUnknownOrganisationBringsItIntoBeing()
    {
        // Named after its slug until somebody renames it: a report is never
        // refused for want of a row, and the name is one command away.
        await new ReportStore(_dbPath).CreateClientAsync("Acme", organisation: "acme-msp");

        var org = Assert.Single(await _store.ListAsync());
        Assert.Equal("acme-msp", org.Slug);
        Assert.Equal("acme-msp", org.Name);
    }
}
