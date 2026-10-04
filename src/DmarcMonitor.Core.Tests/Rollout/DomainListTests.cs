using DmarcMonitor.Core.Rollout;

namespace DmarcMonitor.Core.Tests.Rollout;

/// <summary>
/// How the domains table is ordered and grouped.
///
/// The table used to be one table per client, so a reader with twenty clients
/// met twenty header rows and twenty sets of columns that each sized
/// themselves to their own contents. It is one table now, and these are the
/// rules that decide which row comes next.
/// </summary>
public sealed class DomainListTests
{
    /// <param name="tenant">The organization's identity; its name unless said otherwise, since two can share a name.</param>
    private static DomainTriage Domain(
        string name, string? client = null, long messages = 100, long passing = 100,
        string policy = "none", int sources = 1, TriageLevel level = TriageLevel.Fine,
        DateTimeOffset? lastReport = null, string slug = "", string organization = "", string? tenant = null) => new()
        {
            Domain = name,
            ClientName = client ?? name,
            ClientSlug = slug,
            Organization = organization,
            TenantId = tenant ?? organization,
            Messages = messages,
            Passing = passing,
            Failing = messages - passing,
            Policy = policy,
            Sources = sources,
            Level = level,
            LastReport = lastReport,
        };

    private static string[] Names(IEnumerable<DomainLine> lines) =>
        [.. lines.Where(l => l.Row is not null).Select(l => l.Row!.Domain)];

    // ---- grouping ------------------------------------------------------------

    /// <summary>
    /// A client's domains sit together under its name, and the table stays in
    /// domain order: the block is where its first domain would have been.
    /// </summary>
    [Fact]
    public void ADomainsSiblingsAreBroughtUpBesideItUnderTheClientsName()
    {
        var lines = DomainList.Layout([
            Domain("alpha.example", client: "Alpha"),
            Domain("bravo.example", client: "Family Co"),
            Domain("charlie.example", client: "Charlie"),
            Domain("delta.example", client: "Family Co"),
        ], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: false);

        // bravo opens the Family Co block, so delta comes up beside it rather than
        // staying behind charlie.
        Assert.Equal(["alpha.example", "bravo.example", "delta.example", "charlie.example"], Names(lines));

        var heading = Assert.Single(lines, l => l.Heading is not null);
        Assert.Equal("Family Co", heading.Heading);
        Assert.Equal(2, heading.Count);

        // The heading sits directly above its first domain.
        Assert.Equal(1, lines.ToList().IndexOf(heading));
        Assert.Equal("bravo.example", lines[2].Row!.Domain);
    }

    [Fact]
    public void ADomainThatIsAloneNeedsNoHeading()
    {
        var lines = DomainList.Layout([
            Domain("alpha.example"), Domain("bravo.example"),
        ], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: false);

        // A heading over a single row is the row said twice.
        Assert.All(lines, l => Assert.Null(l.Heading));
        Assert.All(lines, l => Assert.False(l.Headed));
    }

    [Fact]
    public void OnlyTheDomainsInsideAHeadingAreMarkedAsHeaded()
    {
        var lines = DomainList.Layout([
            Domain("a.example", client: "Pair"), Domain("b.example", client: "Pair"), Domain("c.example"),
        ], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: false);

        Assert.Equal([false, true, true, false], lines.Select(l => l.Headed));
    }

    [Fact]
    public void UnfiledDomainsAreOneBlockForFilingThemTogether()
    {
        var lines = DomainList.Layout([
            Domain("a.example", client: "Unassigned"), Domain("b.example", client: "Unassigned"), Domain("c.example"),
        ], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: false);

        var heading = Assert.Single(lines, l => l.Heading is not null);
        Assert.Equal("Unassigned", heading.Heading);
        Assert.Equal(2, heading.Count);
    }

    /// <summary>
    /// Pressing "Passing" asks which domains are worst across every client. A
    /// table that kept each client's block together would answer which are
    /// worst within each.
    /// </summary>
    [Theory]
    [InlineData(DomainSort.Status)]
    [InlineData(DomainSort.Policy)]
    [InlineData(DomainSort.Volume)]
    [InlineData(DomainSort.Passing)]
    [InlineData(DomainSort.Sources)]
    [InlineData(DomainSort.LastReport)]
    public void GroupingIsSuspendedWhenOrderedByAnythingButName(DomainSort sort)
    {
        var lines = DomainList.Layout([
            Domain("a.example", client: "Pair"), Domain("b.example", client: "Pair"),
        ], sort, descending: false, grouped: true, acrossOrganizations: false);

        Assert.All(lines, l => Assert.Null(l.Heading));
        Assert.All(lines, l => Assert.False(l.Headed));
    }

    [Fact]
    public void GroupingCanBeTurnedOff()
    {
        var lines = DomainList.Layout([
            Domain("a.example", client: "Pair"), Domain("b.example", client: "Pair"),
        ], DomainSort.Domain, descending: false, grouped: false, acrossOrganizations: false);

        Assert.All(lines, l => Assert.Null(l.Heading));
    }

    /// <summary>
    /// Two clients can share a name. They are two clients, and merging their
    /// domains under one heading would say they are not.
    /// </summary>
    [Fact]
    public void TwoClientsWithTheSameNameStayApart()
    {
        var lines = DomainList.Layout([
            Domain("a.example", client: "Acme", slug: "acme"),
            Domain("b.example", client: "Acme", slug: "acme-2"),
        ], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: false);

        Assert.All(lines, l => Assert.Null(l.Heading));
    }

    /// <summary>
    /// Two clients with the same name and two domains each are two headings
    /// that read the same. A page keying its rows by the words on them would
    /// be handed one key twice and refuse to draw.
    /// </summary>
    [Fact]
    public void TwoHeadingsThatReadTheSameStillHaveDifferentKeys()
    {
        var lines = DomainList.Layout([
            Domain("a.example", client: "Acme", slug: "acme"),
            Domain("b.example", client: "Acme", slug: "acme"),
            Domain("c.example", client: "Acme", slug: "acme-2"),
            Domain("d.example", client: "Acme", slug: "acme-2"),
        ], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: false);

        var headings = lines.Where(l => l.Heading is not null).ToList();

        Assert.Equal(2, headings.Count);
        Assert.All(headings, h => Assert.Equal("Acme", h.Heading));
        Assert.NotEqual(headings[0].Key, headings[1].Key);
        Assert.All(headings, h => Assert.False(string.IsNullOrEmpty(h.Key)));
    }

    [Fact]
    public void AcrossOrganizationsTheSameClientNameInTwoOfThemIsTwoBlocks()
    {
        var lines = DomainList.Layout([
            Domain("a.example", client: "Acme", slug: "acme", organization: "NRG"),
            Domain("b.example", client: "Acme", slug: "acme", organization: "NextLayerSec"),
            Domain("c.example", client: "Acme", slug: "acme", organization: "NRG"),
        ], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: true);

        var heading = Assert.Single(lines, l => l.Heading is not null);
        Assert.Equal("NRG / Acme", heading.Heading);
        Assert.Equal(["a.example", "c.example", "b.example"], Names(lines));
    }

    /// <summary>
    /// Organizations are told apart by what they are, not by what they are
    /// called, and the schema lets two share a name. Told apart by name, their
    /// same-slugged clients were one block with one heading and the domains of
    /// both inside it.
    /// </summary>
    [Fact]
    public void TwoOrganizationsWithTheSameNameAreStillTwoBlocks()
    {
        var lines = DomainList.Layout([
            Domain("a.example", client: "Contoso", slug: "contoso", organization: "Acme IT", tenant: "t1"),
            Domain("b.example", client: "Contoso", slug: "contoso", organization: "Acme IT", tenant: "t2"),
            Domain("c.example", client: "Contoso", slug: "contoso", organization: "Acme IT", tenant: "t1"),
            Domain("d.example", client: "Contoso", slug: "contoso", organization: "Acme IT", tenant: "t2"),
        ], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: true);

        var headings = lines.Where(l => l.Heading is not null).ToList();

        Assert.Equal(2, headings.Count);
        Assert.All(headings, h => Assert.Equal(2, h.Count));
        Assert.NotEqual(headings[0].Key, headings[1].Key);
        Assert.Equal(["a.example", "c.example", "b.example", "d.example"], Names(lines));
    }

    /// <summary>
    /// The same domain can be managed by two organizations. Equal rows are
    /// never reshuffled, whichever order they arrived in.
    /// </summary>
    [Fact]
    public void ADomainBothOrganizationsManageIsOrderedTheSameWhicheverArrivedFirst()
    {
        var one = Domain("shared.example", organization: "Acme IT", tenant: "t1");
        var two = Domain("shared.example", organization: "Acme IT", tenant: "t2");

        var forwards = DomainList.Order([one, two], DomainSort.Domain, descending: false);
        var backwards = DomainList.Order([two, one], DomainSort.Domain, descending: false);

        Assert.Equal(forwards.Select(d => d.TenantId), backwards.Select(d => d.TenantId));
    }

    [Fact]
    public void ADescendingNameOrderReversesTheBlocksAndTheDomainsInThem()
    {
        var lines = DomainList.Layout([
            Domain("a.example"), Domain("b.example", client: "Pair"), Domain("c.example", client: "Pair"), Domain("d.example"),
        ], DomainSort.Domain, descending: true, grouped: true, acrossOrganizations: false);

        Assert.Equal(["d.example", "c.example", "b.example", "a.example"], Names(lines));
    }

    // ---- whether there is anything to group ------------------------------------

    [Fact]
    public void GroupingIsWorthOfferingWhenSomeClientHasSeveralDomainsAndThereIsMoreThanOneClient()
    {
        Assert.True(DomainList.CanGroup([
            Domain("a.example", client: "Pair", slug: "pair"),
            Domain("b.example", client: "Pair", slug: "pair"),
            Domain("c.example", client: "Solo", slug: "solo"),
        ]));
    }

    [Fact]
    public void ItIsNotWhenEveryClientHasOneDomain()
    {
        Assert.False(DomainList.CanGroup([
            Domain("a.example", slug: "a"), Domain("b.example", slug: "b"), Domain("c.example", slug: "c"),
        ]));
    }

    /// <summary>
    /// One client's several domains under that client's name say nothing the
    /// table does not already.
    /// </summary>
    [Fact]
    public void ItIsNotWhenThereIsOnlyOneClient()
    {
        Assert.False(DomainList.CanGroup([
            Domain("a.example", client: "Pair", slug: "pair"),
            Domain("b.example", client: "Pair", slug: "pair"),
            Domain("c.example", client: "Pair", slug: "pair"),
        ]));
    }

    /// <summary>
    /// Judged from the domains a person is given. A customer's login is given
    /// its own, so what other clients of the same organization have cannot
    /// decide whether this person is offered a box to tick.
    /// </summary>
    [Fact]
    public void ItDoesNotDependOnClientsWhoseDomainsAreNotInView()
    {
        DomainTriage[] whatTheCustomerIsGiven = [Domain("a.example", client: "Acme", slug: "acme")];

        Assert.False(DomainList.CanGroup(whatTheCustomerIsGiven));
    }

    [Fact]
    public void TwoOrganizationsWithAClientOfTheSameSlugEachAreTwoClients()
    {
        Assert.False(DomainList.CanGroup([
            Domain("a.example", client: "Acme", slug: "acme", tenant: "t1"),
            Domain("b.example", client: "Acme", slug: "acme", tenant: "t2"),
        ]));

        Assert.True(DomainList.CanGroup([
            Domain("a.example", client: "Acme", slug: "acme", tenant: "t1"),
            Domain("b.example", client: "Acme", slug: "acme", tenant: "t1"),
            Domain("c.example", client: "Acme", slug: "acme", tenant: "t2"),
        ]));
    }

    // ---- ordering ------------------------------------------------------------

    [Fact]
    public void NamesSortWithoutRegardToCase()
    {
        var ordered = DomainList.Order(
            [Domain("Charlie.example"), Domain("alpha.example"), Domain("Bravo.example")],
            DomainSort.Domain, descending: false);

        Assert.Equal(["alpha.example", "Bravo.example", "Charlie.example"], ordered.Select(d => d.Domain));
    }

    [Fact]
    public void TheMostUrgentComesFirstWhenDescending()
    {
        var ordered = DomainList.Order([
            Domain("fine.example", level: TriageLevel.Fine),
            Domain("urgent.example", level: TriageLevel.Urgent),
            Domain("watch.example", level: TriageLevel.Watch),
            Domain("act.example", level: TriageLevel.Act),
            Domain("ontrack.example", level: TriageLevel.OnTrack),
        ], DomainSort.Status, descending: true);

        Assert.Equal(
            ["urgent.example", "act.example", "watch.example", "ontrack.example", "fine.example"],
            ordered.Select(d => d.Domain));
    }

    /// <summary>
    /// Status is "the order the dashboard ranks them in", and between two
    /// equally urgent domains the dashboard opens the one losing more mail.
    /// Falling to the name instead put a domain losing three messages above one
    /// losing thirty thousand. The tie-break does not flip with the column.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AmongEquallyUrgentDomainsTheOneLosingMoreMailComesFirst(bool descending)
    {
        var ordered = DomainList.Order([
            Domain("aaa.example", level: TriageLevel.Urgent, messages: 100, passing: 97),
            Domain("zzz.example", level: TriageLevel.Urgent, messages: 40_000, passing: 10_000),
            Domain("mmm.example", level: TriageLevel.Urgent, messages: 500, passing: 400),
        ], DomainSort.Status, descending);

        Assert.Equal(["zzz.example", "mmm.example", "aaa.example"], ordered.Select(d => d.Domain));
    }

    [Fact]
    public void PolicyRunsFromNoneToReject()
    {
        var ordered = DomainList.Order([
            Domain("r.example", policy: "reject"), Domain("n.example", policy: "none"), Domain("q.example", policy: "quarantine"),
        ], DomainSort.Policy, descending: false);

        Assert.Equal(["n.example", "q.example", "r.example"], ordered.Select(d => d.Domain));
    }

    /// <summary>
    /// A policy nobody recognizes is read as the weakest, not as an error: it
    /// is still a domain somebody has to look at.
    /// </summary>
    [Fact]
    public void AnUnrecognizedPolicySortsAsNone()
    {
        var ordered = DomainList.Order([
            Domain("q.example", policy: "quarantine"), Domain("odd.example", policy: "sp-only"),
        ], DomainSort.Policy, descending: false);

        Assert.Equal("odd.example", ordered[0].Domain);
    }

    [Fact]
    public void TheBusiestComesFirstWhenDescending()
    {
        var ordered = DomainList.Order([
            Domain("small.example", messages: 5, passing: 5),
            Domain("big.example", messages: 5_000, passing: 5_000),
            Domain("mid.example", messages: 500, passing: 500),
        ], DomainSort.Volume, descending: true);

        Assert.Equal(["big.example", "mid.example", "small.example"], ordered.Select(d => d.Domain));
    }

    /// <summary>
    /// No mail is no pass rate, not a rate of zero. Asked for the worst, the
    /// quiet domains are not the answer.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ADomainWithNoMailHasNoPassRateAndSortsLastEitherWay(bool descending)
    {
        var ordered = DomainList.Order([
            Domain("quiet.example", messages: 0, passing: 0),
            Domain("good.example", messages: 100, passing: 99),
            Domain("bad.example", messages: 100, passing: 40),
        ], DomainSort.Passing, descending);

        Assert.Equal("quiet.example", ordered[^1].Domain);
    }

    [Fact]
    public void PassingRunsFromTheWorstWhenAscending()
    {
        var ordered = DomainList.Order([
            Domain("good.example", messages: 100, passing: 99),
            Domain("bad.example", messages: 100, passing: 40),
        ], DomainSort.Passing, descending: false);

        Assert.Equal("bad.example", ordered[0].Domain);
    }

    /// <summary>
    /// A domain that has never sent a report is the stalest of all, and is the
    /// first thing somebody asking who has gone quiet needs to see.
    /// </summary>
    [Fact]
    public void ADomainThatNeverReportedIsTheOldest()
    {
        var now = DateTimeOffset.UtcNow;
        var ordered = DomainList.Order([
            Domain("today.example", lastReport: now),
            Domain("never.example", lastReport: null),
            Domain("lastmonth.example", lastReport: now.AddDays(-30)),
        ], DomainSort.LastReport, descending: false);

        Assert.Equal(["never.example", "lastmonth.example", "today.example"], ordered.Select(d => d.Domain));
    }

    [Fact]
    public void EqualRowsKeepTheSameOrderWhicheverWayTheColumnRuns()
    {
        DomainTriage[] rows =
        [
            Domain("c.example", sources: 7), Domain("a.example", sources: 7), Domain("b.example", sources: 7),
        ];

        var down = DomainList.Order(rows, DomainSort.Sources, descending: true).Select(d => d.Domain);
        var up = DomainList.Order(rows, DomainSort.Sources, descending: false).Select(d => d.Domain);

        // Ties fall back to the name in both directions: a list that
        // rearranges its equal rows on every press looks broken.
        Assert.Equal(["a.example", "b.example", "c.example"], down);
        Assert.Equal(down, up);
    }

    /// <summary>
    /// The first press of each header opens on the order that was asked for.
    /// </summary>
    [Theory]
    [InlineData(DomainSort.Status, true)]
    [InlineData(DomainSort.Volume, true)]
    [InlineData(DomainSort.Sources, true)]
    [InlineData(DomainSort.Domain, false)]
    [InlineData(DomainSort.Policy, false)]
    [InlineData(DomainSort.Passing, false)]
    [InlineData(DomainSort.LastReport, false)]
    public void EachColumnOpensOnTheOrderSomebodyPressingItWants(DomainSort sort, bool descending)
    {
        Assert.Equal(descending, DomainList.StartsDescending(sort));
    }

    [Fact]
    public void NothingInNothingOut()
    {
        Assert.Empty(DomainList.Layout([], DomainSort.Domain, descending: false, grouped: true, acrossOrganizations: false));
        Assert.Empty(DomainList.Order([], DomainSort.Volume, descending: true));
    }
}
