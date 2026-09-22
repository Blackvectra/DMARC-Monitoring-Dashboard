using System.Net;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Remediation;
using DmarcMonitor.Core.Storage;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Hosting;

namespace DmarcMonitor.Web.Tests;

/// <summary>
/// Every page, loaded for real against a database with data in it.
///
/// The logic behind these pages is covered by six hundred tests in Core. None
/// of them would notice a renamed property in a .razor file, a broken @bind,
/// or a page that throws on an empty database: all three compile, and all
/// three pass the entire suite. Every such fault found so far was found by a
/// person driving the app by hand, which does not survive into next week.
///
/// These run the real application in process, over real HTTP, through the
/// real authentication pipeline. They assert on one sentence per page rather
/// than on markup, so they fail when a page breaks and stay quiet when it is
/// restyled.
/// </summary>
public sealed class PageTests : IClassFixture<SeededApp>
{
    private readonly SeededApp _app;

    public PageTests(SeededApp app) => _app = app;

    private HttpClient Client() => _app.CreateClient(new WebApplicationFactoryClientOptions
    {
        // Local trial mode redirects to its own sign-in and sets a cookie.
        // Following that is what a browser does, and not following it turns
        // every one of these into a test of the redirect.
        AllowAutoRedirect = true,
        HandleCookies = true,
    });

    public static TheoryData<string> EveryRoute => new()
    {
        "/",
        "/domains",
        "/domains/acme.com",
        "/fix",
        "/clients",
        "/import",
        "/sources",
        "/reports",
        "/settings",
        "/updates",
    };

    [Theory]
    [MemberData(nameof(EveryRoute))]
    public async Task EveryRouteInTheSidebarLoads(string route)
    {
        // A sidebar link that 404s is what somebody meets first. Three of
        // these did, for most of a day.
        var response = await Client().GetAsync(route);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(EveryRoute))]
    public async Task NoPageRendersAnUnhandledError(string route)
    {
        // A Blazor component that throws during render still returns 200 with
        // an error boundary in the body, so the status code alone proves
        // nothing.
        var html = await Client().GetStringAsync(route);

        Assert.DoesNotContain("An unhandled error has occurred", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Unhandled exception", html, StringComparison.OrdinalIgnoreCase);
    }

    // ---- what each page is for ----------------------------------------------

    [Fact]
    public async Task TriageNamesTheDomainAndWhatItNeeds()
    {
        var html = await Client().GetStringAsync("/");

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("refused outright", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TriageDoesNotGoQuietAboutMailBeingRefused()
    {
        // The seeded domain is at p=reject on 96%, above the healthy
        // threshold, with 40 messages being refused. That row was empty for
        // most of a day because the percentage looked fine.
        var html = await Client().GetStringAsync("/");

        Assert.Contains("40 message(s)", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainPageOpensFromItsName()
    {
        var html = await Client().GetStringAsync("/domains/acme.com");

        Assert.Contains("acme.com", html, StringComparison.Ordinal);
        Assert.Contains("Who is reporting", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainPageSaysWhenAValidSignatureIsBeingThrownAwayForTheWrongDomain()
    {
        // The whole point of the section. A report row reading "dkim=pass"
        // beside "dmarc=fail" looks like the product is wrong to anybody who
        // has already set DKIM up with the vendor, and they stop looking.
        var html = await Client().GetStringAsync("/domains/signed.example");

        Assert.Contains("signing correctly for the wrong domain", html, StringComparison.Ordinal);
        Assert.Contains("d=training.vendor.example", html, StringComparison.Ordinal);

        // And the distinction itself, not just the label.
        Assert.Contains("the signing domain to match", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainPageNamesTheSameVendorsWorkingPathAsProofItCanBeDone()
    {
        // Both hosts carry the same envelope domain, and one of them already
        // signs as the customer. That fact is what a vendor cannot argue with.
        var html = await Client().GetStringAsync("/domains/signed.example");

        Assert.Contains("23.21.109.197", html, StringComparison.Ordinal);
        Assert.Contains("the capability exists on", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainPageOffersNoVendorProofForADomainThatHasNone()
    {
        // acme.com has no third party signing for it at all, so there is no
        // working path to point at. Claiming one would be an invention.
        var html = await Client().GetStringAsync("/domains/acme.com");

        Assert.DoesNotContain("the capability exists on", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainWhoseMailIsMerelyUnsignedIsNotAccusedOfMisalignment()
    {
        // acme.com's failures have no valid signature at all, which is a
        // different fault with a different fix. Offering alignment advice
        // there sends somebody to a vendor setting that is not the problem.
        var html = await Client().GetStringAsync("/domains/acme.com");

        Assert.DoesNotContain("signing correctly for the wrong domain", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TriageDrawsTheEstateRatherThanOnlyTabulatingIt()
    {
        // A table of totals cannot show that the estate lost a third of its
        // volume on Tuesday.
        var html = await Client().GetStringAsync("/");

        Assert.Contains("chart-svg", html, StringComparison.Ordinal);
        Assert.Contains("class=\"spark\"", html, StringComparison.Ordinal);
        Assert.Contains("proportion-bar", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The dashboard opens on the three figures somebody asks for first, then
    /// the checks, then where the mail came from.
    /// </summary>
    /// <remarks>
    /// Shaped like the platforms this gets compared against, because an MSP
    /// showing it to a customer is showing it beside one of them. The order is
    /// the order the questions get asked in: how are we doing, why, and who is
    /// doing it.
    /// </remarks>
    [Fact]
    public async Task TheDashboardOpensOnAScoreAVolumeAndAComplianceRate()
    {
        var html = await Client().GetStringAsync("/");

        Assert.Contains("class=\"scorecards\"", html, StringComparison.Ordinal);
        Assert.Contains("Security score", html, StringComparison.Ordinal);
        Assert.Contains("Total email volume", html, StringComparison.Ordinal);
        Assert.Contains("DMARC compliance rate", html, StringComparison.Ordinal);

        // A score with nothing under it saying what it is made of is worth
        // nothing to the person reading it, which is the state of every
        // competing dashboard's number.
        Assert.Contains("points lost to", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDashboardCarriesTheCheckResultsAndWhereTheMailCameFrom()
    {
        var html = await Client().GetStringAsync("/");

        Assert.Contains("Authentication results", html, StringComparison.Ordinal);
        Assert.Contains("Outbound email overview", html, StringComparison.Ordinal);
        Assert.Contains("Top sending sources", html, StringComparison.Ordinal);
        Assert.Contains("Top threat / unknown / unaligned sources", html, StringComparison.Ordinal);

        // The counts that were the whole overview before, kept rather than
        // dropped: a domain nobody sends as is not a domain that is safe.
        Assert.Contains("Active domains", html, StringComparison.Ordinal);
        Assert.Contains("Inactive domains", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheThreeChecksAreShownSeparatelyBecauseTheyAreThreeQuestions()
    {
        // SPF and DKIM are the raw checks; DMARC is those plus alignment. A
        // reading of SPF 100, DKIM 100, DMARC 2 is not a contradiction - it is
        // a service authenticating perfectly for its own domain and counting
        // for nothing.
        var html = await Client().GetStringAsync("/");

        var start = html.IndexOf("Authentication results", StringComparison.Ordinal);
        Assert.True(start >= 0, "the authentication panel is missing");
        var panel = html[start..Math.Min(start + 2500, html.Length)];

        Assert.Contains("the sending server was authorised by the envelope domain", panel, StringComparison.Ordinal);
        Assert.Contains("the signature verified", panel, StringComparison.Ordinal);
        Assert.Contains("matched the domain recipients see", panel, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AWideTableScrollsAtEveryWidthRatherThanOnlyOnAPhone()
    {
        // This rule lived inside the narrow-screen media query, so a table
        // wider than its column pushed the whole page sideways at any width
        // above it: 110px of horizontal overflow at 900px, where the overview
        // drops to two columns and the source table no longer fits one.
        var css = await Client().GetStringAsync("/app.css");

        var rule = css.IndexOf(".table-scroll { overflow-x: auto", StringComparison.Ordinal);
        Assert.True(rule >= 0, ".table-scroll has no unconditional overflow rule");

        // Anything before it must be a closed block, or the rule is nested in
        // a media query again.
        var before = css[..rule];
        Assert.Equal(before.Count(c => c == '{'), before.Count(c => c == '}'));
    }

    [Fact]
    public async Task TheDialSplitsVolumeThreeWaysWithEachPartNamed()
    {
        // A pass rate cannot say whether the remainder is forwarding, which is
        // expected, or mail that proved nothing, which is the only part worth
        // chasing.
        var html = await Client().GetStringAsync("/");

        Assert.Contains("gauge-dial", html, StringComparison.Ordinal);
        Assert.Contains("authenticated", html, StringComparison.Ordinal);
        Assert.Contains("forwarded or overridden", html, StringComparison.Ordinal);
        Assert.Contains("unauthenticated", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDialsSegmentsAreFilledRatherThanGivenABackground()
    {
        // SVG takes `fill`, not `background`. The first version reused the
        // proportion bar's color rules, which set `background` on a span and
        // do nothing whatever to a path, so every segment fell back to the
        // default fill and the dial rendered solid black. It looked like a
        // deliberate design until it was put on a screen.
        var css = await Client().GetStringAsync("/app.css");

        var start = css.IndexOf(".gauge-dial .seg", StringComparison.Ordinal);
        Assert.True(start >= 0, "the dial's segments have no color rules of their own");

        var block = css[start..Math.Min(css.Length, start + 600)];
        Assert.Contains("fill:", block, StringComparison.Ordinal);
    }

    /// <summary>
    /// HTML comments, which carry Blazor's persisted state and nothing a
    /// chart draws.
    /// </summary>
    private static readonly System.Text.RegularExpressions.Regex Comments =
        new("<!--.*?-->", System.Text.RegularExpressions.RegexOptions.Singleline);

    [Fact]
    public async Task NoChartEmitsANumberTheBrowserCannotParse()
    {
        // NaN or Infinity in a path attribute renders as an empty chart with
        // nothing logged anywhere, which is the hardest kind of wrong to spot.
        //
        // This failed intermittently on CI and never once locally, and the
        // improved assertion is what finally caught it out: the match was
        // inside the <!--Blazor-Server-Component-State--> comment, which is
        // several kilobytes of base64. N, a and n are all base64 characters,
        // so "NaN" turns up in that blob by chance on roughly one page load in
        // sixty - which is exactly the frequency that had been mistaken for a
        // flaky chart. Every division behind these charts really was guarded;
        // there was never a NaN to find.
        //
        // So the state comment is removed before scanning. Nothing a chart
        // renders lives in an HTML comment, and the test is otherwise
        // unchanged: it still reads every attribute of every element on every
        // route, and still says where it found one.
        foreach (var route in new[] { "/", "/domains/acme.com", "/domains/signed.example" })
        {
            var html = Comments.Replace(await Client().GetStringAsync(route), "");

            foreach (var bad in new[] { "NaN", "Infinity" })
            {
                var at = html.IndexOf(bad, StringComparison.Ordinal);
                if (at < 0) { continue; }

                var from = Math.Max(0, at - 220);
                var to = Math.Min(html.Length, at + 220);
                Assert.Fail($"{route} emitted {bad} at offset {at}:\n…{html[from..to]}…");
            }
        }
    }

    [Fact]
    public async Task ChartsNeedNoScriptAndNothingFetchedFromTheInternet()
    {
        // This is installed on somebody else's server, often one that cannot
        // reach the internet. A chart that fetches a library from a CDN is a
        // chart that does not draw.
        var html = await Client().GetStringAsync("/");

        Assert.DoesNotContain("cdn.", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("unpkg", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("chart.js", html, StringComparison.OrdinalIgnoreCase);

        // The SVG is in the page, not requested after it loads.
        Assert.Contains("<svg", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheShellKeepsDailyWorkAtTheTopAndFoldsTheRest()
    {
        // Nine links in one flat list made the dashboard, where every morning
        // starts, look like the same kind of thing as Updates. The shape now
        // matches the platforms this is compared against: the few things
        // looked at daily are top level, the rest are named groups.
        var html = await Client().GetStringAsync("/");

        Assert.Contains("nav-group", html, StringComparison.Ordinal);
        Assert.Contains(">Reporting<", html, StringComparison.Ordinal);
        Assert.Contains(">Settings<", html, StringComparison.Ordinal);

        // Daily work is not inside a fold: a group opened every morning is a
        // click paid for every morning.
        var dashboard = html.IndexOf(">Dashboard<", StringComparison.Ordinal);
        var firstFold = html.IndexOf("nav-fold", StringComparison.Ordinal);
        Assert.True(dashboard >= 0 && firstFold >= 0 && dashboard < firstFold,
            "the dashboard link must sit above the first collapsible group");
    }

    /// <summary>
    /// A group that stays shut while you are inside it makes the sidebar
    /// disagree with the page, and the person hunting for where they are is
    /// the one least able to afford that.
    /// </summary>
    [Fact]
    public async Task TheGroupYouAreInsideIsOpen()
    {
        var onReports = await Client().GetStringAsync("/reports");
        var onDashboard = await Client().GetStringAsync("/");

        Assert.Contains("<details class=\"nav-fold\" open", onReports, StringComparison.Ordinal);

        // And shut when you are not in it, or the fold is decoration.
        Assert.DoesNotContain("<details class=\"nav-fold\" open", onDashboard, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheShellButtonsCallScriptRatherThanBlazor()
    {
        // This layout has no render mode, so pages are interactive islands
        // inside a static shell and an @onclick here is never wired up. Both
        // buttons shipped that way once: they rendered perfectly and did
        // nothing at all when clicked, which only a real browser caught.
        var html = await Client().GetStringAsync("/");

        Assert.Contains("dmarcShell.toggleNav()", html, StringComparison.Ordinal);
        Assert.Contains("dmarcTheme.toggle()", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheThemeIsAppliedBeforeThePagePaints()
    {
        // A deferred script runs after first paint, so a person who chose dark
        // would get a white flash on every navigation.
        var html = await Client().GetStringAsync("/");

        var head = html[..html.IndexOf("</head>", StringComparison.Ordinal)];
        Assert.Contains("dmarc-theme", head, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LightIsTheDefaultAndDarkIsNotAssumedFromTheOperatingSystem()
    {
        // Somebody who picked light meant it. Inheriting the OS preference
        // would have the app go dark because their laptop did at sunset.
        //
        // Asserted against the stylesheet rather than the page: the rule lives
        // in app.css, so checking the HTML for it passes whatever the CSS says.
        var css = await Client().GetStringAsync("/app.css");

        Assert.Contains("data-theme=\"dark\"", css, StringComparison.Ordinal);
        Assert.DoesNotContain("prefers-color-scheme: dark", css, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EveryColorInTheStylesheetIsAToken()
    {
        // The first pass at a light theme left a dozen literal dark hexes in
        // the rules - table borders, row hovers, code backgrounds - and they
        // came out as black slots on a white page. Only the two token blocks
        // at the top may name a color.
        var css = await Client().GetStringAsync("/app.css");

        var rules = css[css.IndexOf("* { box-sizing", StringComparison.Ordinal)..];
        var literals = System.Text.RegularExpressions.Regex.Matches(rules, "#[0-9a-fA-F]{3,8}")
            .Select(m => m.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        Assert.True(literals.Count == 0, $"hard-coded colors outside the token blocks: {string.Join(", ", literals)}");
    }

    [Fact]
    public async Task TriageCountsAreFiltersRatherThanLabels()
    {
        // Saying four domains are losing mail and giving no way to see only
        // those four is a label, not a tool.
        var html = await Client().GetStringAsync("/");

        Assert.Contains("<button type=\"button\" class=\"count", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TablesCanScrollWithoutStretchingTheWholePage()
    {
        // A table is the one thing here that cannot reflow honestly: stacking
        // rows into cards loses the column-to-column comparison that is the
        // entire reason these are tables. So they scroll, bounded to the
        // table rather than the page.
        foreach (var route in new[] { "/", "/domains", "/domains/acme.com" })
        {
            var html = await Client().GetStringAsync(route);
            Assert.Contains("table-scroll", html, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task TheDomainPageOffersJumpLinksRatherThanHidingSectionsBehindTabs()
    {
        // Tabs would have hidden the unaligned-signature finding, which exists
        // precisely so a discarded valid signature stops being invisible.
        var html = await Client().GetStringAsync("/domains/signed.example");

        Assert.Contains("class=\"jump\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"unaligned\"", html, StringComparison.Ordinal);

        // Still rendered on the page, not merely linked to.
        Assert.Contains("signing correctly for the wrong domain", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDomainPageTellsGatewayTrafficApartFromImpersonation()
    {
        // Half of every failure on the real book was one hosted gateway
        // rewriting the customers' own mail. Listed as "sending as you without
        // authenticating" that is the customer's own security product being
        // described as an impersonator, and an operator who believes it goes
        // and weakens a record to make the number move.
        var html = await Client().GetStringAsync("/domains/signed.example");

        Assert.Contains("id=\"forwarded\"", html, StringComparison.Ordinal);
        Assert.Contains("Broken in transit by a gateway", html, StringComparison.Ordinal);
        // The catalog's name, which is what every other page calls it.
        Assert.Contains("INKY", html, StringComparison.Ordinal);

        // And the sentence that stops the wrong fix being attempted.
        Assert.Contains("No DNS record fixes this", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDomainPageShowsThePassRateWithoutForwardedMailBesideTheRawOne()
    {
        // Both, never one instead of the other: receivers act on the raw
        // figure, and this one says how much of the gap is fixable.
        var html = await Client().GetStringAsync("/domains/signed.example");

        Assert.Contains("excluding forwarded mail", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDomainPageOffersSomewhereToPasteAZoneFile()
    {
        // The one input this application cannot fetch for itself: DNS will not
        // list a domain's DKIM selectors and will not transfer a zone, so the
        // records that have stopped working are only visible in an export the
        // operator already has.
        var html = await Client().GetStringAsync("/domains/acme.com");

        Assert.Contains("id=\"zone\"", html, StringComparison.Ordinal);
        Assert.Contains("Audit this zone", html, StringComparison.Ordinal);
        Assert.Contains("<textarea", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainNamedAfterItsClientDoesNotPrintTheNameTwice()
    {
        // Onboarding by domain name makes the client name equal the domain for
        // most of them, and the heading printed it in the breadcrumb, as the
        // title and again as the customer.
        var html = await Client().GetStringAsync("/domains/acme.com");

        var head = html[html.IndexOf("<h1", StringComparison.Ordinal)..];
        var afterTitle = head[..Math.Min(400, head.Length)];
        Assert.DoesNotContain("<p class=\"sub\">acme.com</p>", afterTitle, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADomainNobodyHasReportedOnIsOnboardingRatherThanAnError()
    {
        var response = await Client().GetAsync("/domains/never-seen.example");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Nothing stored for", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClientsListsTheClientAndSaysWhichMessageCountItIs()
    {
        // Two pages showed "Messages" meaning different windows.
        var html = await Client().GetStringAsync("/clients");

        Assert.Contains("Acme Corp", html, StringComparison.Ordinal);
        Assert.Contains("all time", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReportsNamesTheProviderItWouldSignAs()
    {
        var html = await Client().GetStringAsync("/reports");

        Assert.Contains("NRG Tech Services", html, StringComparison.Ordinal);
        Assert.Contains("Acme Corp", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The print dialog owns the one part of the page the document cannot
    /// style, so the page has to say so.
    /// </summary>
    /// <remarks>
    /// Chrome and Edge stamp the date, the tab title and the URL over every
    /// printed page. On a report opened from this app that URL reads
    /// localhost:5000, and it went to a paying customer that way. No
    /// stylesheet can suppress it; only the person at the dialog can.
    /// </remarks>
    [Fact]
    public async Task ReportsSaysToTurnOffTheBrowsersHeadersAndFooters()
    {
        var html = await Client().GetStringAsync("/reports");

        Assert.Contains("Headers and footers", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The page behind a source's name, asked for as "should also be able to
    /// navigate to whats highlighted to see what to fix". Every table listed
    /// sources as dead text, so a row was the end of the trail rather than
    /// the start of it.
    /// </summary>
    [Fact]
    public async Task ASourceHasAPageOfItsOwn()
    {
        var html = await Client().GetStringAsync("/sources/192.0.2.25");

        Assert.Contains("192.0.2.25", html, StringComparison.Ordinal);
        Assert.Contains("Seen sending as", html, StringComparison.Ordinal);
        Assert.Contains("What to do", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSourcesListLinksToThatPage()
    {
        var html = await Client().GetStringAsync("/sources");

        Assert.Contains("/sources/", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// An address nobody has a report for is not an empty page about an
    /// address that may not exist.
    /// </summary>
    [Fact]
    public async Task AnAddressWithNoReportsSaysSoRatherThanRenderingBlank()
    {
        var html = await Client().GetStringAsync("/sources/198.51.100.200");

        Assert.Contains("Nothing from this address", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// IPv6 is most of the volume on a Microsoft-hosted estate, and its
    /// addresses are full of colons. A link that only worked for IPv4 would
    /// have been broken for the commonest sender there is.
    /// </summary>
    [Fact]
    public async Task AnIpv6AddressSurvivesTheRoundTripThroughTheUrl()
    {
        var html = await Client().GetStringAsync(
            "/sources/" + Uri.EscapeDataString("2a01:111:f403:c112::5"));

        // Either it has reports or it does not; what matters is that the page
        // renders and the address arrived intact rather than 404ing on a colon.
        Assert.Contains("2a01:111:f403:c112::5", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// TLS reports have been parsed and stored since the importer was
    /// written, and no page in the product ever referenced them. On a real
    /// estate the records are published and point at the operator's own
    /// mailbox, so they have been arriving, being filed, and being invisible.
    /// </summary>
    [Fact]
    public async Task TlsReportsHaveAPage()
    {
        var html = await Client().GetStringAsync("/tls");

        Assert.Contains("TLS reports", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// Three states look identical as an empty list and need different
    /// fixes: no record published, a record pointing at somebody else's
    /// mailbox, or a record that is right and nothing has arrived yet.
    /// Saying which saves an afternoon.
    /// </summary>
    [Fact]
    public async Task AnEmptyTlsPageSaysWhichKindOfEmptyItIs()
    {
        var html = await Client().GetStringAsync("/tls");

        Assert.Contains("_smtp._tls", html, StringComparison.Ordinal);
        Assert.Contains("rua=", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReportingGroupLinksToTls()
    {
        var html = await Client().GetStringAsync("/");

        Assert.Contains("href=\"tls\"", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A scoped view is a place, not something you retype.
    /// </summary>
    /// <remarks>
    /// The filter box filtered as you typed and forgot the moment you opened
    /// a domain, so working through one customer meant retyping it on every
    /// return. Held in the address now, which also makes it a link: "here is
    /// the one I mean" can be pasted into a ticket.
    /// </remarks>
    [Fact]
    public async Task TheTriageViewIsRestoredFromTheAddress()
    {
        var html = await Client().GetStringAsync("/?find=acme&level=urgent");

        // The controls come back holding what the address asked for, rather
        // than the page opening on everything again.
        Assert.Contains("value=\"acme\"", html, StringComparison.Ordinal);
        Assert.Contains("aria-pressed=\"true\"", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A hand-typed window the control does not offer is ignored rather than
    /// obeyed, so the select and the page cannot disagree.
    /// </summary>
    [Fact]
    public async Task AnImpossibleWindowInTheAddressIsNotAdopted()
    {
        var html = await Client().GetStringAsync("/?days=900");

        Assert.DoesNotContain("value=\"900\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FailureReportsHaveAPage()
    {
        var html = await Client().GetStringAsync("/failures");

        Assert.Contains("Failure reports", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The normal state of this page is empty, and it has to say why.
    /// </summary>
    /// <remarks>
    /// Almost no large receiver sends failure reports. A page that shows
    /// nothing and explains nothing reads as broken, and the fix an operator
    /// would reach for - republishing ruf= - is not the problem, so they would
    /// spend an afternoon on a record that was already correct.
    /// </remarks>
    [Fact]
    public async Task AnEmptyFailuresPageSaysWhyItIsEmpty()
    {
        var html = await Client().GetStringAsync("/failures");

        Assert.Contains("not a sign that anything is misconfigured", html, StringComparison.Ordinal);
        Assert.Contains("ruf=", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReportingGroupLinksToFailureReports()
    {
        var html = await Client().GetStringAsync("/");

        Assert.Contains("href=\"failures\"", html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/settings")]
    [InlineData("/fix")]
    [InlineData("/")]
    public async Task NoPageEverShowsAProviderToken(string route)
    {
        // The settings page lists the provider and its credential reference.
        // The reference is fine to show; the token behind it is not, on this
        // page or any other, in a screenshot or a support ticket.
        var html = await Client().GetStringAsync(route);

        Assert.DoesNotContain(SeededApp.ProviderToken, html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SettingsNamesTheProviderAndWhereSecretsLive()
    {
        var html = await Client().GetStringAsync("/settings");

        Assert.Contains("cloudflare", html, StringComparison.Ordinal);
        Assert.Contains("zone-acme", html, StringComparison.Ordinal);
        Assert.Contains("dmarc.local.cloudflare.", html, StringComparison.Ordinal);
        Assert.Contains("never", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FixSaysWhatItIsForBeforeAnythingIsRead()
    {
        // DNS is read after first render, so the static page is what a
        // request sees. It has to say what will happen, not sit blank.
        var html = await Client().GetStringAsync("/fix");

        Assert.Contains("what we did", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AReportDownloadsAsAWholeDocument()
    {
        var response = await Client().GetAsync("/reports/download/acme-corp/2026-08");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.Contains("Email Protection Report", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AReportForAClientThatDoesNotExistIsNotFound()
    {
        var response = await Client().GetAsync("/reports/download/no-such-client/2026-08");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ABadMonthIsRefusedRatherThanGuessedAt()
    {
        var response = await Client().GetAsync("/reports/download/acme-corp/August");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task SettingsSaysWhetherSignInIsOn()
    {
        // The question an operator cannot otherwise answer.
        var html = await Client().GetStringAsync("/settings");

        Assert.Contains("local trial mode", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SettingsNeverPrintsASecret()
    {
        // A client secret on a settings page is a secret in a screenshot in a
        // support ticket.
        var html = await Client().GetStringAsync("/settings");

        Assert.DoesNotContain("ClientSecret", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(SeededApp.ProviderToken, html, StringComparison.Ordinal);

        // The page does take a token in, once, through a password field, so
        // what is typed is not on the screen either.
        Assert.Contains("type=\"password\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SourcesSeparatesARelayFromAnImpersonator()
    {
        var html = await Client().GetStringAsync("/sources");

        // The relay sends legitimately for this domain as well as failing, so
        // it must not be described as somebody sending as the client.
        Assert.DoesNotContain("Authenticated nothing, against", html, StringComparison.Ordinal);
    }
}

/// <summary>
/// The application, started in process against a database with known data.
///
/// One database for the whole class: these are read-only pages, and building
/// it per test would make the suite slower than the thing it is testing.
/// </summary>
public class SeededApp : WebApplicationFactory<Program>
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"dmarc-pages-{Guid.NewGuid():N}.db");
    private readonly string _secretsDir =
        Path.Combine(Path.GetTempPath(), $"dmarc-pages-secrets-{Guid.NewGuid():N}");

    /// <summary>The token stored for the seeded provider. Must never appear in any page.</summary>
    public const string ProviderToken = "cf-token-KEEP-OUT-OF-PAGES-9f8e7d";

    /// <summary>
    /// This instance's database, for a test that needs to put something in it
    /// that no report can carry.
    /// </summary>
    /// <remarks>
    /// Safe to write to: xUnit builds one fixture per test class, so each
    /// class gets its own file. Writing to it from a test would be a trap
    /// only if the fixture were shared across classes, which a collection
    /// fixture is and this is not.
    /// </remarks>
    public string DatabasePath => _dbPath;

    public SeededApp() => Seed().GetAwaiter().GetResult();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Configuration rather than swapping the registration. Program
        // resolves the path once at startup and hands it to several services
        // as a plain string, so replacing DatabaseInfo afterwards moves only
        // one of them - the pages then read a seeded database while the
        // triage list reads the default, and everything renders an empty
        // state that looks like a passing test. Going in through
        // configuration is also what a real deployment does.
        builder.UseSetting("Database:Path", _dbPath);
        builder.UseSetting("Secrets:Directory", _secretsDir);

        // A configured install, which is what one looks like before anybody
        // sends a report: without this the download refuses, because a
        // document signed "your IT provider" must not reach a customer. The
        // unset case has its own fixture below, since it is a behaviour in
        // its own right rather than the default state of these tests.
        if (ProviderName is { } provider) { builder.UseSetting("Reporting:ProviderName", provider); }
    }

    /// <summary>How this host names itself on reports, or null for not configured.</summary>
    protected virtual string? ProviderName => "NRG Tech Services";

    private async Task Seed()
    {
        var store = new ReportStore(_dbPath);
        await store.InitializeAsync(DatabaseSchema.Sql);

        var begin = DateTimeOffset.UtcNow.AddDays(-2);
        var august = new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero);

        // Recent, so the triage window sees it: enforcing, above the healthy
        // threshold, and still refusing 40 messages. That combination was
        // silent on the triage page and is the reason these tests exist.
        await StoreAsync(store, begin, 960, 40);

        // And a month with data in it, so a report can be generated.
        await StoreAsync(store, august, 200, 10);

        // A second domain carrying the shape that reads as a contradiction: a
        // vendor whose DKIM signature verifies over its own domain, beside the
        // same vendor's other host signing as the customer correctly. Kept off
        // acme.com so the figures the other tests assert on do not move.
        await StoreUnalignedAsync(store, begin);

        var slug = await store.CreateClientAsync("Acme Corp");
        await store.AssignDomainAsync("acme.com", slug!);
        await store.AssignDomainAsync("signed.example", slug!);

        // A provider with a real-looking token, stored the way the settings
        // page stores one, so the pages can be checked for leaking it.
        var configs = new DnsProviderConfigs(_dbPath, new LocalSecretStore(_secretsDir));
        await configs.SetAsync(slug!, null, "cloudflare", new Dictionary<string, string> { ["zone_id"] = "zone-acme" }, ProviderToken);
    }

    private static async Task StoreAsync(ReportStore store, DateTimeOffset begin, int passing, int failing)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>acme.com</domain><p>reject</p><pct>100</pct></policy_published>
              <record>
                <row>
                  <source_ip>192.0.2.25</source_ip><count>{passing}</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>acme.com</header_from></identifiers>
                <auth_results>
                  <dkim><domain>acme.com</domain><selector>selector1</selector><result>pass</result></dkim>
                  <spf><domain>acme.com</domain><result>pass</result></spf>
                </auth_results>
              </record>
              <record>
                <row>
                  <source_ip>192.0.2.25</source_ip><count>{failing}</count>
                  <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>acme.com</header_from></identifiers>
                <auth_results>
                  <dkim><domain>acme.com</domain><selector>selector1</selector><result>fail</result></dkim>
                  <spf><domain>acme.com</domain><result>fail</result></spf>
                </auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException($"seed report did not parse: {parsed.Error}"); }
        await store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    /// <summary>The valid-signature-wrong-domain case, published at p=reject.</summary>
    private static async Task StoreUnalignedAsync(ReportStore store, DateTimeOffset begin)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>signed.example</domain><p>reject</p><pct>100</pct>
                <adkim>s</adkim><aspf>s</aspf></policy_published>
              <record>
                <row>
                  <source_ip>23.21.109.197</source_ip><count>14</count>
                  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>signed.example</header_from></identifiers>
                <auth_results>
                  <dkim><domain>signed.example</domain><selector>s1</selector><result>pass</result></dkim>
                  <spf><domain>psm.vendor.example</domain><result>pass</result></spf>
                </auth_results>
              </record>
              <record>
                <row>
                  <source_ip>147.160.167.15</source_ip><count>289</count>
                  <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>signed.example</header_from></identifiers>
                <auth_results>
                  <dkim><domain>training.vendor.example</domain><selector>s2</selector><result>pass</result></dkim>
                  <spf><domain>psm.vendor.example</domain><result>pass</result></spf>
                </auth_results>
              </record>
              <!-- A security gateway: it received this domain's mail, added
                   its banner and sent it on, so the domain's own signature is
                   still named on the message and no longer verifies. The
                   envelope is the gateway's, which is what names it. -->
              <record>
                <row>
                  <source_ip>198.51.100.77</source_ip><count>9</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>signed.example</header_from></identifiers>
                <auth_results>
                  <dkim><domain>signed.example</domain><result>fail</result></dkim>
                  <spf><domain>ipw.inkyphishfence.com</domain><result>fail</result></spf>
                </auth_results>
              </record>
              <!-- A forwarder, so the estate has all three of the dial's
                   categories. Without one the middle segment is correctly
                   omitted and there is nothing to assert it against. Kept off
                   acme.com so the figures the other tests rely on do not move. -->
              <record>
                <row>
                  <source_ip>198.51.100.44</source_ip><count>12</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
                    <reason><type>forwarded</type><comment>mailing list</comment></reason>
                  </policy_evaluated>
                </row>
                <identifiers><header_from>signed.example</header_from></identifiers>
                <auth_results>
                  <dkim><domain>signed.example</domain><result>fail</result></dkim>
                  <spf><domain>signed.example</domain><result>fail</result></spf>
                </auth_results>
              </record>
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success) { throw new InvalidOperationException($"seed report did not parse: {parsed.Error}"); }
        await store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) { return; }

        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
        try { Directory.Delete(_secretsDir, recursive: true); } catch (IOException) { }
    }
}

/// <summary>
/// The same install with nobody's name on it, which is how it arrives.
/// </summary>
/// <remarks>
/// A fresh install has no <c>Reporting:ProviderName</c>, and a report built
/// on one is signed "prepared by your IT provider", literally. That happened
/// to a real customer. The page warned about it and still offered the link,
/// which is a page telling somebody what to ignore.
/// </remarks>
public sealed class UnnamedProviderApp : SeededApp
{
    protected override string? ProviderName => null;
}

public sealed class UnnamedProviderTests : IClassFixture<UnnamedProviderApp>
{
    private readonly UnnamedProviderApp _app;

    public UnnamedProviderTests(UnnamedProviderApp app) => _app = app;

    private HttpClient Client() => _app.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = true,
        HandleCookies = true,
    });

    [Fact]
    public async Task AReportThatWouldBeSignedByNobodyIsRefused()
    {
        var response = await Client().GetAsync("/reports/download/acme-corp/2026-08");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains(
            "your IT provider",
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ThePageSaysWhyItCannotBeOpenedRatherThanOfferingTheLink()
    {
        var html = await Client().GetStringAsync("/reports");

        Assert.Contains("Reports cannot be opened yet", html, StringComparison.Ordinal);
        Assert.Contains("Reporting:ProviderName", html, StringComparison.Ordinal);

        // And the control is inert rather than gone: a missing button reads as
        // a feature that does not exist, where a greyed one reads as "not yet".
        Assert.Contains("primary-link disabled", html, StringComparison.Ordinal);
        Assert.DoesNotContain("reports/download/acme-corp", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The way out is on the page that is blocked, not on another one.
    /// </summary>
    /// <remarks>
    /// Refusing is right and sending somebody elsewhere to find one field is
    /// not: on a first run it leaves the one thing the product is for behind
    /// a setting nobody knew existed. The field that unlocks it is here, and
    /// it writes to the organization - which is also the correct answer on a
    /// multi-organization install, where each one signs its own reports.
    /// </remarks>
    [Fact]
    public async Task ThePageOffersTheFieldThatUnlocksItself()
    {
        var html = await Client().GetStringAsync("/reports");

        Assert.Contains("Your name on reports", html, StringComparison.Ordinal);
        Assert.Contains("Use this name", html, StringComparison.Ordinal);
    }
}
