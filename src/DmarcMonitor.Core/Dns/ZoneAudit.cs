namespace DmarcMonitor.Core.Dns;

/// <summary>Where a finding came from, which decides how much it is worth.</summary>
/// <remarks>
/// A zone file is a snapshot somebody exported and pasted. It can be an hour
/// old or a year old, and it can disagree with live DNS in either direction:
/// the fault it shows may have been fixed since, or the fix it shows may never
/// have been published. Every finding says which evidence produced it, so
/// nobody acts on the file believing they are acting on DNS.
/// </remarks>
public enum FindingSource
{
    /// <summary>The pasted file alone. Live DNS was not read, or could not be.</summary>
    Zone,

    /// <summary>The file, and live DNS was asked and agrees.</summary>
    ZoneAndDns,

    /// <summary>Live DNS, which the file disagrees with or is silent about.</summary>
    Dns,

    /// <summary>The file against what the reports have actually seen.</summary>
    ZoneAndReports,
}

/// <summary>One thing wrong in, or missing from, a zone file.</summary>
public sealed record ZoneFinding
{
    public required HygieneSeverity Severity { get; init; }

    /// <summary>SPF, DKIM, DMARC, NS, zone.</summary>
    public required string Record { get; init; }

    /// <summary>The name this is about, qualified. Empty when it is about the zone as a whole.</summary>
    public string Name { get; init; } = "";

    /// <summary>The line in the pasted file, or 0 when the finding did not come from a line.</summary>
    public int Line { get; init; }

    public required string Problem { get; init; }

    public required string Fix { get; init; }

    public required FindingSource Source { get; init; }

    /// <summary>
    /// Where this one came from, when the general sentence for its
    /// <see cref="Source"/> would be wrong.
    /// </summary>
    /// <remarks>
    /// Set rarely and on purpose. "The file alone - live DNS was not consulted
    /// for this, so it may have changed since" is the right caveat for a
    /// finding about a record, and nonsense over a finding about the file's
    /// own header, which no resolver has an opinion about.
    /// </remarks>
    public string Because { get; init; } = "";

    /// <summary>Where this finding came from, in the words an operator needs.</summary>
    public string Evidence => Because.Length > 0 ? Because : ZoneAudit.Describe(Source);

    /// <summary>
    /// The RFC section the rule comes from, where there genuinely is one.
    /// </summary>
    /// <remarks>
    /// Left empty rather than invented. A made-up citation is worse than none,
    /// because the first person who looks it up stops trusting every other one
    /// in the document.
    /// </remarks>
    public string Reference { get; init; } = "";
}

/// <summary>What is published at one DKIM selector, and whether it has ever signed.</summary>
public sealed record SelectorEvidence
{
    public required string Selector { get; init; }

    /// <summary>
    /// Every TXT record live DNS returns at this selector, or null when the
    /// lookup could not answer.
    /// </summary>
    /// <remarks>
    /// Null and empty are different answers and the difference is the point.
    /// Empty means the name resolves to nothing, which for a selector in a
    /// zone file is a real finding. Null means a resolver did not reply, from
    /// which nothing whatever follows.
    /// </remarks>
    public IReadOnlyList<string>? LiveRecords { get; init; }

    /// <summary>The key a verifier would use, or null when the lookup could not answer.</summary>
    public DkimKey? LiveKey { get; init; }

    /// <summary>True when a report has shown a signature by this selector verifying.</summary>
    public bool SeenSigning { get; init; }
}

/// <summary>Everything that could be learned from outside the file.</summary>
public sealed record ZoneEvidence
{
    /// <summary>What the apex publishes right now, or null when DNS was not read.</summary>
    public PublishedRecords? Live { get; init; }

    /// <summary>True when the live reading answered, so an absence in it means something.</summary>
    public bool DnsRead => Live is { LookupFailed: false, DomainDoesNotExist: false };

    /// <summary>The name servers the domain is delegated to. Empty means the lookup did not answer.</summary>
    public IReadOnlyList<string> Delegation { get; init; } = [];

    /// <summary>Selector evidence, keyed by selector.</summary>
    public IReadOnlyDictionary<string, SelectorEvidence> Selectors { get; init; } =
        new Dictionary<string, SelectorEvidence>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Selectors the reports have seen signing for this domain, inside the window.</summary>
    public IReadOnlyList<string> SeenSigning { get; init; } = [];

    /// <summary>True when the reports were consulted at all.</summary>
    public bool ReportsRead { get; init; }

    /// <summary>
    /// Days of reports actually held for this domain.
    /// </summary>
    /// <remarks>
    /// Decides whether silence means anything, exactly as it does in
    /// <see cref="DnsHygiene"/>. A selector that has not signed in the two
    /// days of reports on hand has not told anybody anything.
    /// </remarks>
    public int ReportWindowDays { get; init; }

    public SelectorEvidence? For(string selector) =>
        Selectors.TryGetValue(selector, out var found) ? found : null;
}

/// <summary>
/// Reads a zone file against live DNS and against what the reports have seen.
///
/// The zone file earns its place by being the only thing that can enumerate.
/// DNS has no way to list a domain's DKIM selectors - there is no query for
/// it and no wildcard to walk - so <see cref="RecordStatus"/> can only check
/// the selectors reports have named, which is every selector that is working
/// and none of the ones that are not. A zone export names all of them,
/// including the CNAME left behind by a service retired three years ago that
/// now points at nothing.
///
/// Pure, and deliberately so: an operator acts on this by editing a customer's
/// DNS, and a wrong finding there breaks a business's mail. Nothing is
/// concluded from a lookup that did not answer, and nothing the file alone can
/// show is reported as though DNS had confirmed it.
/// </summary>
public static class ZoneAudit
{
    /// <summary>The label under which a selector's key is published.</summary>
    private const string DomainKey = "_domainkey";

    /// <summary>
    /// Where a finding came from, in the words an operator needs.
    /// </summary>
    /// <remarks>
    /// Here rather than in each caller so the command and the page cannot end
    /// up describing the same evidence differently.
    /// </remarks>
    public static string Describe(FindingSource source) => source switch
    {
        FindingSource.ZoneAndDns => "the file, confirmed against live DNS",
        FindingSource.Dns => "live DNS",
        FindingSource.ZoneAndReports => "the file, against what the reports have seen",
        _ => "the file alone - live DNS was not consulted for this, so it may have changed since",
    };

    /// <summary>
    /// Key size no longer worth publishing.
    /// </summary>
    /// <remarks>
    /// 1024 bits still verifies everywhere. It is on this list because it is
    /// the size every provider issued by default until recently, because the
    /// rotation is free, and because a key nobody has looked at since it was
    /// issued is usually one of a set - eleven of the sixteen domains this was
    /// first run against were on 1024.
    /// </remarks>
    public const int RotateBelowBits = 2048;

    /// <summary>Reports needed before "this selector has never signed" means anything.</summary>
    public const int MinimumDaysToJudgeASelector = DnsHygiene.MinimumDaysToJudgeAnInclude;

    /// <summary>
    /// Every DKIM selector the file carries a record for.
    /// </summary>
    /// <remarks>
    /// Both TXT and CNAME, because which of the two a provider uses says
    /// nothing about whether the key works: Microsoft and Amazon publish
    /// CNAMEs, KnowBe4 and Mandrill publish the key itself, and a dead
    /// selector looks the same either way.
    /// </remarks>
    public static IReadOnlyList<string> SelectorsIn(ParsedZone zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        if (zone.Origin.Length == 0) { return []; }

        var suffix = $".{DomainKey}.{zone.Origin}";
        var found = new List<string>();

        foreach (var record in zone.Records)
        {
            if (record.Type is not ("TXT" or "CNAME")) { continue; }
            if (!record.Name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) { continue; }

            var selector = record.Name[..^suffix.Length];
            if (selector.Length == 0) { continue; }
            if (!found.Contains(selector, StringComparer.OrdinalIgnoreCase)) { found.Add(selector); }
        }

        found.Sort(StringComparer.Ordinal);
        return found;
    }

    /// <summary>
    /// The finding for a file that is a zone for some other domain.
    /// </summary>
    /// <remarks>
    /// The mis-paste, and it produces the most convincing wrong answer this
    /// could give. Asked about one domain and handed another's zone, an audit
    /// that took the caller's word would place every name in the file under a
    /// domain it has nothing to do with, resolve selectors that were never
    /// there, and match it all against a third party's reports - and every
    /// sentence of it would read as a careful finding about the customer on
    /// screen.
    /// </remarks>
    public static ZoneFinding WrongZone(string declared, string asked) => new()
    {
        Severity = HygieneSeverity.Breaking,
        Record = "zone",
        Name = declared,
        Problem = $"This file is a zone for {declared}; the domain asked about is {asked}. Nothing in "
                + "it was judged, because every name in it belongs to a different domain.",
        Fix = $"Export the zone for {asked} and paste that instead. If this file really is {asked}'s "
            + "zone, its header says otherwise and that is worth settling first.",
        Source = FindingSource.Zone,
        Because = "the file's own header",
    };

    public static IReadOnlyList<ZoneFinding> Assess(ParsedZone zone, ZoneEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(zone);
        ArgumentNullException.ThrowIfNull(evidence);

        if (zone.Origin.Length == 0)
        {
            return
            [
                new ZoneFinding
                {
                    Severity = HygieneSeverity.Weakness,
                    Record = "zone",
                    Problem = "The file does not say which domain it is a zone for, so nothing in it could "
                            + "be placed. Every name in a zone file is relative to an origin, and without "
                            + "one there is no way to tell an apex record from a subdomain's.",
                    Fix = "Name the domain explicitly, or paste the file with its header and $ORIGIN line "
                        + "intact.",
                    Source = FindingSource.Zone,
                },
            ];
        }

        var findings = new List<ZoneFinding>();

        if (zone.Records.Count == 0)
        {
            findings.Add(new ZoneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "zone",
                Name = zone.Origin,
                Problem = "No records could be read out of the file, so nothing below was checked.",
                Fix = "Check the whole export was pasted, including the record lines.",
                Source = FindingSource.Zone,
            });

            return findings;
        }

        Spf(findings, zone, evidence);
        Dkim(findings, zone, evidence);
        ReportAuthorizations(findings, zone);
        Delegation(findings, zone, evidence);
        Cnames(findings, zone);
        Disagreements(findings, zone, evidence);

        return [.. findings.OrderByDescending(f => f.Severity)];
    }

    // ---- SPF -----------------------------------------------------------------

    private static void Spf(List<ZoneFinding> findings, ParsedZone zone, ZoneEvidence evidence)
    {
        var apex = zone.At(zone.Origin, "TXT").ToList();
        var spf = apex.FindAll(r => IsSpf(r.Value));
        var liveHasSpf = evidence.DnsRead && evidence.Live!.SpfRecords.Count > 0;

        // The finding this whole feature was built for. A TXT record that is
        // plainly an SPF record and is missing the six characters that make it
        // one is not "no SPF record" - it is a record somebody wrote, believes
        // is protecting the domain, and which every receiver on the internet
        // skips over without a word. Told "no SPF record is published", an
        // operator goes and adds a second one, and then the domain has two.
        foreach (var inert in apex.Where(r => !IsSpf(r.Value) && LooksLikeSpf(r.Value)))
        {
            var stillThere = !evidence.DnsRead
                || evidence.Live!.ApexTxt.Any(t => Same(t, inert.Value));

            findings.Add(new ZoneFinding
            {
                Severity = liveHasSpf ? HygieneSeverity.Tidy : HygieneSeverity.Breaking,
                Record = "SPF",
                Name = zone.Origin,
                Line = inert.Line,
                Problem = Inert(inert.Value, evidence.DnsRead, liveHasSpf, stillThere),
                Fix = liveHasSpf
                    ? (stillThere
                        ? "Delete the record without the prefix. It authorizes nothing and will be read as "
                          + "an SPF record by the next person who looks at the zone."
                        : "Nothing, on this. The export is older than the fix.")
                    : $"Publish it as \"v=spf1 {inert.Value.Trim()}\" - the same record with the version "
                      + "prefix in front - rather than adding a second record beside it.",
                Source = evidence.DnsRead ? FindingSource.ZoneAndDns : FindingSource.Zone,
                Reference = "RFC 7208 §4.5",
            });
        }

        if (spf.Count > 1)
        {
            var liveCount = evidence.DnsRead ? evidence.Live!.SpfRecords.Count : spf.Count;

            findings.Add(new ZoneFinding
            {
                Severity = liveCount > 1 ? HygieneSeverity.Breaking : HygieneSeverity.Tidy,
                Record = "SPF",
                Name = zone.Origin,
                Line = spf[1].Line,
                Problem = liveCount > 1
                    ? $"The zone has {spf.Count} SPF records at the apex and a domain may have one. "
                      + "Receivers treat more than one as an error, and an error is not a pass, so SPF "
                      + "fails for every sender. Live DNS has "
                      + (liveCount == spf.Count ? "the same." : $"{liveCount} of them.")
                    : $"The zone has {spf.Count} SPF records at the apex. Live DNS has one, so this has "
                      + "been fixed since the file was exported.",
                Fix = liveCount > 1
                    ? "Merge them into a single record and delete the rest."
                    : "Nothing, on this.",
                Source = evidence.DnsRead ? FindingSource.ZoneAndDns : FindingSource.Zone,
                Reference = "RFC 7208 §4.5",
            });
        }
    }

    private static string Inert(string value, bool dnsRead, bool liveHasSpf, bool stillThere)
    {
        var record = $"\"{value.Trim()}\"";

        if (liveHasSpf)
        {
            return stillThere
                ? $"The apex carries {record}, which reads as an SPF record and is not one - it has no "
                  + "v=spf1 prefix, so no receiver evaluates it. A valid SPF record is published alongside "
                  + "it, so mail is not affected; this one is just left over."
                : $"The apex in this file carries {record}, which reads as an SPF record and is not one - "
                  + "it has no v=spf1 prefix. Live DNS no longer has it and publishes a valid SPF record, "
                  + "so the file is older than the fix.";
        }

        return $"The apex carries {record}. It reads as an SPF record and is not one: without the v=spf1 "
             + "prefix no receiver evaluates it, so this domain has no SPF at all while appearing to "
             + (dnsRead
                 ? "have one. Live DNS agrees - the record is there and there is no SPF record beside it."
                 : "have one. Live DNS was not read, so this may have been fixed since the export.");
    }

    // ---- DKIM ----------------------------------------------------------------

    private static void Dkim(List<ZoneFinding> findings, ParsedZone zone, ZoneEvidence evidence)
    {
        var selectors = SelectorsIn(zone);
        var rotate = new List<string>();
        var tooSmall = new List<string>();
        var serving = ProvidersThatAnswer(zone, evidence, selectors);

        foreach (var selector in selectors)
        {
            var name = $"{selector}.{DomainKey}.{zone.Origin}";
            var txt = zone.At(name, "TXT").ToList();
            var cname = zone.At(name, "CNAME").ToList();
            var live = evidence.For(selector);

            MoreThanOneKey(findings, name, selector, txt, live);
            NotAKey(findings, name, selector, txt, live);

            // Nothing published where the zone says there is something. The
            // stale CNAME case: a provider was removed, its selector record
            // was left behind, and the name it points at stopped existing.
            if (live?.LiveKey is { Published: false } && !IsARotationSlot(cname, serving))
            {
                var target = cname.Count > 0 ? cname[0].Target : "";

                findings.Add(new ZoneFinding
                {
                    Severity = live.SeenSigning ? HygieneSeverity.Breaking : HygieneSeverity.Tidy,
                    Record = "DKIM",
                    Name = name,
                    Line = txt.Count > 0 ? txt[0].Line : (cname.Count > 0 ? cname[0].Line : 0),
                    Problem = $"The zone publishes the selector {selector} and nothing resolves there"
                            + (target.Length > 0 ? $" - the CNAME points at {target}, which has no key on it" : "")
                            + (live.SeenSigning
                                ? ". Mail has been seen signing with this selector, so that mail is failing "
                                  + "DKIM now or will as soon as the receivers' caches expire."
                                : ". No mail has been seen signing with it either, so it is a leftover."),
                    Fix = live.SeenSigning
                        ? $"Find out which service signs as {selector} and have it republish the key, before "
                          + "removing anything."
                        : $"Confirm the service that owned {selector} is really gone, then remove the record. "
                          + "A selector that resolves to nothing does no harm; it just makes the zone harder "
                          + "to read.",
                    Source = FindingSource.ZoneAndDns,
                    Reference = "RFC 6376 §3.6.2.1",
                });
            }

            // Judged from live DNS where there is any, and from the file
            // otherwise. A CNAME selector with no live reading says nothing
            // about its key at all, and is left alone rather than guessed at.
            var key = live?.LiveKey ?? (txt.Count > 0
                ? DkimKey.Choose(selector, [.. txt.Select(r => r.Value)])
                : null);

            if (key is { Usable: true, Bits: { } bits })
            {
                if (bits < 1024) { tooSmall.Add($"{selector} ({bits}-bit)"); }
                else if (bits < RotateBelowBits) { rotate.Add($"{selector} ({bits}-bit)"); }
            }

            NeverSigned(findings, evidence, name, selector, key, live);
        }

        KeySizes(findings, zone, evidence, tooSmall, rotate);
        NotInTheZone(findings, zone, evidence, selectors);
    }

    /// <summary>
    /// The providers that have at least one selector answering in this zone.
    /// </summary>
    /// <remarks>
    /// Grouped by the last two labels of the CNAME target, which is enough to
    /// tell one signing service from another and is not being used for
    /// anything a mistake would be dangerous in.
    /// </remarks>
    private static HashSet<string> ProvidersThatAnswer(
        ParsedZone zone, ZoneEvidence evidence, IReadOnlyList<string> selectors)
    {
        var answering = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var selector in selectors)
        {
            if (evidence.For(selector)?.LiveKey is not { Usable: true }) { continue; }

            foreach (var cname in zone.At($"{selector}.{DomainKey}.{zone.Origin}", "CNAME"))
            {
                if (Provider(cname.Target) is { Length: > 0 } provider) { answering.Add(provider); }
            }
        }

        return answering;
    }

    /// <summary>
    /// True when a selector that resolves to nothing is the empty half of a
    /// pair rather than something left behind.
    /// </summary>
    /// <remarks>
    /// Microsoft 365 publishes selector1 and selector2 for every domain and
    /// serves a key at only one of them until the first rotation; several
    /// other providers do the same. The unused half looks exactly like a dead
    /// record, and it is the opposite of one - removing it is what breaks the
    /// rotation, months later, in a way nobody connects to the tidy-up. So
    /// where another selector from the same provider is answering, this says
    /// nothing at all rather than inviting somebody to delete it.
    ///
    /// When no selector from that provider answers, the finding stands: that
    /// is a provider configured in DNS and signing nothing.
    /// </remarks>
    private static bool IsARotationSlot(List<ZoneRecord> cname, HashSet<string> serving) =>
        cname.Exists(c => Provider(c.Target) is { Length: > 0 } provider && serving.Contains(provider));

    /// <summary>The last two labels of a name, as a rough identity for a service.</summary>
    private static string Provider(string target)
    {
        var labels = target.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return labels.Length < 2 ? "" : $"{labels[^2]}.{labels[^1]}";
    }

    private static void MoreThanOneKey(
        List<ZoneFinding> findings, string name, string selector,
        List<ZoneRecord> txt, SelectorEvidence? live)
    {
        if (txt.Count <= 1) { return; }

        var liveCount = live?.LiveRecords?.Count;

        findings.Add(new ZoneFinding
        {
            Severity = liveCount is null or > 1 ? HygieneSeverity.Weakness : HygieneSeverity.Tidy,
            Record = "DKIM",
            Name = name,
            Line = txt[1].Line,
            Problem = $"{txt.Count} TXT records are published at {selector}. The standard does not say "
                    + "which of several a verifier picks, so a signature made with one of these keys "
                    + "verifies at some receivers and fails at others"
                    + liveCount switch
                    {
                        null => ". Live DNS was not read.",
                        > 1 => $". Live DNS has {liveCount} of them too.",
                        _ => $". Live DNS has {liveCount}, so this has been tidied since the export.",
                    },
            Fix = liveCount is 1
                ? "Nothing, on this."
                : "Keep the record the signing service issued and delete the others. If two services sign "
                  + "for this domain, give each its own selector.",
            Source = live?.LiveRecords is null ? FindingSource.Zone : FindingSource.ZoneAndDns,
            Reference = "RFC 6376 §3.6.2.1",
        });
    }

    private static void NotAKey(
        List<ZoneFinding> findings, string name, string selector,
        List<ZoneRecord> txt, SelectorEvidence? live)
    {
        foreach (var record in txt)
        {
            // An empty TXT record says nothing worth a finding of its own, and
            // parsing it would produce "nothing published at this selector" -
            // a sentence about an absence, printed over a record that is there.
            if (record.Value.Trim().Length == 0) { continue; }

            var parsed = DkimKey.Parse(selector, record.Value);
            if (parsed.Strength != DkimKeyStrength.Invalid) { continue; }

            // A record that is still there live is a live fault; one that is
            // not is a fault in a file that has been overtaken.
            var stillThere = live?.LiveRecords is null
                || live.LiveRecords.Any(t => Same(t, record.Value));

            findings.Add(new ZoneFinding
            {
                Severity = stillThere ? HygieneSeverity.Weakness : HygieneSeverity.Tidy,
                Record = "DKIM",
                Name = name,
                Line = record.Line,
                Problem = $"A record at this selector is {parsed.Problem}"
                        + (stillThere
                            ? ". Whatever it was meant to be, no verifier can use it as a key."
                            : ". Live DNS no longer has it."),
                Fix = stillThere
                    ? "Republish the record exactly as the signing service issued it. The version tag is "
                      + "v=DKIM1, with the 1: anything else and the record is not read as a DKIM key at all."
                    : "Nothing, on this.",
                Source = live?.LiveRecords is null ? FindingSource.Zone : FindingSource.ZoneAndDns,
                Reference = "RFC 6376 §3.6.1",
            });
        }
    }

    /// <summary>
    /// A selector that is published, resolves, and has never signed anything.
    /// </summary>
    /// <remarks>
    /// Evidence, never an instruction. A selector can be real and idle: a
    /// second key staged for a rotation that has not happened, a service that
    /// sends at quarter end, a provider kept configured for a system nobody
    /// has switched on yet. Microsoft publishes selector1 and selector2 for
    /// every tenant and signs with one of them at a time, which is exactly
    /// this shape and entirely normal. So this says what was and was not seen,
    /// and leaves the decision with somebody who knows the business.
    /// </remarks>
    private static void NeverSigned(
        List<ZoneFinding> findings, ZoneEvidence evidence,
        string name, string selector, DkimKey? key, SelectorEvidence? live)
    {
        if (!evidence.ReportsRead || evidence.ReportWindowDays < MinimumDaysToJudgeASelector) { return; }
        if (live is null || live.SeenSigning) { return; }
        if (key is not { Usable: true }) { return; }

        findings.Add(new ZoneFinding
        {
            Severity = HygieneSeverity.Tidy,
            Record = "DKIM",
            Name = name,
            Problem = $"The selector {selector} publishes a usable key and no mail has been seen signing "
                    + $"with it in the {evidence.ReportWindowDays} days of reports held.",
            Fix = "Nothing on this alone. A staged key, a second selector a provider publishes as a pair, "
                + "and a service that sends quarterly all look like this. It is worth knowing which "
                + "service owns the selector; it is not worth deleting on this evidence.",
            Source = FindingSource.ZoneAndReports,
        });
    }

    private static void KeySizes(
        List<ZoneFinding> findings, ParsedZone zone, ZoneEvidence evidence,
        List<string> tooSmall, List<string> rotate)
    {
        // One finding for the lot rather than one each: it is a single fact
        // about the domain and a single piece of work, and repeating it per
        // selector reads as several unrelated problems.
        if (tooSmall.Count > 0)
        {
            findings.Add(new ZoneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "DKIM",
                Name = zone.Origin,
                Problem = $"{Join(tooSmall)} {(tooSmall.Count == 1 ? "is" : "are")} under 1024 bits. Large "
                        + "receivers have refused keys this short since 2018, so signatures made with "
                        + $"{(tooSmall.Count == 1 ? "it" : "them")} do not verify.",
                Fix = "Have the signing service issue a 2048-bit key and publish the new record before "
                    + "removing the old one.",
                Source = evidence.DnsRead ? FindingSource.Dns : FindingSource.Zone,
                Reference = "RFC 8301",
            });
        }

        if (rotate.Count > 0)
        {
            findings.Add(new ZoneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "DKIM",
                Name = zone.Origin,
                Problem = $"{Join(rotate)} {(rotate.Count == 1 ? "is" : "are")} 1024-bit. That still "
                        + "verifies everywhere; it is the size providers issued by default for years and "
                        + "is no longer what to publish.",
                Fix = "Ask each service to reissue at 2048 bits. It is a provider-side rotation rather than "
                    + "a DNS edit, and it can wait for the next time somebody is in that account.",
                Source = evidence.DnsRead ? FindingSource.Dns : FindingSource.Zone,
                Reference = "RFC 8301",
            });
        }
    }

    /// <summary>
    /// Selectors the reports have seen signing that the file does not carry.
    /// </summary>
    /// <remarks>
    /// The disagreement that runs the other way, and the one worth stating
    /// carefully: it is far more often a stale export than a missing record.
    /// A key added this morning is not in a file exported last week, and a
    /// subdomain's keys live in a zone this file is not.
    /// </remarks>
    private static void NotInTheZone(
        List<ZoneFinding> findings, ParsedZone zone, ZoneEvidence evidence, IReadOnlyList<string> inZone)
    {
        if (!evidence.ReportsRead) { return; }

        var missing = evidence.SeenSigning
            .Where(s => !inZone.Contains(s, StringComparer.OrdinalIgnoreCase))
            .ToList();

        if (missing.Count == 0) { return; }

        findings.Add(new ZoneFinding
        {
            Severity = HygieneSeverity.Tidy,
            Record = "DKIM",
            Name = zone.Origin,
            Problem = $"The reports show {Join(missing)} signing for this domain, and the file has no "
                    + $"record for {(missing.Count == 1 ? "it" : "them")}.",
            Fix = "Usually the export is simply older than the record. Worth confirming it was taken from "
                + "the provider that serves this zone, and after the key was added.",
            Source = FindingSource.ZoneAndReports,
        });
    }

    // ---- external reporting authorization -------------------------------------

    /// <summary>
    /// The records that let another domain send its DMARC reports here.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §7.1: a domain whose rua points at an address outside itself
    /// only gets reports if the receiving domain publishes a record saying so.
    /// Silently, if it does not - the receiver simply declines to send, and
    /// what an operator sees is a customer that never generates any reports at
    /// all. This checks the ones that are in the file; whether every domain
    /// has one is a question about the whole book rather than about this zone.
    /// </remarks>
    private static void ReportAuthorizations(List<ZoneFinding> findings, ParsedZone zone)
    {
        var marker = $"._report._dmarc.{zone.Origin}";

        foreach (var record in zone.Records)
        {
            if (record.Type != "TXT") { continue; }
            if (!record.Name.EndsWith(marker, StringComparison.OrdinalIgnoreCase)) { continue; }

            var authorized = record.Name[..^marker.Length];

            if (!IsDmarcVersion(record.Value, exact: true))
            {
                var casing = IsDmarcVersion(record.Value, exact: false);

                findings.Add(new ZoneFinding
                {
                    Severity = HygieneSeverity.Breaking,
                    Record = "DMARC",
                    Name = record.Name,
                    Line = record.Line,
                    Problem = casing
                        ? $"The record authorizing {authorized} to send its reports here is "
                          + $"\"{record.Value.Trim()}\". The version has to be DMARC1 in capitals - the "
                          + "standard spells it out character by character - so this does not authorize "
                          + "anything, and the reports are never sent."
                        : $"The record authorizing {authorized} to send its reports here is "
                          + $"\"{record.Value.Trim()}\", which is not a DMARC record, so it authorizes "
                          + "nothing and the reports are never sent.",
                    Fix = $"Publish \"v=DMARC1\" at {record.Name}.",
                    Source = FindingSource.Zone,
                    Reference = "RFC 7489 §7.1",
                });
            }

            // A name with no dot in it is not a domain anybody can send mail
            // as, so the record authorizes nothing that exists. It is the
            // shape a dropped suffix leaves behind - "mcleanelectric" where
            // "mcleanelectric.com" was meant - and it is invisible in a
            // provider's panel, where the zone's own name is added on the end
            // and the whole row reads as a sensible hostname.
            if (authorized.Length > 0 && !authorized.Contains('.', StringComparison.Ordinal))
            {
                findings.Add(new ZoneFinding
                {
                    Severity = HygieneSeverity.Breaking,
                    Record = "DMARC",
                    Name = record.Name,
                    Line = record.Line,
                    Problem = $"This authorizes reports for a domain called \"{authorized}\", which has no "
                            + "dot in it and so is not a domain anybody can receive mail for. Whatever "
                            + "domain was meant is not authorized, and no receiver will send its reports "
                            + "here.",
                    Fix = $"Republish it under the full domain name - \"{authorized}.com._report._dmarc\", "
                        + "or whichever suffix is right - and remove this one.",
                    Source = FindingSource.Zone,
                    Reference = "RFC 7489 §7.1",
                });
            }
        }
    }

    // ---- delegation ------------------------------------------------------------

    private static void Delegation(List<ZoneFinding> findings, ParsedZone zone, ZoneEvidence evidence)
    {
        var inZone = zone.At(zone.Origin, "NS")
            .Select(r => r.Target)
            .Where(t => t.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.Ordinal)
            .ToList();

        // Nothing to compare, either because the export leaves the apex NS out
        // or because the delegation could not be read. Both mean silence: a
        // finding about name servers that was not checked against the live
        // delegation is a guess, and acting on it moves a domain's DNS.
        if (inZone.Count == 0 || evidence.Delegation.Count == 0) { return; }

        var live = evidence.Delegation;
        var shared = inZone.Where(n => live.Contains(n, StringComparer.OrdinalIgnoreCase)).ToList();
        var stale = inZone.Where(n => !live.Contains(n, StringComparer.OrdinalIgnoreCase)).ToList();

        if (stale.Count == 0) { return; }

        if (shared.Count == 0)
        {
            findings.Add(new ZoneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "NS",
                Name = zone.Origin,
                Problem = $"The file lists {Join(inZone)} as this domain's name servers, and the domain is "
                        + $"delegated to {Join(live)} instead. None of them match, so this export is from a "
                        + "provider that is not the one answering for this domain - and everything above "
                        + "describes a zone nobody is serving.",
                Fix = "Export the zone from the provider the domain is actually delegated to, and run this "
                    + "again. Nothing above can be trusted until that is settled.",
                Source = FindingSource.ZoneAndDns,
                Reference = "RFC 1034 §4.2",
            });

            return;
        }

        findings.Add(new ZoneFinding
        {
            Severity = HygieneSeverity.Weakness,
            Record = "NS",
            Name = zone.Origin,
            Problem = $"The zone carries {Join(stale)} at the apex, and the domain is delegated to "
                    + $"{Join(live)}. The extra name server(s) do nothing while the delegation stands, "
                    + "and they are a trap: whoever inherits this zone reads them as where it is served "
                    + "from, and anything that reloads the zone authoritatively would act on them.",
            Fix = "Remove the name servers that are not part of the current delegation, once you have "
                + "confirmed nothing is mid-migration.",
            Source = FindingSource.ZoneAndDns,
            Reference = "RFC 1034 §4.2",
        });
    }

    // ---- structure --------------------------------------------------------------

    /// <summary>
    /// A CNAME cannot share a name with anything else.
    /// </summary>
    /// <remarks>
    /// RFC 1034 §3.6.2, and RFC 2181 §10.1 says it again in so many words. It
    /// is the one fault a zone file shows plainly and DNS hides: a resolver
    /// queried for one type returns one answer, so whichever record loses is
    /// simply never seen, and which one loses depends on the server.
    /// </remarks>
    private static void Cnames(List<ZoneFinding> findings, ParsedZone zone)
    {
        foreach (var group in zone.Records
                     .Where(r => r.Type is not ("RRSIG" or "NSEC" or "NSEC3"))
                     .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
        {
            var cname = group.FirstOrDefault(r => r.Type == "CNAME");
            if (cname is null) { continue; }

            var others = group.Where(r => r.Type != "CNAME").Select(r => r.Type)
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();

            if (others.Count == 0) { continue; }

            findings.Add(new ZoneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "zone",
                Name = group.Key,
                Line = cname.Line,
                Problem = $"{group.Key} has a CNAME and also {Join(others)}. A name with a CNAME on it may "
                        + "have nothing else, and which record a resolver returns is up to the server - so "
                        + "one of these is invisible, and which one can change.",
                Fix = "Keep the CNAME or the other record(s), not both. Where a service needs a CNAME at a "
                    + "name that must also carry something else, it usually offers an A record instead.",
                Source = FindingSource.Zone,
                Reference = "RFC 1034 §3.6.2; RFC 2181 §10.1",
            });
        }
    }

    /// <summary>
    /// Where the file and DNS say different things about the same record.
    /// </summary>
    /// <remarks>
    /// Not a fault in itself - an export is a snapshot and DNS moves - but the
    /// thing an operator most needs told before acting on either. Somebody
    /// reading findings off a file exported a month ago is looking at a zone
    /// that no longer exists.
    /// </remarks>
    private static void Disagreements(List<ZoneFinding> findings, ParsedZone zone, ZoneEvidence evidence)
    {
        if (!evidence.DnsRead) { return; }

        var live = evidence.Live!;

        Differs(findings, zone, "SPF", zone.Origin,
            zone.At(zone.Origin, "TXT").FirstOrDefault(r => IsSpf(r.Value)),
            live.SpfRecords.Count > 0 ? live.SpfRecords[0] : null);

        Differs(findings, zone, "DMARC", $"_dmarc.{zone.Origin}",
            zone.At($"_dmarc.{zone.Origin}", "TXT")
                .FirstOrDefault(r => IsDmarcVersion(r.Value, exact: false)),
            live.DmarcRecord);
    }

    private static void Differs(
        List<ZoneFinding> findings, ParsedZone zone, string kind, string name,
        ZoneRecord? inZone, string? live)
    {
        if (inZone is null || string.IsNullOrWhiteSpace(live)) { return; }
        if (Same(inZone.Value, live)) { return; }

        findings.Add(new ZoneFinding
        {
            Severity = HygieneSeverity.Tidy,
            Record = kind,
            Name = name,
            Line = inZone.Line,
            Problem = $"The file and live DNS hold different {kind} records for {zone.Origin}. "
                    + $"The file: \"{inZone.Value.Trim()}\". DNS right now: \"{live.Trim()}\".",
            Fix = "DNS is what receivers act on. If the file is the newer of the two, the change has not "
                + "been published; if DNS is, the export is stale and anything read off it about this "
                + "record is out of date.",
            Source = FindingSource.ZoneAndDns,
        });
    }

    // ---- helpers ------------------------------------------------------------------

    private static bool IsSpf(string value) =>
        value.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when a TXT record is plainly meant to be an SPF record but is not one.
    /// </summary>
    /// <remarks>
    /// Deliberately narrow. A wrong answer here tells somebody to put v=spf1
    /// in front of a record belonging to something else, which would break
    /// whatever that was for and add a second SPF record at the same time. A
    /// record that already declares itself with any v= tag is left alone, and
    /// what remains has to carry a mechanism no other kind of record uses.
    /// </remarks>
    private static bool LooksLikeSpf(string value)
    {
        var text = value.Trim();

        if (text.Length == 0) { return false; }
        if (text.StartsWith("v=", StringComparison.OrdinalIgnoreCase)) { return false; }

        if (text.Contains("include:", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ip4:", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ip6:", StringComparison.OrdinalIgnoreCase)
            || text.Contains("redirect=", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return text.EndsWith("-all", StringComparison.OrdinalIgnoreCase)
            || text.EndsWith("~all", StringComparison.OrdinalIgnoreCase)
            || text.EndsWith("?all", StringComparison.OrdinalIgnoreCase)
            || text.EndsWith("+all", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Whether a record opens with the DMARC version tag.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.4 writes the version as the six characters D M A R C 1
    /// rather than as a quoted string, which in ABNF means it is case
    /// sensitive - so <c>v=dmarc1</c> is not a DMARC record, while <c>V=</c>
    /// is fine, because tag names are quoted and quoted strings are not. The
    /// difference decides whether reports arrive, and it is invisible.
    /// </remarks>
    internal static bool IsDmarcVersion(string? value, bool exact)
    {
        var text = (value ?? string.Empty).TrimStart();

        if (text.Length == 0 || (text[0] != 'v' && text[0] != 'V')) { return false; }

        var at = 1;
        while (at < text.Length && char.IsWhiteSpace(text[at])) { at++; }
        if (at >= text.Length || text[at] != '=') { return false; }

        at++;
        while (at < text.Length && char.IsWhiteSpace(text[at])) { at++; }
        if (at + 6 > text.Length) { return false; }

        var version = text.Substring(at, 6);
        var matches = exact
            ? version.Equals("DMARC1", StringComparison.Ordinal)
            : version.Equals("DMARC1", StringComparison.OrdinalIgnoreCase);

        if (!matches) { return false; }

        var after = at + 6;
        return after == text.Length || text[after] == ';' || char.IsWhiteSpace(text[after]);
    }

    /// <summary>Two records that differ only in spacing are the same record.</summary>
    private static bool Same(string a, string b) =>
        string.Equals(Collapse(a), Collapse(b), StringComparison.OrdinalIgnoreCase);

    private static string Collapse(string value) =>
        string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    /// <summary>A readable list: "a", "a and b", "a, b and c".</summary>
    private static string Join(IReadOnlyList<string> items) => items.Count switch
    {
        0 => "",
        1 => items[0],
        2 => $"{items[0]} and {items[1]}",
        _ => $"{string.Join(", ", items.Take(items.Count - 1))} and {items[^1]}",
    };
}
