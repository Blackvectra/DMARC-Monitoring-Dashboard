using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Storage;

/// <summary>What is known about one organization's collection.</summary>
/// <param name="Organization">Its slug, or "" when the install has only the default one.</param>
/// <param name="Domains">Active domains it holds.</param>
/// <param name="LastStored">When a report was last written for it, or null if never.</param>
/// <param name="StoredLastDay">Reports written for it in the last 24 hours.</param>
public sealed record CollectionFacts(
    string Organization, int Domains, DateTimeOffset? LastStored, int StoredLastDay);

/// <summary>An organization's webhook, as far as the health check needs it.</summary>
/// <param name="Organization">Its slug.</param>
/// <param name="Destination">Scheme and host, never the full address.</param>
/// <param name="CreatedAt">When it was set up.</param>
/// <param name="LastDelivered">When something last arrived there, or null if nothing ever has.</param>
/// <param name="LastFailed">When a delivery last failed, or null if none ever has.</param>
/// <param name="LastError">What the last failure said.</param>
public sealed record WebhookFacts(
    string Organization, string Destination, DateTimeOffset CreatedAt,
    DateTimeOffset? LastDelivered, DateTimeOffset? LastFailed, string? LastError);

/// <summary>One engine's health, as the findings registry computes it.</summary>
/// <param name="Organization">Its slug.</param>
/// <param name="Client">The client's slug for an engine that runs per client; null for the organization's own.</param>
/// <param name="Kind">The engine: dns-scan, reports, remediation.</param>
/// <param name="Health">One of <see cref="DmarcMonitor.Core.Findings.SourceHealth"/>.</param>
public sealed record SourceFacts(
    string Organization, string? Client, string Kind, string Health, DateTimeOffset? LastSuccess, string? LastError);

/// <summary>An organization's critical findings still open and wanting a person.</summary>
/// <param name="Domains">Up to five of the domains concerned, oldest finding first.</param>
public sealed record CriticalFacts(string Organization, int Count, IReadOnlyList<string> Domains);

/// <summary>A domain that used to have reports arriving and now does not.</summary>
/// <param name="Domain">The name.</param>
/// <param name="LastReport">When its newest report covered, or null if none ever.</param>
/// <param name="ReportsHeld">How many are held for it in total.</param>
public sealed record QuietDomain(string Domain, DateTimeOffset? LastReport, int ReportsHeld);

/// <summary>Everything the health check looks at.</summary>
/// <remarks>
/// Separated from the judging so the rules can be tested without a database, a
/// filesystem or a clock - the same split <see cref="ReportReachability"/>
/// uses, and for the same reason: every one of these findings tells an
/// operator something is broken, and a wrong one sends them looking for a
/// fault that is not there.
/// </remarks>
public sealed record HealthFacts
{
    /// <summary>One entry per organization that holds domains.</summary>
    public IReadOnlyList<CollectionFacts> Collection { get; init; } = [];

    /// <summary>Domains with history that have gone silent.</summary>
    public IReadOnlyList<QuietDomain> Quiet { get; init; } = [];

    /// <summary>When the newest backup was taken, or null if none was found.</summary>
    public DateTimeOffset? LastBackup { get; init; }

    /// <summary>Where backups were looked for, or null when nobody said.</summary>
    public string? BackupDirectory { get; init; }

    /// <summary>Domain names held by more than one organization, which is usually a typo.</summary>
    public IReadOnlyList<string> HeldTwice { get; init; } = [];

    /// <summary>Every organization's webhook, working or not.</summary>
    public IReadOnlyList<WebhookFacts> Webhooks { get; init; } = [];

    /// <summary>Every engine that has recorded a run, with its health now.</summary>
    public IReadOnlyList<SourceFacts> Sources { get; init; } = [];

    /// <summary>Per organization, the critical findings open and wanting a person.</summary>
    public IReadOnlyList<CriticalFacts> Critical { get; init; } = [];
}

/// <summary>
/// Whether this install is still doing its job.
///
/// Everything here fails silently, which is why it needs asking rather than
/// watching. A collector whose certificate expired stops storing reports and
/// says nothing; the pages go on showing last week's figures, and last week's
/// figures look fine. A customer whose DMARC record was edited stops being
/// reported on at all, and an empty chart reads as "no problems" rather than
/// "no data".
///
/// The signal is deliberately what was STORED rather than whether a process
/// ran. A collector that runs perfectly every hour against a mailbox nothing
/// is delivered to is a failure, and a run-history table would call it a
/// success every time.
/// </summary>
public static class HealthCheck
{
    /// <summary>How long without a stored report before collection is treated as stopped.</summary>
    /// <remarks>
    /// Receivers send at most once a day per domain, most of them overnight,
    /// so a few quiet hours is ordinary and a quiet day is not. Thirty-six
    /// hours clears a full daily cycle plus a late sender, which keeps this
    /// off an operator's back on an ordinary Monday morning.
    /// </remarks>
    public const int StoppedAfterHours = 36;

    /// <summary>How long a domain must be silent before it is worth naming.</summary>
    /// <remarks>
    /// Longer than the collection window on purpose. One domain going quiet
    /// for a day happens - a small domain sends no mail over a weekend, and
    /// receivers report nothing when there is nothing to report. Seven days is
    /// where "quiet" stops being a plausible week and starts being a fault.
    /// </remarks>
    public const int QuietAfterDays = 7;

    /// <summary>How stale the newest backup may be before it is worth saying.</summary>
    public const int BackupStaleAfterHours = 48;

    /// <summary>How old the newest backup has to be before backups have STOPPED.</summary>
    /// <remarks>
    /// The same two-threshold shape as collection above, and for the same
    /// reason. One missed night is a late job - a slow disk, a machine that
    /// was off - and paging somebody for it is how a check gets muted. Seven
    /// consecutive missed nights is not lateness, it is a timer that is not
    /// running, and the difference has to be visible in the exit code because
    /// that is what <c>OnFailure=</c> hangs off.
    ///
    /// Without this there was a hole exactly where it hurt most. "No backups
    /// at all" was Breaking, so it alerted - but <c>install.sh</c> now takes
    /// the first copy during the install, which makes that branch unreachable
    /// on a real machine. The only backup failure a running install can
    /// develop is the timer stopping and the copies ageing out, and that was
    /// a Weakness: printed, exit 0, unit successful, nobody told. The one
    /// case left was the one nothing covered.
    /// </remarks>
    public const int BackupStoppedAfterDays = 7;

    /// <summary>
    /// The findings, worst first.
    /// </summary>
    public static IReadOnlyList<HygieneFinding> Assess(HealthFacts facts, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(facts);

        var findings = new List<HygieneFinding>();

        Collection(findings, facts, now);
        Quiet(findings, facts, now);
        Backups(findings, facts, now);
        Duplicates(findings, facts);
        Webhooks(findings, facts, now);
        Engines(findings, facts);
        Critical(findings, facts);

        return [.. findings.OrderByDescending(f => f.Severity)];
    }

    /// <summary>
    /// The engines, from what each recorded of its own runs.
    /// </summary>
    /// <remarks>
    /// The stored-data checks above notice a collector that runs against an
    /// empty mailbox; this notices one that does not run at all, or fails,
    /// hours before those do. An engine that failed its last run is broken
    /// now: nothing it watches is being observed, and what it had found is
    /// marked unknown rather than resolved. One that has never recorded a
    /// success is not broken, but its silence means nothing yet, and that is
    /// said rather than shown as health.
    /// </remarks>
    private static void Engines(List<HygieneFinding> findings, HealthFacts facts)
    {
        foreach (var engine in facts.Sources)
        {
            var what = $"The {engine.Kind} engine for {engine.Organization}{(engine.Client is null ? "" : $" ({engine.Client})")}";
            var fix = engine.Kind switch
            {
                "reports" => "Check the collector ran and what it said: `systemctl list-timers 'dmarc-ingest*'` and "
                           + "`journalctl -u 'dmarc-ingest*' -n 50`. By hand: `dmarc ingest` or `dmarc import`.",
                "dns-scan" => "Check the scan ran: `systemctl list-timers dmarc-dns.timer` and `journalctl -u dmarc-dns -n 50`. "
                            + "By hand: `dmarc check --all --save`.",
                _ => "Check the unit that runs it: `journalctl -u dmarc-dns -n 50`. By hand: `dmarc findings observe`.",
            };

            switch (engine.Health)
            {
                case DmarcMonitor.Core.Findings.SourceHealth.Failed:
                    findings.Add(new HygieneFinding
                    {
                        Severity = HygieneSeverity.Breaking,
                        Record = "engine",
                        Problem = $"{what} failed its last run: {engine.LastError}. Until it runs again nothing it watches is "
                                + "being observed, and what it had found is marked unknown rather than resolved.",
                        Fix = fix,
                    });
                    break;

                case DmarcMonitor.Core.Findings.SourceHealth.Stale:
                    findings.Add(new HygieneFinding
                    {
                        Severity = HygieneSeverity.Weakness,
                        Record = "engine",
                        Problem = $"{what} has not run within its expected window"
                                + (engine.LastSuccess is { } ok ? $"; it last succeeded {Describe(DateTimeOffset.UtcNow - ok)} ago." : ".")
                                + " Nothing it watches has been observed since.",
                        Fix = fix,
                    });
                    break;

                case DmarcMonitor.Core.Findings.SourceHealth.Degraded:
                    findings.Add(new HygieneFinding
                    {
                        Severity = HygieneSeverity.Weakness,
                        Record = "engine",
                        Problem = $"{what} failed its last run ({engine.LastError}), though one within its window succeeded.",
                        Fix = fix,
                    });
                    break;

                case DmarcMonitor.Core.Findings.SourceHealth.Unknown:
                    findings.Add(new HygieneFinding
                    {
                        Severity = HygieneSeverity.Tidy,
                        Record = "engine",
                        Problem = $"{what} has never recorded a successful run, so its silence means nothing yet.",
                        Fix = fix,
                    });
                    break;
            }
        }
    }

    /// <summary>
    /// Critical findings open and wanting a person: a check, not an alert.
    /// The alert is the destination the findings are sent to; this is for
    /// the install with none, so they are at least printed somewhere.
    /// </summary>
    private static void Critical(List<HygieneFinding> findings, HealthFacts facts)
    {
        foreach (var org in facts.Critical)
        {
            if (org.Count == 0) { continue; }
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Weakness,
                Record = "findings",
                Problem = $"{Plural(org.Count, "critical finding")} open for {org.Organization} that nobody has closed, called benign or excepted: "
                        + string.Join(", ", org.Domains) + (org.Count > org.Domains.Count ? $", and {org.Count - org.Domains.Count} more" : "") + ".",
                Fix = $"Open Operations in the dashboard, or: `dmarc findings list --org {org.Organization}`.",
            });
        }
    }

    /// <summary>
    /// Collection, per organization.
    /// </summary>
    /// <remarks>
    /// Per organization rather than across the install, because that is the
    /// shape of the failure worth catching. An MSP running two collectors has
    /// two things that can break independently, and one still working keeps
    /// the install-wide figure looking healthy while a whole customer book
    /// goes dark.
    /// </remarks>
    private static void Collection(List<HygieneFinding> findings, HealthFacts facts, DateTimeOffset now)
    {
        foreach (var org in facts.Collection)
        {
            var name = string.IsNullOrWhiteSpace(org.Organization) ? "this install" : org.Organization;

            // A domain nobody has ever collected for is onboarding, not a
            // fault: something has to arrive before there is anything to
            // notice stopping. `dmarc reachability` is the command that
            // answers why nothing ever has.
            if (org.LastStored is null)
            {
                if (org.Domains > 0)
                {
                    findings.Add(new HygieneFinding
                    {
                        Severity = HygieneSeverity.Weakness,
                        Record = "collection",
                        Problem = $"{name} holds {Plural(org.Domains, "domain")} and no report has ever been "
                                + "stored for any of them.",
                        Fix = "Run `dmarc reachability` - either the reports are going somewhere this does "
                            + "not collect, or the collector for this organization has never worked.",
                    });
                }

                continue;
            }

            var silent = now - org.LastStored.Value;
            if (silent.TotalHours < StoppedAfterHours) { continue; }

            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "collection",
                Problem = $"Nothing has been stored for {name} in {Describe(silent)}. Receivers send at "
                        + "least daily, so this is the collector rather than a quiet week - and every "
                        + "screen goes on showing the figures from before it stopped.",
                Fix = "Check the collector ran and what it said: on Linux, "
                    + "`systemctl list-timers 'dmarc-ingest*'` and `journalctl -u 'dmarc-ingest*' -n 50`. "
                    + "An expired certificate and a revoked application permission both look exactly "
                    + "like this.",
            });
        }
    }

    private static void Quiet(List<HygieneFinding> findings, HealthFacts facts, DateTimeOffset now)
    {
        // Only worth raising when collection itself is BROKEN. If nothing is
        // being stored at all, every domain is quiet and saying so seventeen
        // times buries the one finding that matters.
        //
        // Severity, not just Record. Matching any collection finding also
        // matched the Weakness raised for an organization that has never
        // collected - so adding one new organization silenced every
        // quiet-domain finding for the organizations that WERE working, which
        // is the opposite of what this guard is for.
        if (findings.Exists(f => f.Record == "collection" && f.Severity >= HygieneSeverity.Breaking))
        {
            return;
        }
        if (facts.Quiet.Count == 0) { return; }

        var named = facts.Quiet.Take(5).Select(q => q.Domain).ToList();
        var rest = facts.Quiet.Count - named.Count;

        findings.Add(new HygieneFinding
        {
            Severity = HygieneSeverity.Weakness,
            Record = "reporting",
            Problem = $"{Plural(facts.Quiet.Count, "domain")} stopped being reported on more than "
                    + $"{QuietAfterDays} days ago while others kept arriving: "
                    + string.Join(", ", named) + (rest > 0 ? $", and {rest} more" : "") + ". "
                    + "An empty chart reads as no problems rather than no data.",
            Fix = "Check each one's DMARC record still publishes a rua that points here - "
                + "`dmarc reachability --domain <d>`. A record edited by somebody else is the usual cause.",
        });
    }

    private static void Backups(List<HygieneFinding> findings, HealthFacts facts, DateTimeOffset now)
    {
        // Nobody said where to look, so nothing can be concluded. Silence here
        // is not "no backups exist" - it is a question that was not asked, and
        // reporting it as a fault would be a sentence about something nobody
        // established.
        if (facts.BackupDirectory is null) { return; }

        if (facts.LastBackup is null)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "backup",
                Problem = $"There are no backups in {facts.BackupDirectory}. Nothing else here protects the "
                        + "reports: update and rollback roll the binary back, not the data.",
                Fix = "Run `dmarc backup --to <dir>` and enable the nightly timer: "
                    + "`sudo systemctl enable --now dmarc-backup.timer`.",
            });

            return;
        }

        var age = now - facts.LastBackup.Value;
        if (age.TotalHours < BackupStaleAfterHours) { return; }

        // Past a week the nightly timer has missed seven runs, which is not a
        // late job. Breaking, so the unit fails and the alert carries it.
        if (age.TotalDays >= BackupStoppedAfterDays)
        {
            findings.Add(new HygieneFinding
            {
                Severity = HygieneSeverity.Breaking,
                Record = "backup",
                Problem = $"Backups have stopped. The newest in {facts.BackupDirectory} is {Describe(age)} "
                        + "old and the timer is meant to take one nightly, so it has missed every run "
                        + "since. Nothing else here protects the reports.",
                Fix = "Check the timer and why the last runs failed: "
                    + "`systemctl list-timers dmarc-backup.timer` and `journalctl -u dmarc-backup -n 50`. "
                    + "A full disk is the usual cause. Take one now with "
                    + "`sudo systemctl start dmarc-backup`.",
            });

            return;
        }

        findings.Add(new HygieneFinding
        {
            Severity = HygieneSeverity.Weakness,
            Record = "backup",
            Problem = $"The newest backup in {facts.BackupDirectory} is {Describe(age)} old, and the timer "
                    + "is meant to take one nightly.",
            Fix = "Check it ran: `systemctl list-timers dmarc-backup.timer` and "
                + "`journalctl -u dmarc-backup -n 30`. A full disk is the usual cause.",
        });
    }

    private static void Duplicates(List<HygieneFinding> findings, HealthFacts facts)
    {
        if (facts.HeldTwice.Count == 0) { return; }

        findings.Add(new HygieneFinding
        {
            Severity = HygieneSeverity.Weakness,
            Record = "collection",
            Problem = $"{Plural(facts.HeldTwice.Count, "domain name")} held by more than one organization: "
                    + string.Join(", ", facts.HeldTwice.Take(5))
                    + ". Two MSPs each looking after the same name is legitimate; a collector running "
                    + "under the wrong --org looks identical, and leaves one copy quietly not growing.",
            Fix = "Check both are meant to exist. If one came from a mistyped --org, correct the "
                + "collector's DMARC_ORGANIZATION or it will happen again tonight.",
        });
    }

    /// <summary>
    /// A webhook that has stopped delivering.
    /// </summary>
    /// <remarks>
    /// The two thresholds the backups have, for the same reason. One failed
    /// night is a receiver that was restarting at the wrong moment, and the
    /// next scan will send what waited. A day and a half with nothing
    /// delivered is not that: the findings are piling up where nobody reads
    /// them, which is the silence the webhook exists to end - so it has to
    /// reach the exit code, which is what OnFailure= hangs off.
    /// </remarks>
    private static void Webhooks(List<HygieneFinding> findings, HealthFacts facts, DateTimeOffset now)
    {
        foreach (var hook in facts.Webhooks)
        {
            var failing = hook.LastFailed is { } failed && (hook.LastDelivered is not { } ok || failed > ok);
            if (!failing) { continue; }

            var since = now - (hook.LastDelivered ?? hook.CreatedAt);
            var stopped = since.TotalHours >= StoppedAfterHours;
            findings.Add(new HygieneFinding
            {
                Severity = stopped ? HygieneSeverity.Breaking : HygieneSeverity.Weakness,
                Record = "webhook",
                Problem = stopped
                    ? $"Nothing has reached {hook.Destination} for {hook.Organization} in {Describe(since)}, "
                      + $"so its DNS changes are being found and not sent. It said: {hook.LastError}"
                    : $"The last delivery to {hook.Destination} for {hook.Organization} failed: {hook.LastError?.TrimEnd('.')}. "
                      + "What was not sent waits for the next run.",
                Fix = $"Check the receiver, then `dmarc notify test --org {hook.Organization}`; "
                    + $"once it answers, `dmarc notify send --org {hook.Organization}` sends what waited.",
            });
        }
    }

    /// <summary>A duration an operator reads rather than a TimeSpan.</summary>
    private static string Describe(TimeSpan since) => since.TotalDays switch
    {
        >= 2 => $"{(int)since.TotalDays} days",
        >= 1 => "a day",
        _ => $"{(int)since.TotalHours} hours",
    };

    private static string Plural(int count, string noun) =>
        count == 1 ? $"1 {noun}" : $"{count} {noun}s";
}
