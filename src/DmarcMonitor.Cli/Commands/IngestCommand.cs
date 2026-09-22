using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using DmarcMonitor.Core.Graph;
using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Reads the reporting mailbox and stores what arrives.
///
/// The one command that needs a tenant, so it validates its configuration
/// before touching anything: a run that gets halfway and then fails on a
/// missing flag has already moved mail around.
/// </summary>
public static class IngestCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        if (Args.Reject(args, "--db", "--mailbox", "--tenant", "--client-id", "--cert", "--cert-password", "--max", "--fallback", "--reporting-domain", "--org", "--delete", "!--dry-run") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var mailbox = Args.Value(args, "--mailbox");
        var tenantId = Args.Value(args, "--tenant") ?? Environment.GetEnvironmentVariable("DMARC_TENANT_ID");
        var clientId = Args.Value(args, "--client-id") ?? Environment.GetEnvironmentVariable("DMARC_CLIENT_ID");
        var certPath = Args.Value(args, "--cert") ?? Environment.GetEnvironmentVariable("DMARC_CERT_PATH");
        var certPassword = Args.Value(args, "--cert-password") ?? Environment.GetEnvironmentVariable("DMARC_CERT_PASSWORD");
        // An environment file with the line "DMARC_FALLBACK_ADDRESS=" is the
        // template every install ships with, and it means "not set", not "the
        // empty address" - which is what ?? alone made of it.
        var reportingDomain = NonBlank(Args.Value(args, "--reporting-domain")) ?? NonBlank(Environment.GetEnvironmentVariable("DMARC_REPORTING_DOMAIN")) ?? "";
        var fallback = NonBlank(Args.Value(args, "--fallback")) ?? NonBlank(Environment.GetEnvironmentVariable("DMARC_FALLBACK_ADDRESS"));
        var maxMessages = Args.Int(args, "--max", 500);
        var dryRun = Args.Flag(args, "--dry-run");

        // Spelled out rather than a bare flag. This throws a customer's mail
        // away, the two modes differ in whether the space actually comes back,
        // and neither is something to arrive at by typing four characters.
        //
        // Also from the environment, because the scheduled run is the one that
        // matters here: the unit's ExecStart is fixed, and a collector that
        // could only be told to delete by hand would never be the one keeping
        // the mailbox down.
        if (!TryReadDeleteMode(
                NonBlank(Args.Value(args, "--delete")) ?? NonBlank(Environment.GetEnvironmentVariable("DMARC_DELETE")),
                out var deleteMode))
        {
            return 64;
        }

        // Which organization a domain nobody has seen before belongs to. One
        // collector per organization's mailbox is the expected shape; a domain
        // already known keeps its own organization whatever this says.
        // DMARC_ORGANISATION is still read. An environment file written by an
        // earlier bootstrap carries that spelling, and a collector that
        // quietly filed a customer's domains under the wrong organization
        // because of a renamed variable is not a trade worth making.
        var organization = NonBlank(Args.Value(args, "--org"))
            ?? NonBlank(Environment.GetEnvironmentVariable("DMARC_ORGANIZATION"))
            ?? NonBlank(Environment.GetEnvironmentVariable("DMARC_ORGANISATION"))
            ?? ReportStore.DefaultTenantSlug;

        // Everything missing is reported at once. Being told about one missing
        // flag at a time, each after a failed run, is its own small misery.
        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(mailbox)) { missing.Add("--mailbox (the shared mailbox receiving reports)"); }
        if (string.IsNullOrWhiteSpace(tenantId)) { missing.Add("--tenant (Entra tenant id, or DMARC_TENANT_ID)"); }
        if (string.IsNullOrWhiteSpace(clientId)) { missing.Add("--client-id (app registration id, or DMARC_CLIENT_ID)"); }
        if (string.IsNullOrWhiteSpace(certPath)) { missing.Add("--cert (path to the .pfx, or DMARC_CERT_PATH)"); }

        if (missing.Count > 0)
        {
            Console.Error.WriteLine("Missing configuration:");
            foreach (var m in missing) { Console.Error.WriteLine($"  {m}"); }
            Console.Error.WriteLine();
            Console.Error.WriteLine("These come from the app registration the installer created.");
            return 64;
        }

        if (!File.Exists(certPath))
        {
            Console.Error.WriteLine($"Certificate not found: {certPath}");
            return 66;
        }

        // Without a reporting domain or a shared address nothing can be
        // attributed and every report would be filed as unrecognized. The
        // commonest shape by far is one shared mailbox that every domain
        // reports to - which is the mailbox being read - so that is the
        // default, said out loud below. It used to be an error instead, which
        // made the systemd unit and the documented command exit 64 on every
        // machine that followed the docs.
        var attributedBy = string.IsNullOrWhiteSpace(reportingDomain)
            ? $"the shared address {fallback ?? mailbox} (set --reporting-domain or DMARC_REPORTING_DOMAIN if per-domain addresses are in use)"
            : $"per-domain addresses under {reportingDomain}{(fallback is null ? "" : $", falling back to {fallback}")}";
        fallback ??= string.IsNullOrWhiteSpace(reportingDomain) ? mailbox : null;

        var store = new ReportStore(dbPath, organization);
        if (!dryRun && !await store.IsInitializedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
            return 69;   // EX_UNAVAILABLE
        }

        // Before the mailbox is opened, not after: a collector that reads a
        // hundred messages and then cannot store any of them has moved or
        // deleted them from the mailbox for nothing.
        if (!dryRun && !await SchemaGuard.IsCurrentAsync(dbPath, ct).ConfigureAwait(false))
        {
            return 69;   // EX_UNAVAILABLE
        }

        X509Certificate2 certificate;
        try
        {
            certificate = string.IsNullOrEmpty(certPassword)
                ? new X509Certificate2(certPath!)
                : new X509Certificate2(certPath!, certPassword);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"Could not load the certificate: {ex.Message}");
            Console.Error.WriteLine("If it has a password, pass --cert-password or set DMARC_CERT_PASSWORD.");
            return 77;
        }

        using (certificate)
        {
            if (!certificate.HasPrivateKey)
            {
                // A .cer rather than a .pfx. This fails later as a confusing
                // auth error, so it is caught here where the cause is obvious.
                Console.Error.WriteLine("That certificate has no private key, so it cannot be used to authenticate.");
                Console.Error.WriteLine("You need the .pfx, not the .cer that was uploaded to Entra.");
                return 77;
            }

            if (certificate.NotAfter < DateTime.Now)
            {
                Console.Error.WriteLine($"The certificate expired on {certificate.NotAfter:d}. Renew it and upload the new one to the app registration.");
                return 77;
            }

            var credential = new ClientCertificateCredential(tenantId, clientId, certificate);

            var handler = new GraphThrottleHandler { InnerHandler = new HttpClientHandler() };
            using var http = new HttpClient(new BearerTokenHandler(credential) { InnerHandler = handler })
            {
                Timeout = TimeSpan.FromMinutes(5),
            };

            var mailboxClient = new GraphMailboxClient(http, mailbox!);

            var options = new IngestOptions
            {
                ReportingDomain = reportingDomain,
                FallbackAddress = fallback,
                MaxMessages = maxMessages,
                DeleteProcessed = deleteMode,
            };

            // Dry run reads and parses but writes nothing and moves nothing, so
            // the first run against a real mailbox can be inspected before it
            // changes anything.
            // Counted here rather than after the run, because the storing now
            // happens inside it: a message is only filed once its reports are
            // safely in the database.
            var stored = 0;

            var ingestor = dryRun
                ? new ReportIngestor(new ReadOnlyMailbox(mailboxClient), options, ResolveToken, _ => false)
                : new ReportIngestor(mailboxClient, options, ResolveToken,
                    key => IsStored(store, key, ct).GetAwaiter().GetResult(),
                    async (found, token) =>
                    {
                        var (wrote, failed) = await StoreAsync(store, found, token).ConfigureAwait(false);
                        stored += wrote;

                        // False leaves the message in the source folder. A
                        // message read twice is caught by the duplicate check;
                        // a message filed and never stored is gone.
                        return failed == 0;
                    });

            Console.WriteLine($"Reading {mailbox}{(dryRun ? " (dry run: nothing will be written or moved)" : "")}");
            Console.WriteLine($"Attributing reports by {attributedBy}");
            if (deleteMode != DeleteProcessed.Keep && !dryRun)
            {
                Console.WriteLine(deleteMode == DeleteProcessed.Permanent
                    ? "Stored reports will be deleted from the mailbox (recoverable from Recoverable Items only)"
                    : "Stored reports will be moved to Deleted Items");
            }
            if (organization != ReportStore.DefaultTenantSlug)
            {
                Console.WriteLine($"Filing new domains under the organization '{organization}'");
            }
            Console.WriteLine();

            IngestRunResult result;
            try
            {
                result = await ingestor.RunAsync(ct).ConfigureAwait(false);
            }
            catch (GraphException ex)
            {
                // Already a sentence naming a likely cause.
                Console.Error.WriteLine(ex.Message);
                return 69;
            }
            catch (AuthenticationFailedException ex)
            {
                Console.Error.WriteLine("Could not authenticate to Microsoft Entra.");
                Console.Error.WriteLine($"  {ex.Message}");
                Console.Error.WriteLine();
                Console.Error.WriteLine("Check the tenant id, the application id, and that this certificate is the one");
                Console.Error.WriteLine("uploaded to that app registration.");
                return 77;
            }

            Report(result, stored, dryRun);
            if (!dryRun) { await WarnUnassignedAsync(store, ct).ConfigureAwait(false); }

            // Genuine reports and not one of them addressed to anything this
            // deployment recognizes means the shared address is wrong, not
            // the mail. The messages were left in place, so this is the exit
            // code that says "configure it and run again", not "data lost".
            if (result.UnattributedCount > 0 && result.IngestedCount == 0 && result.DuplicateCount == 0)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine($"No report was addressed to {fallback ?? "a recognized address"}. They were sent to:");
                foreach (var a in result.UnattributedAddresses.Take(5)) { Console.Error.WriteLine($"  {a}"); }
                Console.Error.WriteLine("Set --fallback (or DMARC_FALLBACK_ADDRESS) to the address in the domains' rua= tag,");
                Console.Error.WriteLine("or --reporting-domain if per-domain addresses are in use. Nothing was moved.");
                return 64;
            }

            return result.Errors.Count > 0 ? 1 : 0;
        }

        // Per-domain addressing is not wired to storage yet, so no token
        // resolves and attribution falls back to the shared address. Returning
        // null is honest about that; inventing a domain would file reports
        // against the wrong customer.
        static string? ResolveToken(string token) => null;

        static string? NonBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static async Task<bool> IsStored(ReportStore store, string key, CancellationToken ct)
    {
        // key is "kind|domain|org|reportId", built by the ingestor.
        var parts = key.Split('|');
        if (parts.Length != 4) { return false; }

        return parts[0] switch
        {
            "dmarc" => await store.IsAggregateStoredAsync(parts[2], parts[3], parts[1], ct).ConfigureAwait(false),
            "tls" => await store.IsTlsStoredAsync(parts[2], parts[3], parts[1], ct).ConfigureAwait(false),
            _ => false,
        };
    }

    /// <summary>
    /// Writes one message's reports, and says how many did not make it.
    /// </summary>
    /// <remarks>
    /// Called from inside the run, before the message is filed. A report that
    /// cannot be stored leaves its message in the source folder so the next
    /// run tries again, which is why the failure count matters rather than
    /// just being printed.
    /// </remarks>
    private static async Task<(int Written, int Failed)> StoreAsync(
        ReportStore store, IReadOnlyList<IngestedReport> found, CancellationToken ct)
    {
        var written = 0;
        var failed = 0;

        foreach (var report in found.Where(r => r.Outcome == IngestOutcome.Ingested))
        {
            try
            {
                var id = report.Kind switch
                {
                    ReportKind.DmarcAggregate when report.Aggregate is not null =>
                        await store.SaveAggregateAsync(report.Aggregate, report.FileName, report.MessageId, report.ArrivedAt, ct).ConfigureAwait(false),
                    ReportKind.TlsRpt when report.Tls is not null =>
                        await store.SaveTlsAsync(report.Tls, report.FileName, report.MessageId, report.ArrivedAt, ct).ConfigureAwait(false),
                    _ => null,
                };

                if (id is not null) { written++; } else { failed++; }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Could not store {report.FileName} for {report.Domain}: {ex.Message}");
                failed++;
            }
        }

        return (written, failed);
    }

    /// <summary>
    /// Reads --delete, which must name which kind of delete is meant.
    /// </summary>
    /// <remarks>
    /// The difference is not cosmetic. A soft delete empties the inbox and
    /// gives no quota back, because Deleted Items is the same mailbox; a
    /// permanent one is what returns the space. Somebody who typed --delete
    /// expecting the second and got the first would find the mailbox just as
    /// full a month later, with the mail no longer where they left it.
    /// </remarks>
    private static bool TryReadDeleteMode(string? value, out DeleteProcessed mode)
    {
        mode = DeleteProcessed.Keep;
        if (value is null) { return true; }

        switch (value.Trim().ToLowerInvariant())
        {
            case "soft":
                mode = DeleteProcessed.Soft;
                return true;

            case "permanent":
                mode = DeleteProcessed.Permanent;
                return true;

            default:
                Console.Error.WriteLine($"--delete takes 'soft' or 'permanent', not '{value}'.");
                Console.Error.WriteLine();
                Console.Error.WriteLine("  soft       moves the message to Deleted Items. A person can get it back,");
                Console.Error.WriteLine("             and it still counts against the mailbox quota until a retention");
                Console.Error.WriteLine("             policy clears that folder.");
                Console.Error.WriteLine("  permanent  removes it from the mailbox. In Exchange Online it goes to");
                Console.Error.WriteLine("             Recoverable Items, which has its own quota - so this is the one");
                Console.Error.WriteLine("             that gives the space back. Still recoverable for the tenant's");
                Console.Error.WriteLine("             retention period.");
                Console.Error.WriteLine();
                Console.Error.WriteLine("Either way only mail whose reports are already stored is deleted. Reports");
                Console.Error.WriteLine("that could not be read, that were quarantined, or that were not attributed");
                Console.Error.WriteLine("are always kept. Run with --dry-run first.");
                return false;
        }
    }

    private static void Report(IngestRunResult result, int stored, bool dryRun)
    {
        Console.WriteLine($"  messages read      {result.MessagesRead}");
        if (result.MessagesDeleted > 0)
        {
            Console.WriteLine($"  deleted            {result.MessagesDeleted} (reports stored first)");
        }
        Console.WriteLine($"  reports ingested   {result.IngestedCount}{(dryRun ? " (not written)" : $", {stored} stored")}");
        if (result.DuplicateCount > 0) { Console.WriteLine($"  already seen       {result.DuplicateCount}"); }
        if (result.UnrecognizedCount > 0)
        {
            Console.WriteLine($"  not reports        {result.UnrecognizedCount}");
            // Grouped by reason, so a mailbox full of one kind of thing is one
            // line rather than a page, and the reason points at the cause.
            foreach (var g in result.Reports.Where(r => r.Outcome == IngestOutcome.Unrecognized)
                         .GroupBy(r => r.Reason).OrderByDescending(g => g.Count()).Take(5))
            {
                Console.WriteLine($"    {g.Count()}: {g.Key}");
            }
        }

        if (result.UnattributedCount > 0)
        {
            Console.WriteLine($"  not attributed     {result.UnattributedCount} (genuine reports, left in the mailbox)");
            Console.WriteLine($"    delivered to: {string.Join(", ", result.UnattributedAddresses.Take(5))}");
        }

        if (result.QuarantinedCount > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"  QUARANTINED        {result.QuarantinedCount}");
            foreach (var r in result.Reports.Where(r => r.Outcome == IngestOutcome.Quarantined))
            {
                Console.WriteLine($"    {r.FileName}: {r.Reason}");
            }
        }

        if (result.Errors.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"  errors             {result.Errors.Count}");
            foreach (var e in result.Errors) { Console.WriteLine($"    {e}"); }
        }

        if (result.StoppedEarly)
        {
            Console.WriteLine();
            Console.WriteLine("  Stopped before the end of the mailbox. Processed mail has been filed, so the");
            Console.WriteLine("  next run continues from here rather than starting again.");
        }

    }

    /// <summary>
    /// Unbilled work, said out loud at the end of a run.
    /// </summary>
    /// <remarks>
    /// Separate from the counts above because it asks the database a question
    /// and the rest of the summary is arithmetic already in hand.
    /// </remarks>
    private static async Task WarnUnassignedAsync(ReportStore store, CancellationToken ct)
    {
        var unassigned = await store.GetUnassignedDomainsAsync(ct: ct).ConfigureAwait(false);
        if (unassigned.Count == 0) { return; }

        Console.WriteLine();
        Console.WriteLine($"  {unassigned.Count} domain(s) are not assigned to a client:");
        foreach (var d in unassigned.Take(20)) { Console.WriteLine($"    {d}"); }
        Console.WriteLine("  Reports are arriving for these and nobody is being billed for them.");
    }
}

/// <summary>Attaches a Graph access token to every request.</summary>
internal sealed class BearerTokenHandler(TokenCredential credential) : DelegatingHandler
{
    private static readonly string[] Scopes = ["https://graph.microsoft.com/.default"];
    private readonly TokenCredential _credential = credential;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Azure.Identity caches internally, so this does not fetch a token per
        // request; it returns the cached one until it is close to expiring.
        var token = await _credential
            .GetTokenAsync(new TokenRequestContext(Scopes), cancellationToken)
            .ConfigureAwait(false);

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.Token);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Wraps a mailbox so a dry run cannot change it.
/// </summary>
/// <remarks>
/// Enforced here rather than by remembering to check a flag at each call site.
/// A dry run that quietly moved mail would be worse than no dry run at all,
/// because it would be trusted.
/// </remarks>
internal sealed class ReadOnlyMailbox(IMailboxClient inner) : IMailboxClient
{
    private readonly IMailboxClient _inner = inner;

    public IAsyncEnumerable<MailMessage> GetMessagesAsync(string folder, CancellationToken cancellationToken = default) =>
        _inner.GetMessagesAsync(folder, cancellationToken);

    public Task<IReadOnlyList<MailAttachment>> GetAttachmentsAsync(string messageId, CancellationToken cancellationToken = default) =>
        _inner.GetAttachmentsAsync(messageId, cancellationToken);

    public Task MoveMessageAsync(string messageId, string destinationFolderId, CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    /// <summary>
    /// Does nothing, which is the whole reason this wrapper exists.
    /// </summary>
    /// <remarks>
    /// A dry run that moved mail would be bad. A dry run that deleted it would
    /// be unrecoverable, and it is exactly the run somebody uses to decide
    /// whether deleting is safe.
    /// </remarks>
    public Task DeleteMessageAsync(string messageId, bool permanent, CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    /// <summary>Returns the name unchanged rather than creating anything.</summary>
    public Task<string> EnsureFolderAsync(string folderName, CancellationToken cancellationToken = default) =>
        Task.FromResult(folderName);

    public Task<IReadOnlyList<MailFolder>> GetChildFoldersAsync(string folderName, CancellationToken cancellationToken = default) =>
        _inner.GetChildFoldersAsync(folderName, cancellationToken);
}
