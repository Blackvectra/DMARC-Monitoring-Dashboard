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
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var mailbox = Args.Value(args, "--mailbox");
        var tenantId = Args.Value(args, "--tenant") ?? Environment.GetEnvironmentVariable("DMARC_TENANT_ID");
        var clientId = Args.Value(args, "--client-id") ?? Environment.GetEnvironmentVariable("DMARC_CLIENT_ID");
        var certPath = Args.Value(args, "--cert") ?? Environment.GetEnvironmentVariable("DMARC_CERT_PATH");
        var certPassword = Args.Value(args, "--cert-password") ?? Environment.GetEnvironmentVariable("DMARC_CERT_PASSWORD");
        var reportingDomain = Args.Value(args, "--reporting-domain") ?? "";
        var fallback = Args.Value(args, "--fallback");
        var maxMessages = Args.Int(args, "--max", 500);
        var dryRun = Args.Flag(args, "--dry-run");

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

        if (string.IsNullOrWhiteSpace(reportingDomain) && string.IsNullOrWhiteSpace(fallback))
        {
            // Without either, nothing can be attributed and every report would
            // be filed as unrecognised. Saying so now beats a run that reads
            // the whole mailbox and stores nothing.
            Console.Error.WriteLine("Give me --reporting-domain, --fallback, or both.");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  --reporting-domain  the subdomain per-domain report addresses use,");
            Console.Error.WriteLine("                      for example rua.nrgsecure.com");
            Console.Error.WriteLine("  --fallback          a single shared address every domain reports to,");
            Console.Error.WriteLine("                      for example dmarc@nrgtechservices.com");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Without one of these no report can be attributed to a domain.");
            return 64;
        }

        var store = new ReportStore(dbPath);
        if (!dryRun && !await store.IsInitialisedAsync(ct).ConfigureAwait(false))
        {
            Console.Error.WriteLine($"{dbPath} is not a DMARC Monitor database. Run: dmarc init-db --db {dbPath}");
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
            };

            // Dry run reads and parses but writes nothing and moves nothing, so
            // the first run against a real mailbox can be inspected before it
            // changes anything.
            var ingestor = dryRun
                ? new ReportIngestor(new ReadOnlyMailbox(mailboxClient), options, ResolveToken, _ => false)
                : new ReportIngestor(mailboxClient, options, ResolveToken,
                    key => IsStored(store, key, ct).GetAwaiter().GetResult());

            Console.WriteLine($"Reading {mailbox}{(dryRun ? " (dry run: nothing will be written or moved)" : "")}");
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

            await ReportAsync(result, store, dryRun, ct).ConfigureAwait(false);
            return result.Errors.Count > 0 ? 1 : 0;
        }

        // Per-domain addressing is not wired to storage yet, so no token
        // resolves and attribution falls back to the shared address. Returning
        // null is honest about that; inventing a domain would file reports
        // against the wrong customer.
        static string? ResolveToken(string token) => null;
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

    private static async Task ReportAsync(IngestRunResult result, ReportStore store, bool dryRun, CancellationToken ct)
    {
        var stored = 0;

        if (!dryRun)
        {
            foreach (var report in result.Reports.Where(r => r.Outcome == IngestOutcome.Ingested))
            {
                try
                {
                    var id = report.Kind switch
                    {
                        ReportKind.DmarcAggregate when report.Aggregate is not null =>
                            await store.SaveAggregateAsync(report.Aggregate, report.FileName, report.MessageId, ct).ConfigureAwait(false),
                        ReportKind.TlsRpt when report.Tls is not null =>
                            await store.SaveTlsAsync(report.Tls, report.FileName, report.MessageId, ct).ConfigureAwait(false),
                        _ => null,
                    };
                    if (id is not null) { stored++; }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Console.Error.WriteLine($"Could not store {report.FileName} for {report.Domain}: {ex.Message}");
                }
            }
        }

        Console.WriteLine($"  messages read      {result.MessagesRead}");
        Console.WriteLine($"  reports ingested   {result.IngestedCount}{(dryRun ? " (not written)" : $", {stored} stored")}");
        if (result.DuplicateCount > 0) { Console.WriteLine($"  already seen       {result.DuplicateCount}"); }
        if (result.UnrecognisedCount > 0) { Console.WriteLine($"  not reports        {result.UnrecognisedCount}"); }

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

        if (!dryRun)
        {
            var unassigned = await store.GetUnassignedDomainsAsync(ct).ConfigureAwait(false);
            if (unassigned.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"  {unassigned.Count} domain(s) are not assigned to a client:");
                foreach (var d in unassigned.Take(20)) { Console.WriteLine($"    {d}"); }
                Console.WriteLine("  Reports are arriving for these and nobody is being billed for them.");
            }
        }
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

    /// <summary>Returns the name unchanged rather than creating anything.</summary>
    public Task<string> EnsureFolderAsync(string folderName, CancellationToken cancellationToken = default) =>
        Task.FromResult(folderName);

    public Task<IReadOnlyList<MailFolder>> GetChildFoldersAsync(string folderName, CancellationToken cancellationToken = default) =>
        _inner.GetChildFoldersAsync(folderName, cancellationToken);
}
