using DmarcMonitor.Cli.Commands;

namespace DmarcMonitor.Cli;

/// <summary>
/// Entry point.
///
/// Commands are separated by whether they need a tenant, because that decides
/// what can be run today. 'explain' and 'init-db' need nothing but a file and
/// a disk; 'ingest' needs a certificate, an app registration and a mailbox.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        using var cts = new CancellationTokenSource();

        // Ctrl+C means stop tidily, not die. An ingest run that is interrupted
        // returns what it already did, and its messages are already filed, so
        // the next run resumes rather than starting again.
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.Error.WriteLine();
            Console.Error.WriteLine("Stopping. Work already done is kept; the next run will resume.");
            cts.Cancel();
        };

        try
        {
            var command = args.Length > 0 ? args[0].ToLowerInvariant() : "help";
            var rest = args.Skip(1).ToArray();

            // Asked what a command does, answer - do not do it. No subcommand
            // looked for a help request, and the consequences were not all
            // harmless: `init-db --help` found no value for --db, fell back to
            // the default, and created a 548 KB database in whatever directory
            // the person happened to be standing in, exit 0. Somebody asking a
            // command what it does should never have it happen to them.
            if (rest.Any(a => a is "--help" or "-h" or "/?")) { return Help(); }

            return command switch
            {
                "explain" => await ExplainCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "init-db" => await InitDbCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "ingest" => await IngestCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "import" => await ImportCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "client" => await ClientCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "org" => await OrgCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "report" => await ReportCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "check" => await CheckCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "audit" => await AuditCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "simulate" => await SimulateCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "intel" => await IntelCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "fix" => await FixCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "dns" => await DnsCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "mta-sts" => await MtaStsCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "version" or "--version" => Version(),
                "help" or "--help" or "-h" => Help(),
                _ => Unknown(command),
            };
        }
        catch (OperationCanceledException)
        {
            return 130;   // conventional exit code for interrupted
        }
        catch (Exception ex)
        {
            // Every expected failure is already handled inside its command with
            // a readable message. Anything reaching here is a bug, so it says
            // so rather than pretending to be ordinary.
            Console.Error.WriteLine();
            Console.Error.WriteLine($"Unexpected error: {ex.Message}");
            Console.Error.WriteLine();
            Console.Error.WriteLine("This is a bug. The detail below is worth reporting:");
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    /// <summary>What this build is, which is the first question when something is wrong.</summary>
    private static int Version()
    {
        Console.WriteLine($"dmarc {DmarcMonitor.Core.Updates.BuildInfo.Version}");

        if (!DmarcMonitor.Core.Updates.BuildInfo.IsRelease)
        {
            Console.WriteLine("Built from a working tree rather than a release tag.");
        }

        Console.WriteLine($"Database schema this build expects: {DmarcMonitor.Core.Storage.DatabaseMigrations.BaselineVersion}");
        return 0;
    }

    private static int Help()
    {
        Console.WriteLine("""
            DMARC Monitor

            USAGE
              dmarc <command> [options]

            COMMANDS
              explain <file>     Read a DMARC or TLS report and explain it in plain English.
                                 Works on any report file. Needs no mailbox, no database and
                                 no configuration, so it also works on a report somebody has
                                 just sent you.

              init-db            Create the SQLite database.
                --db <path>      Database file. Default: dmarc.db
                --schema <path>  Schema file. Default: db/schema.sql

              import             Import report files from a folder. Needs no mailbox, so it
                                 works on an archive or on files somebody sent you.
                --from <folder>  Folder to read, including subfolders.
                --db <path>      Database file. Default: dmarc.db

              client             Onboarding: turn domains reports arrived for into clients.
                                 Reports for a domain nobody has onboarded are kept under
                                 "Unassigned" rather than refused, so this is the worklist.
                list             Every client, with domains and messages. Names what is
                                 still unassigned.
                add              Create a client.
                  --name <name>  Display name. The slug is derived from it.
                  --slug <slug>  Override the derived slug.
                assign           File a domain, and its stored history, under a client.
                  --domain <d>   Domain as it appears in the reports.
                  --client <s>   Client slug, from 'dmarc client list'.
                --org <slug>     Organization a new client belongs to. Default: local
                --db <path>      Database file. Default: dmarc.db

              org                Organizations: the layer above clients. Each has its own
                                 clients and domains, and its people - an Entra security
                                 group - see those and nothing else.
                list             Every organization, with its group.
                add              Create one.  --name <name> [--slug <slug>] [--group <id>]
                set-group        Say which Entra group belongs to it.  --org <slug> --group <id>
                rename           --org <slug> --name <name>
                --db <path>      Database file. Default: dmarc.db

              report             Write the monthly report a client receives, as one
                                 self-contained HTML file that opens offline and prints.
                                 Defaults to the month that has ENDED, so running it twice
                                 in the same month produces the same document.
                --client <slug>  Client to report on.
                --all            Every client except Unassigned.
                --month <yyyy-MM> Month to cover. Default: last complete month.
                --out <folder>   Where to write. Default: reports
                --provider <n>   How to name yourself in the report.
                --db <path>      Database file. Default: dmarc.db

              check              Read what a domain publishes in DNS and say what is wrong
                                 with it: SPF lookup limit, dead includes, a record that
                                 authorizes everybody, a policy applied to only part of the
                                 mail. Needs no database, so it works on a prospect's domain.
                                 Where a domain announces MTA-STS the policy file is fetched
                                 as a sender would, so the mode is the one being served
                                 rather than the one the last reports remember, and the
                                 policy's mx: lines are checked against the real MX - an
                                 enforce policy naming the wrong host bounces the domain's
                                 own mail.
                --domain <d>     One domain.
                --all            Every domain in the database.
                --save           Store what was read, so the dashboard can show each domain's
                                 SPF, DKIM and DMARC status without resolving eighty domains
                                 every time somebody opens the page. Also looks up the DKIM
                                 selectors the reports have seen signing, which is the only
                                 way to check DKIM at all - DNS cannot be asked which
                                 selectors a domain has. Run it daily:
                                 dmarc check --all --save --db <path>
                --db <path>      Database file. Default: dmarc.db

              audit              Read a zone file and say what is wrong with it. Takes the
                                 BIND-format export every registrar and DNS host offers,
                                 and checks it against live DNS and against the reports.
                                 It sees what 'check' cannot: DNS will not list a domain's
                                 DKIM selectors, so only a zone file can show the ones that
                                 have stopped resolving, the key published with the wrong
                                 version tag, or the record that reads as SPF and has no
                                 v=spf1 in front of it.
                --zone <file>    The exported zone file.
                --domain <d>     The domain it is a zone for, if the file does not say.
                --offline        Judge the file alone; ask neither DNS nor the reports.
                --db <path>      Database file. Default: dmarc.db

              simulate           Replay the reports already held against a record you have
                                 not published, and say what it would cost. Anything not
                                 named keeps what the domain publishes today, so the answer
                                 is the cost of the change rather than of the whole record.
                --domain <d>     Domain to replay.
                --policy <p>     none, quarantine or reject.
                --adkim r|s      DKIM alignment to try.
                --aspf r|s       SPF alignment to try.
                --pct <n>        Percent of failing mail the policy would apply to.
                --days <n>       Window to replay. Default: 30
                --db <path>      Database file. Default: dmarc.db
                                 Exits non-zero when the change would cost mail.

              fix                Fix what 'check' found, in the customer's DNS. A dry run
                                 unless --apply is given. Every apply is recorded with who,
                                 when, why and what was there before, and appears on the
                                 client's report under "what we did".
                --domain <d>     One domain. With no other flag: the safe fixes only (a
                                 weaker subdomain policy, includes that resolve to nothing).
                --all            The safe fixes for every domain.
                --policy <p>     Move one domain to quarantine or reject. Refuses to skip
                                 quarantine on the way to reject.
                --pct <n>        Apply the policy to this percent of failing mail.
                --apply          Write it. Needs --reason "...", written for the customer.
                --by <name>      Who is doing this. Default: the signed-in user.
                --history        What has been applied, newest first.
                --verify <id>    Check a change is visible in DNS yet.
                --rollback <id>  Put back what was there. Needs --reason.
                --db <path>      Database file. Default: dmarc.db

              dns                Which DNS provider holds each client's zones. Needed for
                                 'fix --apply'; without one, fixes are planned and shown.
                list             What is configured. Never shows a credential.
                set              --client <slug> [--domain <d>] --provider cloudflare|azuredns|manual
                                 The credential is read from DMARC_DNS_SECRET, stdin with
                                 --secret-stdin, or a prompt. Never as an argument.
                test             --domain <d>  Read the zone through the provider.
                remove           --client <slug> [--domain <d>]

              mta-sts            The MTA-STS policy this serves for a domain, at
                                 mta-sts.<domain>. MTA-STS needs a DNS record AND a policy
                                 file served over HTTPS; this is the file. Point
                                 mta-sts.<domain> at the host running the web app, then
                                 announce it with 'dmarc fix'.
                list             What is being served, and where.
                set              --domain <d> [--mode testing|enforce|none] [--mx <host>]...
                                 Mail servers come from the domain's MX records unless
                                 named. Starts in testing, which enforces nothing.
                check            --domain <d>  Fetch what is really served, as a sender does.
                remove           --domain <d>
                --db <path>      Database file. Default: dmarc.db

              intel              Refresh and show what has been learned about sources
                                 impersonating clients, across every domain watched.
                --db <path>      Database file. Default: dmarc.db
                --export         Print confirmed and high-confidence indicators only,
                                 one per line, for a firewall or SIEM.

              ingest             Read the reporting mailbox and store what arrives.
                --db <path>            Database file. Default: dmarc.db
                --mailbox <address>    Shared mailbox receiving reports.
                --tenant <guid>        Entra tenant id.
                --client-id <guid>     App registration (client) id.
                --cert <path>          Certificate with private key (.pfx).
                --cert-password <pw>   Certificate password, if it has one.
                --reporting-domain <d> Subdomain per-domain report addresses use.
                --fallback <address>   Shared address, for domains not yet migrated.
                --max <n>              Messages per run. Default: 500
                --delete <mode>        Delete a message once its reports are stored, rather
                                     than filing it. A reporting mailbox grows without
                                     limit, and the processed folder is the same quota.
                                       soft       to Deleted Items: a person can get it
                                                  back, and it still uses the quota until
                                                  a retention policy clears that folder.
                                       permanent  out of the mailbox, which is what gives
                                                  the space back. Recoverable Items keeps
                                                  it for the tenant's retention period.
                                     Only stored mail is ever deleted. Reports that could
                                     not be read, that were quarantined, or that were not
                                     attributed are always kept. Try --dry-run first.
                --dry-run              Parse and report, write nothing, move nothing,
                                     delete nothing.
                                     Safe against a live mailbox. See
                                     docs/INGEST-SETUP.md for the app registration,
                                     and read the part about restricting it to one
                                     mailbox before the first run.

            EXAMPLES
              dmarc explain report.xml
              dmarc explain report.json.gz
              dmarc init-db --db /var/dmarc/dmarc.db
              dmarc import --from C:\dmarc-export
              dmarc client add --name "Morton, ND"
              dmarc client assign --domain mortonnd.gov --client morton-nd
              dmarc check --domain example.com
              dmarc audit --zone example.com.txt
              dmarc simulate --domain example.com --policy quarantine
              dmarc fix --domain example.com
              dmarc fix --domain example.com --policy quarantine --apply --reason "30 days at p=none with everything authenticating"
              dmarc ingest --mailbox dmarc@example.com --dry-run
            """);
        return 0;
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"Unknown command '{command}'. Run 'dmarc help' to see what is available.");
        return 64;   // EX_USAGE
    }
}
