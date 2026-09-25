using DmarcMonitor.Cli.Commands;
using DmarcMonitor.Core.Platform;

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
        // Somebody double-clicked this in Explorer. It is a reasonable thing
        // to try - it is called dmarc.exe and it is sitting next to the
        // application - and until now what it got was the help text in a
        // window that Windows destroyed on the same tick it was written to.
        //
        // The report that produced this was "the app appears like it opens
        // then just closes with a shadow", which is a perfect description of
        // a console application working exactly as designed. So: say which
        // program this is before saying what it does, and hold the window
        // afterwards so that either can be read.
        if (args.Length == 0 && ConsoleWindow.BelongsToThisProcess())
        {
            NotTheApplication();
        }

        var exitCode = await RunAsync(args).ConfigureAwait(false);

        ConsoleWindow.HoldOpen();
        return exitCode;
    }

    private static async Task<int> RunAsync(string[] args)
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
                "reachability" => await ReachabilityCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "prune" => await PruneCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "export" => await ExportCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "backup" => await BackupCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "health" => await HealthCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
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

    /// <summary>
    /// Printed above the help when this was double-clicked rather than typed.
    /// </summary>
    /// <remarks>
    /// What it says depends on whether the application is actually here. In
    /// the Windows trial bundle it is in the same folder, so it can be named
    /// exactly; a dmarc.exe downloaded on its own has no sibling to point at,
    /// and sending somebody to look for a file that is not there is worse
    /// than sending them back to the releases page.
    /// </remarks>
    internal static void NotTheApplication()
    {
        var beside = Path.Combine(AppContext.BaseDirectory, "DmarcMonitor.Web.exe");

        Console.WriteLine();
        Console.WriteLine("This is the command-line tool, not the dashboard.");
        Console.WriteLine();

        if (File.Exists(beside))
        {
            Console.WriteLine("To open the dashboard, close this window and double-click:");
            Console.WriteLine();
            Console.WriteLine("    DmarcMonitor.Web.exe");
            Console.WriteLine();
            Console.WriteLine("It is in this same folder. A browser opens by itself.");
        }
        else
        {
            Console.WriteLine("The dashboard is a separate download. On the releases page it is");
            Console.WriteLine("the file whose name says Windows - unzip it and double-click");
            Console.WriteLine("DmarcMonitor.Web.exe. This file is only useful from a terminal.");
        }

        Console.WriteLine();
        Console.WriteLine("What this tool can do, if a terminal is what you wanted:");
    }

    private static int Help()
    {
        Console.WriteLine("""
            DMARC Monitor

            USAGE
              dmarc <command> [options]

            COMMANDS
              explain <file>     Read a report and explain it in plain English. Aggregate
                                 (RUA), TLS (TLS-RPT) and failure (RUF) reports all work.
                                 Needs no mailbox, no database and no configuration, so it
                                 also works on a report somebody has just sent you.

              init-db            Create the SQLite database.
                --db <path>      Database file. Default: dmarc.db
                --schema <path>  Schema file. Default: db/schema.sql

              import             Import report files from a folder. Needs no mailbox, so it
                                 works on an archive or on files somebody sent you. A file
                                 that cannot be read is named and skipped, the rest are
                                 imported, and the run exits 1.
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
                erase            Remove a client and everything belonging to them,
                                 permanently. The answer to "can we have our data
                                 deleted". A dry run unless --apply, and --apply alone
                                 is not enough: the slug must be typed again into
                                 --confirm, because --apply is muscle memory by the
                                 time anybody reaches this. Verified afterwards - every
                                 table carrying a client_id is checked, and anything
                                 left behind takes the whole thing back. The audit log
                                 survives it, because proving a request was honoured is
                                 the other half of honouring it. Says what your backups
                                 still hold, and until when.
                  --client <s>   Client slug.
                  --apply --confirm <s> --by <name>
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

              report             Write the monthly report a client receives, as a PDF:
                                 the document you attach to an email, carrying your own
                                 name and none of this server's. Defaults to the month
                                 that has ENDED, so running it twice in the same month
                                 produces the same document.
                --client <slug>  Client to report on.
                --all            Every client except Unassigned.
                --month <yyyy-MM> Month to cover. Default: last complete month.
                --out <folder>   Where to write. Default: reports
                --html           Also write the long on-screen version, with the
                                 full evidence tables. A PDF is written either way.
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

              reachability       Which domains' reports can actually get back here. Both
                                 ways this breaks are silent: a receiver that looks for the
                                 RFC 7489 authorization record and does not find it declines
                                 to send and tells nobody, and a domain whose rua points at
                                 a mailbox nothing collects looks perfect in DNS and
                                 produces nothing. Run it after onboarding a domain.
                --domain <d>     One domain. Default: every domain in the book.
                --quiet          Only the domains with something wrong.
                --db <path>      Database file. Default: dmarc.db

              prune              Remove report data past its retention window. A dry run
                                 unless --apply. Nothing else in this product deletes a
                                 customer's history, so it counts first, deletes in one
                                 transaction, and records what it removed in the audit log.
                                 Domains and clients are never touched - only the reports
                                 age out.
                --aggregate-days <n>  Aggregate and TLS reports to keep. Default: 400
                                      (thirteen months, so this month still has last
                                      year's same month to sit beside).
                --forensic-days <n>   Forensic reports to keep. Default: 30. These hold
                                      real message headers, so this is deliberately the
                                      shortest window and may not exceed the one above.
                --apply               Do it.
                --by <name>           Who is doing this. Default: the signed-in user.
                --db <path>           Database file. Default: dmarc.db

              export             Write the stored records out for something else to query.
                                 The screens here are opinionated, and that is also their
                                 limit - "every address that hit these three domains,
                                 aligned on SPF only, in a six-hour window" is a question
                                 no fixed view answers. This hands the rows to jq, a
                                 spreadsheet, OpenSearch or Splunk and lets those be the
                                 query language. It is also how to keep retention here
                                 short and let an index hold the long tail.
                                 Rows go to stdout, so it pipes; everything it says about
                                 itself goes to stderr.
                --format <f>     ndjson (default) or csv. ndjson is what _bulk, jq and HEC
                                 read, and a row at a time rather than one huge array.
                --out <path>     Write to a file instead of stdout.
                --org <slug>     One organization. --client <slug>, --domain <d> narrow it
                                 further.
                --days <n>       How far back. Default: everything held.
                --failures-only  Only the rows that did not pass DMARC.
                --after-id <n>   Start after this row id, for shipping only what is new.
                                 Every run prints the number to use next time.
                --db <path>      Database file. Default: dmarc.db

              backup             Take a verified copy of the database. The only thing here
                                 that protects the reports - update and rollback roll the
                                 BINARY back, and years of a customer's history had nothing.
                                 Safe while the collector is running: the copy comes from
                                 SQLite, not the filesystem, so it is a consistent snapshot
                                 rather than whatever the bytes were mid-write.
                                 The LIVE database is integrity-checked first, before
                                 anything is written or removed: a database that has begun
                                 to corrupt still copies, and the copy verifies, so checking
                                 only the copy would quietly replace every good backup you
                                 hold with a copy of the damage. A source that fails stops
                                 the run - nothing written, nothing pruned, exit 74.
                --to <dir>       Where to write. Put it on a different disk from --db.
                --keep <n>       Backups to keep, newest first. Default: 14. Older ones go
                                 only after a new copy has verified, so a failed run never
                                 costs you yesterday's.
                --quick          Use PRAGMA quick_check on the live database instead of
                                 integrity_check: ~9x faster, and skips the one part worth
                                 having - whether each index still agrees with its table.
                                 The full check is 100ms on 17 MB and 3.8s on 313 MB, so
                                 this is for much later than you think.
                --db <path>      Database file. Default: dmarc.db

              health             Whether this install is still doing its job. Everything it
                                 looks at fails silently: a collector whose certificate
                                 expired stops storing reports and says nothing, while every
                                 screen goes on showing the figures from before it stopped.
                                 Judged on what was STORED, not on whether a process ran - a
                                 run against the wrong mailbox succeeds every time.
                                 Exits 1 when something is broken, so systemd OnFailure= or
                                 cron's mail-on-output turns it into an alert with no SMTP
                                 configuration of its own.
                --backups <dir>  Also check a backup was taken recently. Left out, nothing
                                 is concluded about backups rather than assumed missing.
                --quiet          Print nothing when there is nothing wrong. What a
                                 scheduled run wants.
                --db <path>      Database file. Default: dmarc.db

              fix              Fix what 'check' found, in the customer's DNS. A dry run
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
                                 one per line, for a firewall or SIEM. Anything not
                                 safe to block - a shared platform, or an address
                                 that also delivered a client's authenticated mail -
                                 is withheld and listed underneath with the reason.
                --names          Look up what each source's address reverses to, and
                                 check the name points back. Reports and pages use
                                 these names to recognize mail filters and services;
                                 run it after an import. Server installs run it nightly.
                --names-limit <n> Look up at most n sources, busiest first. Default: 500

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
                --folder <name>        A folder to read, by its exact name; give it again
                                     for each folder. Default: Inbox. Each is read with
                                     the folders directly inside it. The name is matched
                                     whole, so a backslash is part of it, as in
                                     DMARC\example.org - quote it. Or DMARC_FOLDERS, with
                                     the names separated by semicolons.
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
              dmarc client add --name "Acme Corp"
              dmarc client assign --domain acme.example --client acme-corp
              dmarc check --domain example.com
              dmarc audit --zone example.com.txt
              dmarc simulate --domain example.com --policy quarantine
              dmarc reachability --quiet
              dmarc prune                                    # what would go
              dmarc prune --apply
              dmarc export --days 7 --failures-only | jq -r .source_ip | sort | uniq -c
              dmarc export --format csv --out book.csv
              dmarc backup --to /var/backups/dmarc
              dmarc health --quiet          # silent unless something is wrong
              dmarc export --after-id 41232 | jq -c '{index:{_index:"dmarc",_id:.id}},.'
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
