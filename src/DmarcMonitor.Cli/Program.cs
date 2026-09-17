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

            return command switch
            {
                "explain" => await ExplainCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "init-db" => await InitDbCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "ingest" => await IngestCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "import" => await ImportCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "client" => await ClientCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
                "intel" => await IntelCommand.RunAsync(rest, cts.Token).ConfigureAwait(false),
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
                --dry-run              Parse and report, write nothing, move nothing.

            EXAMPLES
              dmarc explain report.xml
              dmarc explain report.json.gz
              dmarc init-db --db /var/dmarc/dmarc.db
              dmarc import --from C:\dmarc-export
              dmarc client add --name "Morton, ND"
              dmarc client assign --domain mortonnd.gov --client morton-nd
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
