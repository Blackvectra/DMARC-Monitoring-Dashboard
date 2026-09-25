using System.Net;
using System.Text;
using DmarcMonitor.Core.Graph;
using DmarcMonitor.Core.Ingest;

namespace DmarcMonitor.Core.Tests.Graph;

/// <summary>
/// The Graph mailbox client.
///
/// The failure to avoid above every other is a misconfigured deployment that
/// returns zero messages and looks like a quiet mailbox. An operator would
/// wait days for reports that were never going to arrive, with nothing saying
/// why. So most of these tests are about errors being loud and specific
/// rather than about the happy path.
/// </summary>
public sealed class GraphMailboxClientTests
{
    private const string Mailbox = "dmarc@nrgtechservices.com";

    private static (GraphMailboxClient Client, StubHttpMessageHandler Stub) Build(StubHttpMessageHandler stub)
    {
        var http = new HttpClient(stub) { BaseAddress = new Uri("https://graph.microsoft.com/") };
        return (new GraphMailboxClient(http, Mailbox), stub);
    }

    private const string OneMessage = """
        {"value":[{
          "id":"AAMkAD1",
          "subject":"Report Domain: nrgtechservices.com",
          "from":{"emailAddress":{"address":"noreply-dmarc-support@google.com"}},
          "toRecipients":[{"emailAddress":{"address":"k3m9p2xq7rt4vwn8@rua.nrgsecure.com"}}],
          "receivedDateTime":"2026-09-16T08:15:00Z",
          "hasAttachments":true}]}
        """;

    // ---- reading messages ---------------------------------------------------

    [Fact]
    public async Task ReadsAMessage()
    {
        var (client, _) = Build(new StubHttpMessageHandler().When("/messages", HttpStatusCode.OK, OneMessage));

        var messages = new List<MailMessage>();
        await foreach (var m in client.GetMessagesAsync("Inbox")) { messages.Add(m); }

        var message = Assert.Single(messages);
        Assert.Equal("AAMkAD1", message.Id);
        Assert.Equal("noreply-dmarc-support@google.com", message.From);
        Assert.Equal("k3m9p2xq7rt4vwn8@rua.nrgsecure.com", Assert.Single(message.ToAddresses));
        Assert.True(message.HasAttachments);
        Assert.Equal(new DateTimeOffset(2026, 9, 16, 8, 15, 0, TimeSpan.Zero), message.ReceivedAt);
    }

    [Fact]
    public async Task RequestsOldestFirst()
    {
        // The contract the ingestor relies on to work through a backlog rather
        // than repeatedly re-reading the newest mail.
        var (client, stub) = Build(new StubHttpMessageHandler().When("/messages", HttpStatusCode.OK, """{"value":[]}"""));

        await foreach (var _ in client.GetMessagesAsync("Inbox")) { }

        // Compare unescaped: Uri normalizes %20 back to a space and re-encodes
        // on the wire, so asserting on the encoding tests the wrong thing.
        var url = Uri.UnescapeDataString(stub.Requests[^1].RequestUri!.ToString());
        Assert.Contains("$orderby=receivedDateTime asc", url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DoesNotFilterOnHasAttachmentsServerSide()
    {
        // Graph's hasAttachments filter is unreliable for inline attachments.
        // A report excluded by the server is invisible: it sits in the inbox
        // forever and nothing reports it as skipped.
        var (client, stub) = Build(new StubHttpMessageHandler().When("/messages", HttpStatusCode.OK, """{"value":[]}"""));

        await foreach (var _ in client.GetMessagesAsync("Inbox")) { }

        Assert.DoesNotContain("hasAttachments%20eq", stub.Requests[^1].RequestUri!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task FollowsPaging()
    {
        // A mailbox with a backlog returns many pages. Stopping at the first
        // would silently ingest a fraction of it.
        const string page1 = """
            {"value":[{"id":"m1","toRecipients":[],"receivedDateTime":"2026-09-16T08:00:00Z"}],
             "@odata.nextLink":"https://graph.microsoft.com/v1.0/nextpage"}
            """;
        const string page2 = """{"value":[{"id":"m2","toRecipients":[],"receivedDateTime":"2026-09-16T09:00:00Z"}]}""";

        var stub = new StubHttpMessageHandler()
            .When("/nextpage", HttpStatusCode.OK, page2)
            .When("/messages", HttpStatusCode.OK, page1);
        var (client, _) = Build(stub);

        var ids = new List<string>();
        await foreach (var m in client.GetMessagesAsync("Inbox")) { ids.Add(m.Id); }

        Assert.Equal(["m1", "m2"], ids);
    }

    [Fact]
    public async Task SkipsAMessageWithNoIdRatherThanFailing()
    {
        const string body = """{"value":[{"subject":"no id"},{"id":"m2","toRecipients":[]}]}""";
        var (client, _) = Build(new StubHttpMessageHandler().When("/messages", HttpStatusCode.OK, body));

        var ids = new List<string>();
        await foreach (var m in client.GetMessagesAsync("Inbox")) { ids.Add(m.Id); }

        Assert.Equal("m2", Assert.Single(ids));
    }

    [Fact]
    public async Task ReadsEveryRecipientAddress()
    {
        // Attribution depends on these, so dropping all but the first would
        // silently weaken it.
        const string body = """
            {"value":[{"id":"m1","toRecipients":[
              {"emailAddress":{"address":"a@rua.nrgsecure.com"}},
              {"emailAddress":{"address":"b@rua.nrgsecure.com"}}]}]}
            """;
        var (client, _) = Build(new StubHttpMessageHandler().When("/messages", HttpStatusCode.OK, body));

        await foreach (var m in client.GetMessagesAsync("Inbox"))
        {
            Assert.Equal(2, m.ToAddresses.Count);
        }
    }

    // ---- attachments --------------------------------------------------------

    [Fact]
    public async Task FetchesAttachmentContent()
    {
        var content = Encoding.UTF8.GetBytes("<feedback></feedback>");
        var stub = new StubHttpMessageHandler()
            .WhenBytes("/$value", content)
            .When("/attachments", HttpStatusCode.OK, """
                {"value":[{"@odata.type":"#microsoft.graph.fileAttachment",
                  "id":"att1","name":"report.xml.gz","contentType":"application/gzip","size":21}]}
                """);
        var (client, _) = Build(stub);

        var attachment = Assert.Single(await client.GetAttachmentsAsync("m1"));
        Assert.Equal("report.xml.gz", attachment.Name);
        Assert.Equal(21, attachment.Size);
        Assert.Equal(content, attachment.Content);
    }

    [Fact]
    public async Task SkipsAttachmentTypesThatCarryNoBytes()
    {
        // An itemAttachment is a forwarded message and a referenceAttachment
        // is a cloud link. Asking either for $value fails, and that failure
        // would take down the whole message.
        var stub = new StubHttpMessageHandler()
            .WhenBytes("/$value", Encoding.UTF8.GetBytes("x"))
            .When("/attachments", HttpStatusCode.OK, """
                {"value":[
                  {"@odata.type":"#microsoft.graph.itemAttachment","id":"a1","name":"forwarded"},
                  {"@odata.type":"#microsoft.graph.referenceAttachment","id":"a2","name":"link"},
                  {"@odata.type":"#microsoft.graph.fileAttachment","id":"a3","name":"real.xml"}]}
                """);
        var (client, _) = Build(stub);

        var attachment = Assert.Single(await client.GetAttachmentsAsync("m1"));
        Assert.Equal("real.xml", attachment.Name);
    }

    [Fact]
    public async Task ReturnsNoAttachmentsRatherThanFailingForAMessageWithNone()
    {
        var (client, _) = Build(new StubHttpMessageHandler().When("/attachments", HttpStatusCode.OK, """{"value":[]}"""));
        Assert.Empty(await client.GetAttachmentsAsync("m1"));
    }

    // ---- folders ------------------------------------------------------------

    [Fact]
    public async Task UsesAWellKnownFolderNameWithoutLookingItUp()
    {
        var (client, stub) = Build(new StubHttpMessageHandler());

        Assert.Equal("Inbox", await client.EnsureFolderAsync("Inbox"));
        Assert.Empty(stub.Requests);
    }

    [Fact]
    public async Task FindsAnExistingFolder()
    {
        var stub = new StubHttpMessageHandler().When("/mailFolders?", HttpStatusCode.OK, """
            {"value":[{"id":"folder-123","displayName":"DMARC-Processed"}]}
            """);
        var (client, _) = Build(stub);

        Assert.Equal("folder-123", await client.EnsureFolderAsync("DMARC-Processed"));
    }

    [Fact]
    public async Task CreatesAFolderThatDoesNotExist()
    {
        var stub = new StubHttpMessageHandler()
            .When("/mailFolders?", HttpStatusCode.OK, """{"value":[]}""")
            .When("/mailFolders", HttpStatusCode.Created, """{"id":"new-folder","displayName":"DMARC-Quarantine"}""");
        var (client, _) = Build(stub);

        Assert.Equal("new-folder", await client.EnsureFolderAsync("DMARC-Quarantine"));
    }

    [Fact]
    public async Task LooksUpEachFolderOnlyOnce()
    {
        // A run touches the same three folders for every message.
        var stub = new StubHttpMessageHandler().When("/mailFolders?", HttpStatusCode.OK, """
            {"value":[{"id":"f1","displayName":"DMARC-Processed"}]}
            """);
        var (client, _) = Build(stub);

        await client.EnsureFolderAsync("DMARC-Processed");
        await client.EnsureFolderAsync("DMARC-Processed");
        await client.EnsureFolderAsync("DMARC-Processed");

        Assert.Single(stub.Requests);
    }

    [Fact]
    public async Task FindsAFolderWhoseNameHasAnApostropheWithoutCreatingAnother()
    {
        // The name used to go into a $filter, where a quote had to be doubled
        // or Graph refused the request. It is compared here now, so there is
        // nothing to escape - but the folder still has to be found rather than
        // made a second time.
        var stub = new StubHttpMessageHandler()
            .When("/mailFolders?", HttpStatusCode.OK, """{"value":[{"id":"f-bob","displayName":"Bob's Reports"}]}""")
            .When("/mailFolders", HttpStatusCode.Created, """{"id":"should-not-happen"}""");
        var (client, _) = Build(stub);

        Assert.Equal("f-bob", await client.EnsureFolderAsync("Bob's Reports"));
        Assert.DoesNotContain(stub.Requests, r => r.Method == HttpMethod.Post);
    }

    // ---- folders named to be read -------------------------------------------
    //
    // The live mailbox has Outlook rules filing reports into folders beside
    // Inbox whose names hold a literal backslash, DMARC\example.org. Graph
    // addresses a folder by id, so the name only matters once: when it is
    // turned into one. These are about that moment.

    /// <summary>
    /// The top of a mailbox holding a folder with a backslash in its name and
    /// every near miss a looser comparison could land on. JSON escapes the
    /// backslash; each name has exactly one.
    /// </summary>
    private const string TopLevel = """
        {"value":[
          {"id":"f-inbox","displayName":"Inbox"},
          {"id":"f-dmarc","displayName":"DMARC"},
          {"id":"f-bare","displayName":"example.org"},
          {"id":"f-old","displayName":"DMARC\\example.org.old"},
          {"id":"f-right","displayName":"DMARC\\example.org","childFolderCount":0,"totalItemCount":212},
          {"id":"f-other","displayName":"DMARC\\example.net"}]}
        """;

    [Fact]
    public async Task FindsAFolderWhoseNameHasABackslashByTheWholeName()
    {
        var stub = new StubHttpMessageHandler().When("/mailFolders?", HttpStatusCode.OK, TopLevel);
        var (client, _) = Build(stub);

        var folder = await client.FindFolderAsync(@"DMARC\example.org");

        Assert.NotNull(folder);
        Assert.Equal("f-right", folder.Id);
        Assert.Equal(@"DMARC\example.org", folder.Name);
        Assert.Equal(212, folder.TotalItemCount);
    }

    [Fact]
    public async Task MatchesTheNameIgnoringCaseAsOutlookDoes()
    {
        var (client, _) = Build(new StubHttpMessageHandler().When("/mailFolders?", HttpStatusCode.OK, TopLevel));

        Assert.Equal("f-right", (await client.FindFolderAsync(@"dmarc\EXAMPLE.org"))?.Id);
    }

    [Fact]
    public async Task ComparesTheNameHereRatherThanAskingGraphToFilterOnIt()
    {
        // A backslash inside a string the server parses is one character
        // nobody has checked it treats as itself. A comparison made here is a
        // promise this code can keep.
        var stub = new StubHttpMessageHandler().When("/mailFolders?", HttpStatusCode.OK, TopLevel);
        var (client, _) = Build(stub);

        await client.FindFolderAsync(@"DMARC\example.org");

        Assert.DoesNotContain(stub.Requests, r => r.RequestUri!.ToString().Contains("$filter", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NeverCreatesAFolderItWasOnlyAskedToFind()
    {
        // Created, an empty folder of that name is read every hour and looks
        // exactly like a quiet mailbox - and a --dry-run makes it in the live one.
        var stub = new StubHttpMessageHandler()
            .When("/mailFolders?", HttpStatusCode.OK, TopLevel)
            .When("/mailFolders", HttpStatusCode.Created, """{"id":"should-not-happen"}""");
        var (client, _) = Build(stub);

        Assert.Null(await client.FindFolderAsync(@"DMARC\missing.example"));
        Assert.Null(await client.FindFolderAsync("DMARCexample.org"));
        Assert.DoesNotContain(stub.Requests, r => r.Method == HttpMethod.Post);
    }

    [Fact]
    public async Task LooksForAFolderOnEveryPage()
    {
        // The default page is ten folders, and a mailbox sorted by rule easily
        // has more than that beside Inbox.
        var stub = new StubHttpMessageHandler()
            .When("/nextpage", HttpStatusCode.OK, """{"value":[{"id":"f-right","displayName":"DMARC\\example.org"}]}""")
            .When("/mailFolders?", HttpStatusCode.OK, """
                {"value":[{"id":"f-inbox","displayName":"Inbox"}],
                 "@odata.nextLink":"https://graph.microsoft.com/v1.0/nextpage"}
                """);
        var (client, _) = Build(stub);

        Assert.Equal("f-right", (await client.FindFolderAsync(@"DMARC\example.org"))?.Id);
    }

    [Fact]
    public async Task OneListingServesEveryFolderARunLooksUp()
    {
        // The three folders a run files into, and every folder it was asked
        // to read, are all top-level: one list answers them all.
        var stub = new StubHttpMessageHandler().When("/mailFolders?", HttpStatusCode.OK, """
            {"value":[
              {"id":"f-p","displayName":"DMARC-Processed"},
              {"id":"f-u","displayName":"DMARC-Unrecognized"},
              {"id":"f-q","displayName":"DMARC-Quarantine"},
              {"id":"f-1","displayName":"DMARC\\example.org"},
              {"id":"f-2","displayName":"DMARC\\example.net"}]}
            """);
        var (client, _) = Build(stub);

        await client.EnsureFolderAsync("DMARC-Processed");
        await client.EnsureFolderAsync("DMARC-Unrecognized");
        await client.EnsureFolderAsync("DMARC-Quarantine");
        Assert.Equal("f-1", (await client.FindFolderAsync(@"DMARC\example.org"))?.Id);
        Assert.Equal("f-2", (await client.FindFolderAsync(@"DMARC\example.net"))?.Id);

        Assert.Single(stub.Requests);
    }

    [Fact]
    public async Task FindsInboxByItsWellKnownNameWithoutLookingItUp()
    {
        // Addressable by name whatever the mailbox calls it on screen.
        var (client, stub) = Build(new StubHttpMessageHandler());

        var inbox = await client.FindFolderAsync("Inbox");

        Assert.Equal("Inbox", inbox?.Id);
        Assert.Empty(stub.Requests);
    }

    [Fact]
    public async Task ReadsMessagesFromTheFolderIdItIsGiven()
    {
        // No lookup on the way: the id is used as given. Looking a name up
        // again, somewhere it was not, is how rule-sorted reports once went
        // uncollected - and how an empty folder of the same name got made.
        var stub = new StubHttpMessageHandler().When("/messages", HttpStatusCode.OK, OneMessage);
        var (client, _) = Build(stub);

        var messages = new List<MailMessage>();
        await foreach (var m in client.GetMessagesAsync("AAMkADf-right=")) { messages.Add(m); }

        Assert.Single(messages);

        // Compared unescaped, as RequestsOldestFirst explains.
        var request = Assert.Single(stub.Requests);
        Assert.Contains("/mailFolders/AAMkADf-right=/messages",
            Uri.UnescapeDataString(request.RequestUri!.ToString()), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListsTheFoldersInsideAFolderById()
    {
        var stub = new StubHttpMessageHandler().When("/childFolders", HttpStatusCode.OK, """
            {"value":[{"id":"f-child","displayName":"example.org","childFolderCount":0,"totalItemCount":3}]}
            """);
        var (client, _) = Build(stub);

        var child = Assert.Single(await client.GetChildFoldersAsync("f-right"));

        Assert.Equal("f-child", child.Id);
        Assert.Equal("example.org", child.Name);
        Assert.Contains("/mailFolders/f-right/childFolders", Assert.Single(stub.Requests).RequestUri!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AChildFolderDoesNotTakeThePlaceOfATopLevelOneWithTheSameName()
    {
        // Children used to be remembered by name alongside top-level folders,
        // so listing Inbox's children could send a later lookup of a top-level
        // folder with the same name somewhere else entirely.
        var stub = new StubHttpMessageHandler()
            .When("/childFolders", HttpStatusCode.OK, """{"value":[{"id":"f-child","displayName":"DMARC\\example.org"}]}""")
            .When("/mailFolders?", HttpStatusCode.OK, TopLevel);
        var (client, _) = Build(stub);

        await client.GetChildFoldersAsync("Inbox");

        Assert.Equal("f-right", (await client.FindFolderAsync(@"DMARC\example.org"))?.Id);
    }

    [Fact]
    public async Task RecoversWhenAnotherRunCreatedTheFolderFirst()
    {
        // Two overlapping runs both try to create the folder. Losing that race
        // is normal and must not fail the run.
        var stub = new StubHttpMessageHandler()
            .WhenSequence("/mailFolders?",
                (HttpStatusCode.OK, """{"value":[]}"""),
                (HttpStatusCode.OK, """{"value":[{"id":"f-race","displayName":"DMARC-Processed"}]}"""))
            .When("/mailFolders", HttpStatusCode.Conflict, """{"error":{"code":"ErrorFolderExists"}}""");
        var (client, _) = Build(stub);

        Assert.Equal("f-race", await client.EnsureFolderAsync("DMARC-Processed"));
    }

    [Fact]
    public async Task IgnoresAFolderWhoseNameOnlyMatchesLoosely()
    {
        // Graph's filter comparison is case-insensitive and can return a
        // neighbour; taking the first result blindly would pick the wrong one.
        var stub = new StubHttpMessageHandler()
            .When("/mailFolders?", HttpStatusCode.OK, """
                {"value":[{"id":"wrong","displayName":"DMARC-Processed-Old"}]}
                """)
            .When("/mailFolders", HttpStatusCode.Created, """{"id":"right"}""");
        var (client, _) = Build(stub);

        Assert.Equal("right", await client.EnsureFolderAsync("DMARC-Processed"));
    }

    // ---- moving -------------------------------------------------------------

    [Fact]
    public async Task MovesAMessage()
    {
        var stub = new StubHttpMessageHandler().When("/move", HttpStatusCode.Created, """{"id":"m1"}""");
        var (client, _) = Build(stub);

        await client.MoveMessageAsync("m1", "folder-123");

        Assert.Contains("/move", stub.Requests[^1].RequestUri!.ToString(), StringComparison.Ordinal);
        Assert.Equal(HttpMethod.Post, stub.Requests[^1].Method);
    }

    // ---- failures must be loud and specific ---------------------------------

    [Fact]
    public async Task ExplainsAnAuthenticationFailureInTermsOfTheCertificate()
    {
        var stub = new StubHttpMessageHandler().When("/messages", HttpStatusCode.Unauthorized, """
            {"error":{"code":"InvalidAuthenticationToken","message":"Access token is empty."}}
            """);
        var (client, _) = Build(stub);

        var ex = await Assert.ThrowsAsync<GraphException>(async () =>
        {
            await foreach (var _ in client.GetMessagesAsync("Inbox")) { }
        });

        Assert.Contains("certificate", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
    }

    [Fact]
    public async Task ExplainsAForbiddenResponseInTermsOfPermissionAndAccessPolicy()
    {
        // The single most likely misconfiguration: permission granted but the
        // application access policy excludes the mailbox. That produces this
        // exact error, and nothing in Graph's own message says so.
        var stub = new StubHttpMessageHandler().When("/messages", HttpStatusCode.Forbidden, """
            {"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}
            """);
        var (client, _) = Build(stub);

        var ex = await Assert.ThrowsAsync<GraphException>(async () =>
        {
            await foreach (var _ in client.GetMessagesAsync("Inbox")) { }
        });

        Assert.Contains("Mail.ReadWrite", ex.Message, StringComparison.Ordinal);
        Assert.Contains("application access policy", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(Mailbox, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExplainsAMissingMailbox()
    {
        var stub = new StubHttpMessageHandler().When("/messages", HttpStatusCode.NotFound, """
            {"error":{"code":"ResourceNotFound","message":"Resource could not be discovered."}}
            """);
        var (client, _) = Build(stub);

        var ex = await Assert.ThrowsAsync<GraphException>(async () =>
        {
            await foreach (var _ in client.GetMessagesAsync("Inbox")) { }
        });

        Assert.Contains("could not find", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExplainsANonJsonResponseAsInterception()
    {
        // A proxy or captive portal returning an HTML login page. A bare JSON
        // parse error would send somebody hunting in the wrong place.
        var stub = new StubHttpMessageHandler().When("/messages", HttpStatusCode.OK, "<html>Sign in</html>", "text/html");
        var (client, _) = Build(stub);

        var ex = await Assert.ThrowsAsync<GraphException>(async () =>
        {
            await foreach (var _ in client.GetMessagesAsync("Inbox")) { }
        });

        Assert.Contains("proxy", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NeverReturnsAnEmptyResultForAFailedCall()
    {
        // The whole point. Zero messages must mean an empty mailbox, never a
        // misconfiguration, or an operator waits days for nothing.
        foreach (var status in new[]
        {
            HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden,
            HttpStatusCode.NotFound, HttpStatusCode.InternalServerError,
        })
        {
            var stub = new StubHttpMessageHandler().When("/messages", status, """{"error":{"code":"x"}}""");
            var (client, _) = Build(stub);

            await Assert.ThrowsAsync<GraphException>(async () =>
            {
                await foreach (var _ in client.GetMessagesAsync("Inbox")) { }
            });
        }
    }

    [Fact]
    public void RejectsConstructionWithoutAMailbox()
    {
        using var http = new HttpClient();
        Assert.Throws<ArgumentException>(() => new GraphMailboxClient(http, "  "));
        Assert.Throws<ArgumentNullException>(() => new GraphMailboxClient(null!, Mailbox));
    }
}
