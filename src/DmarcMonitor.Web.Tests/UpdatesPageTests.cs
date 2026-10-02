namespace DmarcMonitor.Web.Tests;

/// <summary>
/// The Updates page for an instance that has not been told where releases
/// live, which is every Windows download until somebody edits a file.
/// </summary>
public sealed class UpdatesPageTests : IClassFixture<SeededApp>
{
    private readonly SeededApp _app;

    public UpdatesPageTests(SeededApp app) => _app = app;

    [Fact]
    public async Task NotCheckingSaysWhichFileWhatTheValueLooksLikeAndThatItIsReadAtStart()
    {
        // The page used to name only the server's file, so somebody running the
        // download edited the right file, saw the same page, and had no way to
        // tell a wrong file from a missing restart.
        var html = await _app.CreateClient().GetStringAsync("/updates");

        Assert.Contains("Not checking for releases", html, StringComparison.Ordinal);
        Assert.Contains("owner/name", html, StringComparison.Ordinal);
        Assert.Contains("appsettings.json", html, StringComparison.Ordinal);
        Assert.Contains("read when it starts", html, StringComparison.Ordinal);
    }
}
