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
    public async Task NotCheckingSaysWhichFileWhatTheValueLooksLikeAndWhatToDoIfSavingIsNotEnough()
    {
        // The page used to name only the server's file, so somebody running the
        // download edited the right file, saw the same page, and had no way to
        // tell a wrong file from one that had not been picked up.
        var html = await _app.CreateClient().GetStringAsync("/updates");

        Assert.Contains("Not checking for releases", html, StringComparison.Ordinal);
        Assert.Contains("owner/name", html, StringComparison.Ordinal);
        Assert.Contains("appsettings.json", html, StringComparison.Ordinal);
        Assert.Contains("restart the application", html, StringComparison.Ordinal);

        // Not the claim this page once made. The file is watched, so a saved
        // value is picked up without a restart, and saying it was not sent
        // people to restart a service that did not need it.
        Assert.DoesNotContain("saving the file is not enough", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("read when it starts", html, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Installing is not offered here, and the page says what to do instead for
    /// the way this copy is run: a zip on Windows is updated by downloading the
    /// new zip, anything else by installing the update agent. Which of the two
    /// is asked of it is decided by where it runs, so the assertion is too.
    /// </summary>
    [Fact]
    public async Task SaysHowToUpdateForTheWayThisCopyIsRun()
    {
        var html = await _app.CreateClient().GetStringAsync("/updates");

        if (OperatingSystem.IsWindows())
        {
            Assert.Contains("DMARC-Monitor-Windows.zip", html, StringComparison.Ordinal);
            Assert.Contains("dmarc-clients", html, StringComparison.Ordinal);
            Assert.DoesNotContain("install-update-agent.sh", html, StringComparison.Ordinal);
        }
        else
        {
            Assert.Contains("install-update-agent.sh", html, StringComparison.Ordinal);
            Assert.DoesNotContain("DMARC-Monitor-Windows.zip", html, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The statement above is true, and this is the proof: the page reads the
    /// setting each time it is drawn, from a configuration that reloads when
    /// its file is saved.
    /// </summary>
    [Fact]
    public async Task ASettingSavedToTheFileIsPickedUpWithoutARestart()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"dmarc-reload-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);

        try
        {
            var file = Path.Combine(directory, "appsettings.json");
            await File.WriteAllTextAsync(file, "{}");

            // Built the way Program.cs builds it: the framework's defaults, which
            // watch appsettings.json.
            var builder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder(
                new Microsoft.AspNetCore.Builder.WebApplicationOptions { ContentRootPath = directory });
            var configuration = builder.Configuration;

            Assert.True(string.IsNullOrWhiteSpace(configuration["Updates:Repository"]));

            await File.WriteAllTextAsync(file, "{ \"Updates\": { \"Repository\": \"owner/name\" } }");

            // A file watcher tells the framework on its own schedule.
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (string.IsNullOrWhiteSpace(configuration["Updates:Repository"]) && DateTime.UtcNow < deadline)
            {
                await Task.Delay(50);
            }

            Assert.Equal("owner/name", configuration["Updates:Repository"]);
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }
    }
}
