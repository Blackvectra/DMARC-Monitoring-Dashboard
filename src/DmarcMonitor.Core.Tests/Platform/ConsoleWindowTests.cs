using DmarcMonitor.Core.Platform;

namespace DmarcMonitor.Core.Tests.Platform;

/// <summary>
/// The rule this has to obey everywhere, and the one that would be expensive
/// to get wrong: a pause intended for a person at a keyboard must never
/// happen anywhere else.
///
/// Holding a console open is the right thing when Explorer created the window
/// and is about to destroy it with the answer still in it. It is the wrong
/// thing in every other place this code runs - a systemd unit, a scheduled
/// task, a CI step, a shell pipeline, an ingest run at three in the morning -
/// where it would not be a nuisance but a hang, and a hang in a timer is a
/// collector that silently stops.
/// </summary>
public sealed class ConsoleWindowTests
{
    [Fact]
    public async Task HoldingOpenReturnsImmediatelyWhenNobodyIsWatching()
    {
        // A test process never owns its console: the runner is attached to it
        // on every platform, and on Linux the check is false before it looks.
        var returned = Task.Run(() => ConsoleWindow.HoldOpen("this must not wait"));

        var first = await Task.WhenAny(returned, Task.Delay(TimeSpan.FromSeconds(10)));

        Assert.True(
            ReferenceEquals(first, returned),
            "HoldOpen blocked in a process with no interactive console - this would hang CI and every timer");
    }

    [Fact]
    public void IsNotOursWhenARunnerIsAttached()
    {
        // The test host is a second process on this console, so whatever the
        // platform, the answer here is no. On Linux it is no because the
        // question is only ever asked about a Windows desktop.
        Assert.False(ConsoleWindow.BelongsToThisProcess());
    }

    [Fact]
    public void AsksTheSameQuestionTwiceAndGetsTheSameAnswer()
    {
        // It is called on the exit path of every command, so it has to be
        // cheap and it has to be stable. A P/Invoke that failed the second
        // time would turn a clean exit into a crash.
        Assert.Equal(ConsoleWindow.BelongsToThisProcess(), ConsoleWindow.BelongsToThisProcess());
    }
}
