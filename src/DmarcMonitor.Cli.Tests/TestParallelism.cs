using Xunit;

// Same process-global SQLite connection pool the other suites serialise for,
// and the same ClearAllPools() in this one's teardown. See
// DmarcMonitor.Core.Tests/TestParallelism.cs for what goes wrong.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
