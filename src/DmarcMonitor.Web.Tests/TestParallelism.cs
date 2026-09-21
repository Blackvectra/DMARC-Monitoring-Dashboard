using Xunit;

// The same process-global SQLite connection pool the Core tests serialise
// for, and the same ClearAllPools() in each fixture's teardown. See
// DmarcMonitor.Core.Tests/TestParallelism.cs for what goes wrong.
//
// These also stand up a WebApplicationFactory apiece, so running them one at
// a time keeps two applications from sharing a data-protection key ring and a
// database file by accident.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
