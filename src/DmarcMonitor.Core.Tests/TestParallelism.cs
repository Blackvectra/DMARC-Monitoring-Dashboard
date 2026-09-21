using Xunit;

// Thirteen test classes here put a SQLite database in a temp file, and every
// one of them calls SqliteConnection.ClearAllPools() when it disposes, to let
// Windows delete the file afterwards.
//
// That call is process-global. It disposes every pooled connection in the
// process, not this class's - including the handle another test class has at
// that moment taken from the pool and is still opening. The victim then fails
// inside SqliteConnection.Open(), with ObjectDisposedException naming a
// SQLitePCL.sqlite3 it never touched, in a test that has nothing to do with
// whichever class was tearing down.
//
// It surfaced as one test in eleven hundred failing on a CI run, on a pull
// request that changed a PowerShell script and no C# at all. Nothing in the
// product calls ClearAllPools; only these teardowns do. Tests that share a
// process-global resource cannot run concurrently, so they no longer do.
//
// The cost, measured: the Core suite goes from about four and a half seconds
// to about eleven, and the web suite from one to two. Both are still far
// inside the time the build itself takes, and a suite that passes slowly
// beats one that fails once a fortnight for a reason nobody can reproduce.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
