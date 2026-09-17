using System.Reflection;

namespace DmarcMonitor.Core.Storage;

/// <summary>
/// The schema, carried inside the binary.
///
/// db/schema.sql is the source of truth and stays a readable file in the
/// repository, but a copy is compiled in so a published binary can create a
/// database on a machine that has nothing else on it. Without this the first
/// command anybody runs fails looking for a file that only exists in a git
/// checkout, which makes the whole tool feel unfinished at the exact moment
/// somebody is deciding whether it works.
/// </summary>
public static class DatabaseSchema
{
    private const string ResourceName = "schema.sql";

    /// <summary>The schema SQL compiled into this assembly.</summary>
    public static string Sql { get; } = Load();

    private static string Load()
    {
        var assembly = Assembly.GetExecutingAssembly();

        using var stream = assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException(
                $"'{ResourceName}' is not embedded in {assembly.GetName().Name}. "
                + "The build should include db/schema.sql as an EmbeddedResource.");

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
