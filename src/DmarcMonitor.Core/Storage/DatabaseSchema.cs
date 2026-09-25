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
    /// <summary>The organization's database: db/schema.sql.</summary>
    public static string Sql { get; } = Load("schema.sql");

    /// <summary>One client's own file: db/client-schema.sql.</summary>
    public static string ClientSql { get; } = Load("client-schema.sql");

    private static string Load(string resourceName)
    {
        var assembly = Assembly.GetExecutingAssembly();

        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException(
                $"'{resourceName}' is not embedded in {assembly.GetName().Name}. "
                + $"The build should include db/{resourceName} as an EmbeddedResource.");

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
