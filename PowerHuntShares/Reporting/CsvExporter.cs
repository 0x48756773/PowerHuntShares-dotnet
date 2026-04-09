using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text;

namespace PowerHuntShares.Reporting;

/// <summary>
/// Writes generic lists of objects to CSV files.
/// Mirrors Export-Csv -NoTypeInformation used throughout Invoke-HuntSMBShares.
/// </summary>
public static class CsvExporter
{
    /// <summary>
    /// Writes a list of objects to a CSV file at the specified path.
    /// Column headers are derived from public property names (mirrors -NoTypeInformation).
    /// </summary>
    public static void Export<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)] T>(
        IEnumerable<T> items, string filePath)
    {
        var props = typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance);
        var sb = new StringBuilder();

        // Header row
        sb.AppendLine(string.Join(",", props.Select(p => QuoteCsvField(p.Name))));

        // Data rows
        foreach (var item in items)
        {
            sb.AppendLine(string.Join(",",
                props.Select(p => QuoteCsvField(p.GetValue(item)?.ToString() ?? string.Empty))));
        }

        File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
    }

    /// <summary>Wraps a CSV field in quotes and escapes embedded quotes.</summary>
    private static string QuoteCsvField(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return $"\"{value.Replace("\"", "\"\"")}\"";
        return value;
    }
}
