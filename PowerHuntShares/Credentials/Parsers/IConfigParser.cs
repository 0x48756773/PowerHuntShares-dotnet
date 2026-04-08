using PowerHuntShares.Credentials.Models;

namespace PowerHuntShares.Credentials.Parsers;

/// <summary>
/// Common contract for all config-file credential parsers.
/// Each parser corresponds to one Get-Pw* function in PowerHuntShares.psm1.
/// </summary>
public interface IConfigParser
{
    /// <summary>
    /// File name patterns this parser handles, e.g. "web.config", "*.ini".
    /// Used by FileCredentialHunter to route files to the correct parser.
    /// </summary>
    IReadOnlyList<string> FilePatterns { get; }

    /// <summary>
    /// Attempts to extract credentials from the supplied file.
    /// Returns an empty list when nothing relevant is found.
    /// </summary>
    IReadOnlyList<CredentialFinding> Parse(
        string filePath,
        string computerName,
        string shareName,
        string uncFilePath);
}
