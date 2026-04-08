using System.Text.RegularExpressions;
using PowerHuntShares.Credentials.Models;

namespace PowerHuntShares.Credentials.Parsers;

/// <summary>
/// Extracts saved-session credentials from WinSCP.ini files.
/// Translates Get-PwWinSCPConfig (line 24417) from PowerHuntShares.psm1.
///
/// WinSCP stores passwords as an obfuscated hex string — this parser records
/// the raw encoded value in PasswordEncoded and leaves Password empty,
/// matching the original PS behaviour (line 24465: "Encrypted password in .ini").
/// </summary>
public class WinScpParser : IConfigParser
{
    public IReadOnlyList<string> FilePatterns => ["WinSCP.ini", "winscp.ini"];

    public IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        var results = new List<CredentialFinding>();
        string fileName = Path.GetFileName(filePath);

        try
        {
            string[] lines = File.ReadAllLines(filePath);

            // WinSCP.ini can contain multiple [Sessions\...] sections.
            // Process each section independently.
            string? currentSection = null;
            string? host = null, port = null, user = null, encPassword = null, keyFile = null;

            void FlushSession()
            {
                if (!string.IsNullOrEmpty(user) || !string.IsNullOrEmpty(encPassword))
                {
                    results.Add(new CredentialFinding
                    {
                        ComputerName = computerName,
                        ShareName = shareName,
                        UncFilePath = uncFilePath,
                        FileName = fileName,
                        Section = currentSection ?? "Sessions",
                        ObjectName = "NA",
                        TargetUrl = "NA",
                        TargetServer = host ?? "NA",
                        TargetPort = port ?? "NA",
                        Database = "NA",
                        Domain = "NA",
                        Username = user ?? string.Empty,
                        Password = string.Empty,           // stored encrypted below
                        PasswordEncoded = encPassword ?? "NA",
                        KeyFilePath = keyFile ?? "NA",
                        SourceParser = nameof(WinScpParser),
                    });
                }

                host = port = user = encPassword = keyFile = null;
            }

            foreach (string line in lines)
            {
                var sectionMatch = Regex.Match(line, @"^\[(.+)\]$");
                if (sectionMatch.Success)
                {
                    FlushSession();
                    currentSection = sectionMatch.Groups[1].Value;
                    continue;
                }

                // Key=Value lines — mirrors the foreach loop in Get-PwWinSCPConfig.
                if (Regex.Match(line, @"^HostName=(.*)") is { Success: true } m1)
                    host = m1.Groups[1].Value;
                else if (Regex.Match(line, @"^PortNumber=(.*)") is { Success: true } m2)
                    port = m2.Groups[1].Value;
                else if (Regex.Match(line, @"^UserName=(.*)") is { Success: true } m3)
                    user = m3.Groups[1].Value;
                else if (Regex.Match(line, @"^Password=(.*)") is { Success: true } m4)
                    encPassword = m4.Groups[1].Value;
                else if (Regex.Match(line, @"^PrivateKeyFile=(.*)") is { Success: true } m5)
                    keyFile = m5.Groups[1].Value;
            }

            FlushSession(); // flush the last section
        }
        catch { /* unreadable file */ }

        return results;
    }
}
