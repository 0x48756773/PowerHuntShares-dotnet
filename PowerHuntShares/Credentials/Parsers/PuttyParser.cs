using System.Text.RegularExpressions;
using PowerHuntShares.Credentials.Models;

namespace PowerHuntShares.Credentials.Parsers;

/// <summary>
/// Extracts saved-session credentials from PuTTY registry export files (.reg).
/// Translates Get-PwPuttyRegFile (line 25410) from PowerHuntShares.psm1.
///
/// PuTTY exports are plain-text Windows registry files.  Sessions live under
/// HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\&lt;name&gt;.
/// </summary>
public class PuttyParser : IConfigParser
{
    public IReadOnlyList<string> FilePatterns => ["*.reg", "putty.reg"];

    public IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        var results = new List<CredentialFinding>();
        string fileName = Path.GetFileName(filePath);

        try
        {
            string[] lines = File.ReadAllLines(filePath);

            string? currentSession = null;
            string? host = null, port = null, user = null;

            void FlushSession()
            {
                if (!string.IsNullOrEmpty(host) || !string.IsNullOrEmpty(user))
                {
                    results.Add(new CredentialFinding
                    {
                        ComputerName = computerName,
                        ShareName = shareName,
                        UncFilePath = uncFilePath,
                        FileName = fileName,
                        Section = currentSession ?? "PuTTY Session",
                        ObjectName = "NA",
                        TargetUrl = "NA",
                        TargetServer = host ?? "NA",
                        TargetPort = port ?? "22",
                        Database = "NA",
                        Domain = "NA",
                        Username = user ?? string.Empty,
                        Password = string.Empty,
                        PasswordEncoded = "NA",
                        KeyFilePath = "NA",
                        SourceParser = nameof(PuttyParser),
                    });
                }

                host = port = user = null;
            }

            foreach (string line in lines)
            {
                // Registry section header — e.g.
                //   [HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\MySession]
                var sessionMatch = Regex.Match(line,
                    @"\[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\(.+)\]",
                    RegexOptions.IgnoreCase);

                if (sessionMatch.Success)
                {
                    FlushSession();
                    currentSession = Uri.UnescapeDataString(
                        sessionMatch.Groups[1].Value.Replace("%20", " "));
                    continue;
                }

                // "HostName"="hostname"
                if (Regex.Match(line, @"""HostName""\s*=\s*""([^""]+)""") is { Success: true } h)
                    host = h.Groups[1].Value;

                // "PortNumber"=dword:00000016  → decimal
                else if (Regex.Match(line, @"""PortNumber""\s*=\s*dword:([0-9a-fA-F]+)") is { Success: true } p)
                {
                    if (uint.TryParse(p.Groups[1].Value, System.Globalization.NumberStyles.HexNumber,
                        null, out uint portNum))
                        port = portNum.ToString();
                }

                // "UserName"="user"
                else if (Regex.Match(line, @"""UserName""\s*=\s*""([^""]+)""") is { Success: true } u)
                    user = u.Groups[1].Value;
            }

            FlushSession();
        }
        catch { /* unreadable file */ }

        return results;
    }
}
