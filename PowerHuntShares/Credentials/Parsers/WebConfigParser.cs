using System.Text.RegularExpressions;
using System.Xml.Linq;
using PowerHuntShares.Credentials.Models;

namespace PowerHuntShares.Credentials.Parsers;

/// <summary>
/// Extracts credentials from ASP.NET web.config / app.config files.
/// Translates Get-PwWebConfig (line 24238) from PowerHuntShares.psm1.
///
/// Targets:
///   • connectionStrings — server, port, username, password, database
///   • appSettings — keys containing "password", "user", "pwd", "pass"
/// </summary>
public class WebConfigParser : IConfigParser
{
    public IReadOnlyList<string> FilePatterns => ["web.config", "app.config", "*.config"];

    public IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        var results = new List<CredentialFinding>();
        string fileName = Path.GetFileName(filePath);

        try
        {
            XDocument doc = XDocument.Load(filePath);

            // ── connectionStrings ──────────────────────────────────────────
            foreach (var add in doc.Descendants("connectionStrings").Elements("add"))
            {
                string connStr = (string?)add.Attribute("connectionString") ?? string.Empty;
                string name = (string?)add.Attribute("name") ?? string.Empty;
                string provider = (string?)add.Attribute("providerName") ?? string.Empty;

                ParseConnectionString(connStr, out string server, out string port,
                    out string database, out string user, out string password);

                if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(password))
                {
                    results.Add(Build(computerName, shareName, uncFilePath, fileName,
                        section: $"ConnectionStrings ({provider})",
                        objectName: name,
                        targetServer: server,
                        targetPort: port,
                        database: database,
                        username: user,
                        password: password));
                }
            }

            // ── appSettings ────────────────────────────────────────────────
            var appSettings = doc.Descendants("appSettings")
                                 .Elements("add")
                                 .ToDictionary(
                                     e => ((string?)e.Attribute("key") ?? string.Empty).ToLowerInvariant(),
                                     e => (string?)e.Attribute("value") ?? string.Empty);

            string appUser = FindValue(appSettings, "username", "user", "userid");
            string appPass = FindValue(appSettings, "password", "pwd", "pass");

            if (!string.IsNullOrEmpty(appUser) && !string.IsNullOrEmpty(appPass))
            {
                results.Add(Build(computerName, shareName, uncFilePath, fileName,
                    section: "appSettings",
                    username: appUser,
                    password: appPass));
            }
        }
        catch
        {
            // Not a valid XML config — skip.
        }

        return results;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Parses a connection string for server, port, database, user, password.
    /// Mirrors the regex chain in Get-PwWebConfig (lines 24308–24330).
    /// </summary>
    private static void ParseConnectionString(string cs,
        out string server, out string port, out string database,
        out string user, out string password)
    {
        server = database = user = password = port = string.Empty;

        // PostgreSQL-style: Host=…;Port=…;Username=…;Password=…
        var pg = Regex.Match(cs,
            @"Host\s*=\s*([^;]+).*?Port\s*=\s*(\d+).*?Username\s*=\s*([^;]+).*?Password\s*=\s*([^;]+)",
            RegexOptions.IgnoreCase);
        if (pg.Success)
        {
            server = pg.Groups[1].Value.Trim();
            port = pg.Groups[2].Value.Trim();
            user = pg.Groups[3].Value.Trim();
            password = pg.Groups[4].Value.Trim();
            return;
        }

        // SQL Server-style: Server=…  or  Data Source=…,port
        var srv = Regex.Match(cs, @"(?:Server|Data Source)\s*=\s*([^;,]+)(?:,(\d+))?",
            RegexOptions.IgnoreCase);
        if (srv.Success)
        {
            server = srv.Groups[1].Value.Trim();
            port = srv.Groups[2].Value.Trim();
        }

        var db = Regex.Match(cs, @"(?:Initial Catalog|Database)\s*=\s*([^;]+)",
            RegexOptions.IgnoreCase);
        if (db.Success) database = db.Groups[1].Value.Trim();

        var uid = Regex.Match(cs, @"User\s*Id\s*=\s*([^;]+)", RegexOptions.IgnoreCase);
        if (uid.Success) user = uid.Groups[1].Value.Trim();

        var pwd = Regex.Match(cs, @"Password\s*=\s*([^;]+)", RegexOptions.IgnoreCase);
        if (pwd.Success) password = pwd.Groups[1].Value.Trim();
    }

    private static string FindValue(Dictionary<string, string> dict, params string[] keys)
    {
        foreach (var key in keys)
            if (dict.TryGetValue(key, out var val) && !string.IsNullOrEmpty(val))
                return val;
        return string.Empty;
    }

    private static CredentialFinding Build(
        string computerName, string shareName, string uncFilePath, string fileName,
        string section = "NA", string objectName = "NA",
        string targetUrl = "NA", string targetServer = "NA", string targetPort = "NA",
        string database = "NA", string domain = "NA",
        string username = "", string password = "")
        => new()
        {
            ComputerName = computerName,
            ShareName = shareName,
            UncFilePath = uncFilePath,
            FileName = fileName,
            Section = section,
            ObjectName = objectName,
            TargetUrl = targetUrl,
            TargetServer = targetServer,
            TargetPort = targetPort,
            Database = database,
            Domain = domain,
            Username = username,
            Password = password,
            SourceParser = nameof(WebConfigParser),
        };
}
