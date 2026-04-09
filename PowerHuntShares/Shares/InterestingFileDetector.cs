using PowerHuntShares.Shares.Models;

namespace PowerHuntShares.Shares;

/// <summary>
/// Detects interesting files in directory listings by matching file names
/// against keyword patterns.  Mirrors the interesting-file detection in
/// Invoke-HuntSMBShares (PS lines 1688–1804).
///
/// Patterns use simple wildcard matching (* = any characters, ? = single char),
/// consistent with the PS -like operator used in the original module.
/// </summary>
public class InterestingFileDetector
{
    private readonly List<KeywordEntry> _keywords;

    public InterestingFileDetector(string? csvPath = null)
    {
        _keywords = !string.IsNullOrEmpty(csvPath) && File.Exists(csvPath)
            ? LoadCsv(csvPath)
            : GetDefaults();
    }

    /// <summary>
    /// Scans directory listings and returns files whose names match a keyword.
    /// </summary>
    public IReadOnlyList<InterestingFile> Detect(IReadOnlyList<DirectoryListingEntry> listings)
    {
        var results = new List<InterestingFile>();

        foreach (var entry in listings)
        {
            string fileName = Path.GetFileName(entry.FilePath);
            if (string.IsNullOrEmpty(fileName))
                continue;

            foreach (var kw in _keywords)
            {
                if (WildcardMatch(fileName, kw.Keyword))
                {
                    results.Add(new InterestingFile
                    {
                        ComputerName = entry.ComputerName,
                        ShareName = entry.ShareName,
                        SharePath = entry.SharePath,
                        FilePath = entry.FilePath,
                        FileName = fileName,
                        Category = kw.Category,
                        Keyword = kw.Keyword,
                    });
                    break; // one match per file is sufficient
                }
            }
        }

        return results;
    }

    // ── CSV loader ──────────────────────────────────────────────────────────

    /// <summary>
    /// Reads a CSV with at least Keyword and Category columns.
    /// Mirrors the PS Import-Csv + column validation (lines 1688–1701).
    /// </summary>
    private static List<KeywordEntry> LoadCsv(string path)
    {
        var entries = new List<KeywordEntry>();
        var lines = File.ReadAllLines(path);
        if (lines.Length == 0)
            return GetDefaults();

        // Parse header to find column indices.
        var header = ParseCsvLine(lines[0]);
        int kwIdx = -1, catIdx = -1;
        for (int i = 0; i < header.Length; i++)
        {
            if (header[i].Equals("Keyword", StringComparison.OrdinalIgnoreCase))
                kwIdx = i;
            else if (header[i].Equals("Category", StringComparison.OrdinalIgnoreCase))
                catIdx = i;
        }

        if (kwIdx < 0 || catIdx < 0)
            return GetDefaults(); // missing required columns — fall back

        for (int i = 1; i < lines.Length; i++)
        {
            var cols = ParseCsvLine(lines[i]);
            if (cols.Length <= Math.Max(kwIdx, catIdx))
                continue;

            string kw = cols[kwIdx].Trim();
            string cat = cols[catIdx].Trim();
            if (!string.IsNullOrEmpty(kw))
                entries.Add(new KeywordEntry(kw, cat));
        }

        return entries.Count > 0 ? entries : GetDefaults();
    }

    /// <summary>Minimal CSV line parser that handles quoted fields.</summary>
    private static string[] ParseCsvLine(string line)
    {
        var fields = new List<string>();
        bool inQuote = false;
        var current = new System.Text.StringBuilder();

        foreach (char c in line)
        {
            if (c == '"')
            {
                inQuote = !inQuote;
            }
            else if (c == ',' && !inQuote)
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }
        fields.Add(current.ToString());
        return fields.ToArray();
    }

    // ── Wildcard matching ───────────────────────────────────────────────────

    /// <summary>
    /// Simple wildcard match (case-insensitive).
    /// * matches zero or more characters, ? matches exactly one.
    /// </summary>
    private static bool WildcardMatch(string input, string pattern)
    {
        int iIdx = 0, pIdx = 0;
        int starI = -1, starP = -1;

        while (iIdx < input.Length)
        {
            if (pIdx < pattern.Length &&
                (char.ToLowerInvariant(pattern[pIdx]) == char.ToLowerInvariant(input[iIdx]) ||
                 pattern[pIdx] == '?'))
            {
                iIdx++;
                pIdx++;
            }
            else if (pIdx < pattern.Length && pattern[pIdx] == '*')
            {
                starI = iIdx;
                starP = pIdx;
                pIdx++;
            }
            else if (starP >= 0)
            {
                pIdx = starP + 1;
                iIdx = ++starI;
            }
            else
            {
                return false;
            }
        }

        while (pIdx < pattern.Length && pattern[pIdx] == '*')
            pIdx++;

        return pIdx == pattern.Length;
    }

    // ── Default keyword table ───────────────────────────────────────────────

    /// <summary>
    /// Built-in keyword patterns mirroring the $FileNamePatternsAll table
    /// from PowerHuntShares.psm1 (lines 1474–1685).
    /// </summary>
    private static List<KeywordEntry> GetDefaults() =>
    [
        // ── Secrets ─────────────────────────────────────────────────────
        new("web.config",                "Secret"),
        new("machine.config",            "Secret"),
        new("*.config",                  "Secret"),
        new("applicationHost.config",    "Secret"),
        new("php.ini",                   "Secret"),
        new("my.cnf",                    "Secret"),
        new("my.ini",                    "Secret"),
        new("*.pfx",                     "Secret"),
        new("*.p12",                     "Secret"),
        new("*.pem",                     "Secret"),
        new("*.cer",                     "Secret"),
        new("*.crt",                     "Secret"),
        new("*.key",                     "Secret"),
        new("*.ppk",                     "Secret"),
        new("id_rsa",                    "Secret"),
        new("id_dsa",                    "Secret"),
        new("id_ecdsa",                  "Secret"),
        new("id_ed25519",               "Secret"),
        new("authorized_keys",           "Secret"),
        new("known_hosts",               "Secret"),
        new("*.kdb",                     "Secret"),
        new("*.kdbx",                    "Secret"),
        new("KeePass.config.xml",        "Secret"),
        new("*.rdp",                     "Secret"),
        new("*.rdg",                     "Secret"),
        new("*.remmina",                 "Secret"),
        new("remmina.pref",              "Secret"),
        new("*.vnc",                     "Secret"),
        new("vnc.ini",                   "Secret"),
        new("ultravnc.ini",              "Secret"),
        new("*.pcf",                     "Secret"),
        new("unattend.xml",              "Secret"),
        new("unattend.txt",              "Secret"),
        new("unattended.xml",            "Secret"),
        new("sysprep.xml",               "Secret"),
        new("sysprep.inf",               "Secret"),
        new("*.gpg",                     "Secret"),
        new("*.asc",                     "Secret"),
        new("*.pgp",                     "Secret"),
        new(".pgpass",                    "Secret"),
        new(".netrc",                     "Secret"),
        new(".git-credentials",           "Secret"),
        new(".fetchmailrc",              "Secret"),
        new(".htpasswd",                  "Secret"),
        new("*.sitemanager.xml",         "Secret"),
        new("sitemanager.xml",           "Secret"),
        new("recentservers.xml",         "Secret"),
        new("filezilla.xml",             "Secret"),
        new("winscp.ini",                "Secret"),
        new("WinSCP.ini",                "Secret"),
        new("tomcat-users.xml",          "Secret"),
        new("server.xml",                "Secret"),
        new("context.xml",               "Secret"),
        new("standalone.xml",            "Secret"),
        new("jboss-cli.xml",             "Secret"),
        new("tnsnames.ora",              "Secret"),
        new("sqlnet.ora",                "Secret"),
        new("Groups.xml",                "Secret"),
        new("ScheduledTasks.xml",        "Secret"),
        new("Services.xml",              "Secret"),
        new("DataSources.xml",           "Secret"),
        new("Drives.xml",                "Secret"),
        new("Printers.xml",              "Secret"),
        new("bootstrap.ini",             "Secret"),
        new("krb5.conf",                 "Secret"),
        new("sssd.conf",                 "Secret"),
        new("smb.conf",                  "Secret"),
        new("grub.cfg",                  "Secret"),
        new("pure-ftpd.passwd",          "Secret"),
        new("shadow",                    "Secret"),
        new("passwd",                    "Secret"),
        new("dbvis.xml",                 "Secret"),
        new("*.dtsx",                    "Secret"),
        new("*.env",                     "Secret"),
        new(".env",                      "Secret"),
        new(".env.*",                    "Secret"),
        new("credentials",               "Secret"),
        new("credentials.xml",           "Secret"),
        new("credentials.json",          "Secret"),
        new("credentials.yaml",          "Secret"),
        new("credentials.yml",           "Secret"),
        new("secrets.json",              "Secret"),
        new("secrets.yaml",              "Secret"),
        new("secrets.yml",               "Secret"),
        new("vault.json",                "Secret"),
        new("vault.yaml",                "Secret"),
        new("appsettings.json",          "Secret"),
        new("appsettings.*.json",        "Secret"),
        new("connection*.config",        "Secret"),
        new("*.connection",              "Secret"),
        new("*.dsn",                     "Secret"),
        new("odbc.ini",                  "Secret"),
        new("odbcinst.ini",              "Secret"),

        // ── Sensitive ───────────────────────────────────────────────────
        new("*password*",                "Sensitive"),
        new("*passwd*",                  "Sensitive"),
        new("*credential*",             "Sensitive"),
        new("*secret*",                  "Sensitive"),
        new("*cpassword*",              "Sensitive"),
        new("*token*",                   "Sensitive"),
        new("*api_key*",                "Sensitive"),
        new("*apikey*",                  "Sensitive"),
        new("*account*",                "Sensitive"),
        new("*login*",                   "Sensitive"),
        new("*logon*",                   "Sensitive"),
        new("*access*",                  "Sensitive"),

        // ── Scripts ─────────────────────────────────────────────────────
        new("*.ps1",                     "Script"),
        new("*.psm1",                    "Script"),
        new("*.psd1",                    "Script"),
        new("*.bat",                     "Script"),
        new("*.cmd",                     "Script"),
        new("*.vbs",                     "Script"),
        new("*.js",                      "Script"),
        new("*.sh",                      "Script"),
        new("*.py",                      "Script"),
        new("*.pl",                      "Script"),
        new("*.rb",                      "Script"),

        // ── Backup ──────────────────────────────────────────────────────
        new("*.bak",                     "Backup"),
        new("*.old",                     "Backup"),
        new("*.orig",                    "Backup"),
        new("*.backup",                  "Backup"),
        new("*.bkp",                     "Backup"),
        new("*.tmp",                     "Backup"),
        new("*.temp",                    "Backup"),
        new("*.copy",                    "Backup"),
        new("NTDS.dit",                  "Backup"),
        new("SAM",                       "Backup"),
        new("SYSTEM",                    "Backup"),
        new("SECURITY",                  "Backup"),

        // ── Database ────────────────────────────────────────────────────
        new("*.sql",                     "Database"),
        new("*.sqlite",                  "Database"),
        new("*.sqlite3",                "Database"),
        new("*.db",                      "Database"),
        new("*.mdb",                     "Database"),
        new("*.accdb",                   "Database"),
        new("*.mdf",                     "Database"),
        new("*.ldf",                     "Database"),
        new("*.sdf",                     "Database"),

        // ── Binaries ────────────────────────────────────────────────────
        new("*.exe",                     "Binary"),
        new("*.dll",                     "Binary"),
        new("*.msi",                     "Binary"),
        new("*.msp",                     "Binary"),

        // ── System images ───────────────────────────────────────────────
        new("*.iso",                     "SystemImage"),
        new("*.img",                     "SystemImage"),
        new("*.wim",                     "SystemImage"),
        new("*.vhd",                     "SystemImage"),
        new("*.vhdx",                    "SystemImage"),
        new("*.vmdk",                    "SystemImage"),
        new("*.ova",                     "SystemImage"),
        new("*.ovf",                     "SystemImage"),
    ];

    private sealed record KeywordEntry(string Keyword, string Category);
}
