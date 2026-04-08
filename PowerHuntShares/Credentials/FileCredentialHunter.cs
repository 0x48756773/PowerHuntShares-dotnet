using PowerHuntShares.Credentials.Models;
using PowerHuntShares.Credentials.Parsers;
using PowerHuntShares.Shares.Models;

namespace PowerHuntShares.Credentials;

/// <summary>
/// Walks directory listings from accessible shares, routes each file to the
/// appropriate credential parser, and returns all findings.
///
/// This orchestrates all Get-Pw* calls that occur during the credential-hunting
/// phase of Invoke-HuntSMBShares (implicitly called via Invoke-FingerPrintShare).
/// </summary>
public class FileCredentialHunter
{
    private readonly int _threads;
    private readonly IReadOnlyList<IConfigParser> _parsers;

    // Map from lower-cased file name (or pattern root) → parser
    private readonly List<(string Pattern, IConfigParser Parser)> _patterns;

    public FileCredentialHunter(int threads = 20, IEnumerable<IConfigParser>? parsers = null)
    {
        _threads = threads;
        _parsers = parsers is not null
            ? parsers.ToList()
            : BuildDefaultParsers();

        _patterns = BuildPatternMap(_parsers);
    }

    /// <summary>
    /// Hunts for credentials across all supplied directory listing entries in parallel.
    /// </summary>
    public IReadOnlyList<CredentialFinding> Hunt(IEnumerable<DirectoryListingEntry> listings)
    {
        var findings = new System.Collections.Concurrent.ConcurrentBag<CredentialFinding>();
        var opts = new ParallelOptions { MaxDegreeOfParallelism = _threads };

        Parallel.ForEach(listings, opts, entry =>
        {
            if (!File.Exists(entry.FilePath))
                return;

            string fileName = Path.GetFileName(entry.FilePath);
            var parser = MatchParser(fileName);
            if (parser is null)
                return;

            try
            {
                string uncFilePath = Path.Combine(entry.SharePath, entry.FilePath
                    .Substring(entry.SharePath.Length).TrimStart('\\', '/'));

                var results = parser.Parse(entry.FilePath,
                    entry.ComputerName, entry.ShareName, uncFilePath);

                foreach (var f in results)
                    findings.Add(f);
            }
            catch { /* per-file errors are swallowed */ }
        });

        return [.. findings];
    }

    // ── Pattern routing ───────────────────────────────────────────────────────

    private IConfigParser? MatchParser(string fileName)
    {
        string lower = fileName.ToLowerInvariant();

        foreach (var (pattern, parser) in _patterns)
        {
            if (pattern.StartsWith('*'))
            {
                // Wildcard extension match: *.config → ends with .config
                string ext = pattern[1..]; // e.g. ".config"
                if (lower.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                    return parser;
            }
            else if (lower.Equals(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return parser;
            }
        }

        return null;
    }

    // ── Parser catalogue ──────────────────────────────────────────────────────

    private static IReadOnlyList<IConfigParser> BuildDefaultParsers() =>
    [
        new WebConfigParser(),
        new WinScpParser(),
        new PuttyParser(),
        new WordPressConfigParser(),
        new VncParser(),
        new UnattendParser(),
        new TomcatUsersParser(),
        new TnsNamesParser(),
        new SysprepParser(),
        new StandaloneXmlParser(),
        new SssdParser(),
        new SmbConfParser(),
        new SiteManagerParser(),
        new ShadowParser(),
        new ServerXmlParser(),
        new PureFtpParser(),
        new PhpIniParser(),
        new MySqlConfigParser(),
        new MachineConfigParser(),
        new Krb5ConfParser(),
        new JbossCliParser(),
        new HtpasswdParser(),
        new ContextXmlParser(),
        new JenkinsConfigParser(),
        new BootstrapIniParser(),
        new PgPassParser(),
        new GppParser(),
        new DtsxParser(),
        new RdpParser(),
        new PrivateKeyPathParser(),
        new CiscoConfigParser(),
        new GrubParser(),
        new NetrcParser(),
        new RemminaParser(),
        new RemminaPrefParser(),
        new DbvisParser(),
        new GitCredentialsParser(),
        new FetchmailrcParser(),
        new BaramundiParser(),
        new DbxDriverParser(),
        // GenericIniParser last — broad *.ini wildcard
        new GenericIniParser(),
    ];

    private static List<(string Pattern, IConfigParser Parser)> BuildPatternMap(
        IReadOnlyList<IConfigParser> parsers)
    {
        var map = new List<(string, IConfigParser)>();
        foreach (var parser in parsers)
            foreach (var pattern in parser.FilePatterns)
                map.Add((pattern.ToLowerInvariant(), parser));
        return map;
    }
}
