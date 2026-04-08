using System.Net;
using PowerHuntShares.Credentials;
using PowerHuntShares.Discovery;
using PowerHuntShares.Discovery.Models;
using PowerHuntShares.Reporting;
using PowerHuntShares.Shares;
using PowerHuntShares.Shares.Models;
using PowerHuntShares.Utilities;

namespace PowerHuntShares.Core;

/// <summary>
/// Top-level orchestrator.  Runs every phase of the scan in sequence, mirroring
/// the Begin / Process block of Invoke-HuntSMBShares in PowerHuntShares.psm1.
///
/// Phase order (matches the original PowerShell flow):
///   1. Validate output directory
///   2. Import or enumerate target computers
///   3. Ping sweep (optional)
///   4. TCP 445 port scan
///   5. SMB share enumeration
///   6. ACL enumeration
///   7. Excessive-privilege classification
///   8. Directory listing on accessible shares
///   9. Credential file hunting
///  10. Report generation
/// </summary>
public class HuntOrchestrator
{
    private readonly ScanOptions _opts;
    private ScanResults _results = new();

    // Sub-components — constructed once and reused across phases.
    private LdapEnumerator? _ldap;
    private PingScanner? _ping;
    private PortScanner? _ports;
    private ShareEnumerator? _shares;
    private AclEnumerator? _acls;
    private FileCredentialHunter? _creds;
    private LlmClient? _llm;

    // Output sub-directory created for this run (timestamped).
    private string _outputBase = string.Empty;
    private string _outputResults = string.Empty;

    public HuntOrchestrator(ScanOptions opts) => _opts = opts;

    // ── Public entry point ────────────────────────────────────────────────────

    public ScanResults Run()
    {
        PrintBanner();

        _results.StartTime = DateTime.Now;

        try
        {
            SetupOutputDirectory();
            InitComponents();
            TestLlmConnectivity();

            Log("Scan Start");

            Phase2_DiscoverComputers();
            Phase3_PingSweep();
            Phase4_PortScan();
            Phase5_EnumerateShares();
            Phase6_EnumerateAcls();
            Phase7_ClassifyRisk();
            Phase8_DirectoryListings();
            Phase9_CredentialHunting();

            Log("Scan Complete");

            Phase10_GenerateReports();
        }
        catch (OperationCanceledException)
        {
            Log("Scan aborted by user.");
        }
        finally
        {
            _results.EndTime = DateTime.Now;
            _llm?.Dispose();
        }

        PrintSummary();
        return _results;
    }

    // ── Phase implementations ─────────────────────────────────────────────────

    private void SetupOutputDirectory()
    {
        if (!Directory.Exists(_opts.OutputDirectory))
            Abort($"Output directory not found or not writable: {_opts.OutputDirectory}");

        string stamp = DateTime.Now.ToString("MMddyyyyHHmmss");
        _outputBase = Path.Combine(_opts.OutputDirectory, $"SmbShareHunt-{stamp}");
        _outputResults = Path.Combine(_outputBase, "Results");

        Directory.CreateDirectory(_outputBase);
        Directory.CreateDirectory(_outputResults);

        Log($"Output Directory: {_outputBase}");

        // Validate optional keyword file if provided.
        if (!string.IsNullOrEmpty(_opts.FileKeywordsPath) &&
            !File.Exists(_opts.FileKeywordsPath))
            Abort($"File keywords path not found: {_opts.FileKeywordsPath}");
    }

    private void InitComponents()
    {
        NetworkCredential? cred = null;
        if (!string.IsNullOrEmpty(_opts.Username) && !string.IsNullOrEmpty(_opts.Password))
            cred = new NetworkCredential(_opts.Username, _opts.Password);

        _ldap = new LdapEnumerator(_opts.DomainController, cred);
        _ping = new PingScanner(_opts.Threads, timeoutMs: 1000);
        _ports = new PortScanner(_opts.Threads, timeoutMs: _opts.ConnectionTimeoutSeconds * 1000);
        _shares = new ShareEnumerator(_opts.Threads, timeoutMs: _opts.ConnectionTimeoutSeconds * 1000);
        _acls = new AclEnumerator(_opts.Threads);
        _creds = new FileCredentialHunter(_opts.Threads);

        if (!string.IsNullOrEmpty(_opts.ApiKey) && !string.IsNullOrEmpty(_opts.Endpoint))
            _llm = new LlmClient(_opts.ApiKey, _opts.Endpoint);
    }

    private void TestLlmConnectivity()
    {
        if (_llm is null) return;

        Log("Testing LLM API connectivity…");
        bool ok = _llm.TestConnectivityAsync().GetAwaiter().GetResult();
        if (!ok)
            Log("LLM connectivity test failed — LLM queries will be skipped.");
        else
            Log("LLM API reachable.");
    }

    /// <summary>
    /// Phase 2: Import from host file or enumerate via LDAP.
    /// Mirrors lines 342–435 of Invoke-HuntSMBShares.
    /// </summary>
    private void Phase2_DiscoverComputers()
    {
        if (!string.IsNullOrEmpty(_opts.HostList))
        {
            Log($"Importing computer targets from {_opts.HostList}");
            if (!File.Exists(_opts.HostList))
                Abort($"Host list not found: {_opts.HostList}");

            _results.DomainComputers = File.ReadAllLines(_opts.HostList)
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .Select(l => new ComputerInfo { ComputerName = l.Trim() })
                .ToList();

            _results.TargetDomain = "SmbHunt";
            Log($"  {_results.DomainComputers.Count} systems will be targeted");
            return;
        }

        // LDAP enumeration path.
        Log("Discovering domain controller via LDAP…");
        var (dcHostname, domain) = _ldap!.DiscoverDomainController();
        _results.TargetDomain = domain;
        Log($"  Successful connection to domain controller: {dcHostname}");

        Log($"Performing LDAP query for computers associated with the {domain} domain");
        _results.DomainComputers = _ldap.GetDomainComputers().ToList();
        Log($"  {_results.DomainComputers.Count} computers found");
        CsvExporter.Export(_results.DomainComputers,
            Path.Combine(_outputResults, $"{domain}-Domain-Computers.csv"));

        Log("Querying AD site subnets…");
        _results.DomainSubnets = _ldap.GetDomainSubnets().ToList();
        Log($"  {_results.DomainSubnets.Count} subnets found");
        CsvExporter.Export(_results.DomainSubnets,
            Path.Combine(_outputResults, $"{domain}-Domain-Subnets.csv"));
    }

    /// <summary>
    /// Phase 3: Parallel ICMP ping sweep.
    /// Mirrors lines 442–480 of Invoke-HuntSMBShares.
    /// </summary>
    private void Phase3_PingSweep()
    {
        if (_opts.NoPing)
        {
            Log("Skipping ping scan (--no-ping).");
            _results.PingableComputers = _results.DomainComputers.ToList();
            return;
        }

        Log($"Pinging {_results.DomainComputers.Count} computers");
        _results.PingableComputers = _ping!.Scan(_results.DomainComputers).ToList();
        Log($"  {_results.PingableComputers.Count} computers responded to ping requests.");

        if (_results.PingableComputers.Count > 0)
            CsvExporter.Export(_results.PingableComputers,
                Path.Combine(_outputResults, $"{_results.TargetDomain}-Domain-Computers-Pingable.csv"));
    }

    /// <summary>
    /// Phase 4: TCP 445 port check on all computers (not just pingable ones,
    /// matching the original PS behaviour which scans $DomainComputers, not
    /// $ComputersPingable, for the port scan).
    /// Mirrors lines 487–544 of Invoke-HuntSMBShares.
    /// </summary>
    private void Phase4_PortScan()
    {
        Log($"Checking if TCP Port 445 is open on {_results.DomainComputers.Count} computers");
        _results.Computers445Open = _ports!.Scan(_results.DomainComputers).ToList();
        Log($"  {_results.Computers445Open.Count} computers have TCP port 445 open.");

        if (_results.Computers445Open.Count == 0)
            Abort("No computers with port 445 open found. Aborting.");

        CsvExporter.Export(_results.Computers445Open,
            Path.Combine(_outputResults, $"{_results.TargetDomain}-Domain-Computers-Open445.csv"));
    }

    /// <summary>
    /// Phase 5: Enumerate SMB shares on hosts with port 445 open.
    /// Mirrors lines 549–584 of Invoke-HuntSMBShares.
    /// </summary>
    private void Phase5_EnumerateShares()
    {
        Log($"Getting a list of SMB shares from {_results.Computers445Open.Count} computers");
        _results.AllShares = _shares!.EnumerateShares(_results.Computers445Open).ToList();
        Log($"  {_results.AllShares.Count} SMB shares were found.");

        if (_results.AllShares.Count == 0)
            Abort("No SMB shares found. Aborting.");

        CsvExporter.Export(_results.AllShares,
            Path.Combine(_outputResults, $"{_results.TargetDomain}-Shares-Inventory-All.csv"));
    }

    /// <summary>
    /// Phase 6: Enumerate share DACL entries and directory metadata.
    /// Mirrors lines 586–695 of Invoke-HuntSMBShares.
    /// </summary>
    private void Phase6_EnumerateAcls()
    {
        Log($"Getting share permissions from {_results.AllShares.Count} SMB shares");
        _results.AllShareAcls = _acls!.EnumerateAcls(_results.AllShares).ToList();
        Log($"  {_results.AllShareAcls.Count} share permissions were enumerated.");

        if (_results.AllShareAcls.Count == 0)
            Abort("No share ACLs could be enumerated. Aborting.");

        CsvExporter.Export(_results.AllShareAcls,
            Path.Combine(_outputResults, $"{_results.TargetDomain}-Shares-Inventory-All-ACL.csv"));
    }

    /// <summary>
    /// Phase 7: Classify excessive, readable, writable, and high-risk privileges.
    /// Mirrors lines 700–848 of Invoke-HuntSMBShares.
    /// </summary>
    private void Phase7_ClassifyRisk()
    {
        Log("Identifying potentially excessive share permissions");

        _results.ExcessiveShareAcls = HighRiskClassifier
            .GetExcessivePrivileges(_results.AllShareAcls).ToList();

        int excessiveShares = _results.ExcessiveShareAcls
            .Select(a => a.ShareName).Distinct().Count();
        int excessiveComputers = _results.ExcessiveShareAcls
            .Select(a => a.ComputerName).Distinct().Count();

        Log($"  {_results.ExcessiveShareAcls.Count} potentially excessive privileges on " +
            $"{excessiveShares} shares across {excessiveComputers} systems.");

        if (_results.ExcessiveShareAcls.Count == 0)
        {
            Log("  0 excessive privileges found — skipping downstream phases.");
            return;
        }

        CsvExporter.Export(_results.ExcessiveShareAcls,
            Path.Combine(_outputResults,
                $"{_results.TargetDomain}-Shares-Inventory-Excessive-Privileges.csv"));

        _results.AclsWithRead = HighRiskClassifier
            .GetReadableShares(_results.ExcessiveShareAcls).ToList();
        Log($"  {_results.AclsWithRead.Count} ACLs allow READ access.");

        _results.AclsWithWrite = HighRiskClassifier
            .GetWritableShares(_results.ExcessiveShareAcls).ToList();
        Log($"  {_results.AclsWithWrite.Count} ACLs allow WRITE access.");

        _results.HighRiskAcls = HighRiskClassifier
            .GetHighRiskShares(_results.ExcessiveShareAcls).ToList();
        Log($"  {_results.HighRiskAcls.Count} ACLs are on HIGH RISK shares.");

        if (_results.AclsWithRead.Count > 0)
            CsvExporter.Export(_results.AclsWithRead,
                Path.Combine(_outputResults,
                    $"{_results.TargetDomain}-Shares-Inventory-Excessive-Privileges-Read.csv"));

        if (_results.AclsWithWrite.Count > 0)
            CsvExporter.Export(_results.AclsWithWrite,
                Path.Combine(_outputResults,
                    $"{_results.TargetDomain}-Shares-Inventory-Excessive-Privileges-Write.csv"));
    }

    /// <summary>
    /// Phase 8: Recursive directory listing on accessible excessive-privilege shares.
    /// Mirrors lines 747–807 of Invoke-HuntSMBShares.
    /// </summary>
    private void Phase8_DirectoryListings()
    {
        var uniqueShares = _results.ExcessiveShareAcls
            .GroupBy(a => a.SharePath)
            .Select(g => g.First())
            .ToList();

        Log($"Getting directory listings from {uniqueShares.Count} SMB shares");
        Log($"  Targeting up to {_opts.DirLevel} nested directory levels");

        var listings = new System.Collections.Concurrent.ConcurrentBag<DirectoryListingEntry>();
        var opts = new ParallelOptions { MaxDegreeOfParallelism = _opts.Threads };

        Parallel.ForEach(uniqueShares, opts, acl =>
        {
            try
            {
                var di = new DirectoryInfo(acl.SharePath);
                foreach (var fsi in di.EnumerateFileSystemInfos("*",
                    new EnumerationOptions
                    {
                        RecurseSubdirectories = true,
                        MaxRecursionDepth = _opts.DirLevel,
                        IgnoreInaccessible = true,
                    }))
                {
                    // Skip Windows directories (mirrors the -notlike filter in PS).
                    if (fsi.FullName.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase) ||
                        fsi.FullName.Contains("\\WINNT\\", StringComparison.OrdinalIgnoreCase))
                        continue;

                    listings.Add(new DirectoryListingEntry
                    {
                        ComputerName = acl.ComputerName,
                        IpAddress = acl.IpAddress,
                        ShareName = acl.ShareName,
                        SharePath = acl.SharePath,
                        ShareDescription = acl.ShareDescription,
                        FilePath = fsi.FullName,
                    });
                }
            }
            catch { /* inaccessible share */ }
        });

        _results.DirectoryListings = [.. listings];
        Log($"  {_results.DirectoryListings.Count} files and folders were enumerated.");

        CsvExporter.Export(_results.DirectoryListings,
            Path.Combine(_outputResults,
                $"{_results.TargetDomain}-Shares-Directory-Listings-Depth-{_opts.DirLevel}.csv"));
    }

    /// <summary>
    /// Phase 9: Hunt credential files in the directory listings.
    /// </summary>
    private void Phase9_CredentialHunting()
    {
        if (_results.DirectoryListings.Count == 0) return;

        Log("Hunting credential files in directory listings…");
        _results.CredentialFindings = _creds!.Hunt(_results.DirectoryListings).ToList();
        Log($"  {_results.CredentialFindings.Count} credential findings.");

        if (_results.CredentialFindings.Count > 0)
            CsvExporter.Export(_results.CredentialFindings,
                Path.Combine(_outputResults,
                    $"{_results.TargetDomain}-Credential-Findings.csv"));
    }

    /// <summary>Phase 10: Build the HTML summary report.</summary>
    private void Phase10_GenerateReports()
    {
        BuildSummary();

        string reportPath = Path.Combine(_outputBase,
            $"{_results.TargetDomain}-Share-Hunt-Report.html");

        Log($"Generating HTML report: {reportPath}");
        new HtmlReportGenerator(_results, _opts).WriteReport(reportPath);
    }

    // ── Summary calculation ───────────────────────────────────────────────────

    private void BuildSummary()
    {
        var s = _results.Summary;
        s.TotalComputers = _results.DomainComputers.Count;
        s.PingableCount = _results.PingableComputers.Count;
        s.Port445OpenCount = _results.Computers445Open.Count;

        s.TotalShares = _results.AllShares.Count;
        s.TotalAcls = _results.AllShareAcls.Count;

        s.ExcessiveAclCount = _results.ExcessiveShareAcls.Count;
        s.SharesWithReadCount = _results.AclsWithRead
            .Select(a => a.SharePath).Distinct().Count();
        s.SharesWithWriteCount = _results.AclsWithWrite
            .Select(a => a.SharePath).Distinct().Count();
        s.HighRiskShareCount = _results.HighRiskAcls
            .Select(a => a.SharePath).Distinct().Count();

        s.ComputersWithExcessivePrivs = _results.ExcessiveShareAcls
            .Select(a => a.ComputerName).Distinct().Count();
        s.ComputersWithRead = _results.AclsWithRead
            .Select(a => a.ComputerName).Distinct().Count();
        s.ComputersWithWrite = _results.AclsWithWrite
            .Select(a => a.ComputerName).Distinct().Count();
        s.ComputersWithHighRisk = _results.HighRiskAcls
            .Select(a => a.ComputerName).Distinct().Count();

        s.NonDefaultShareCount = _results.AllShares.Count(s => !s.IsDefault);
        s.ComputersWithNonDefaultShares = _results.AllShares
            .Where(sh => !sh.IsDefault)
            .Select(sh => sh.ComputerName).Distinct().Count();
    }

    // ── Console output helpers ────────────────────────────────────────────────

    private void PrintBanner()
    {
        Console.WriteLine(" ===============================================================");
        Console.WriteLine(" POWERHUNTSHARES — SMB Share Hunter                            ");
        Console.WriteLine(" ===============================================================");
        Console.WriteLine("  o Determine current computer's domain");
        Console.WriteLine("  o Enumerate domain computers");
        Console.WriteLine("  o Check if computers respond to ping requests");
        Console.WriteLine("  o Filter for computers that have TCP 445 open and accessible");
        Console.WriteLine("  o Enumerate SMB shares");
        Console.WriteLine("  o Enumerate SMB share permissions");
        Console.WriteLine("  o Identify shares with potentially excessive privileges");
        Console.WriteLine("  o Identify shares that provide read or write access");
        Console.WriteLine("  o Identify shares that are high risk");
        Console.WriteLine("  o Generate HTML summary report and detailed CSV files");
        Console.WriteLine(" ---------------------------------------------------------------");
    }

    private void PrintSummary()
    {
        var s = _results.Summary;
        TimeSpan elapsed = _results.EndTime - _results.StartTime;

        Console.WriteLine();
        Console.WriteLine(" ---------------------------------------------------------------");
        Console.WriteLine(" SHARE REPORT SUMMARY");
        Console.WriteLine(" ---------------------------------------------------------------");
        Console.WriteLine($" [*] Domain: {_results.TargetDomain}");
        Console.WriteLine($" [*] Start time:  {_results.StartTime:MM/dd/yyyy HH:mm:ss}");
        Console.WriteLine($" [*] End time:    {_results.EndTime:MM/dd/yyyy HH:mm:ss}");
        Console.WriteLine($" [*] Run time:    {elapsed:hh\\:mm\\:ss}");
        Console.WriteLine();
        Console.WriteLine($" [*] COMPUTER SUMMARY");
        Console.WriteLine($" [*] - {s.TotalComputers} domain computers found.");
        Console.WriteLine($" [*] - {s.PingableCount} ({Pct(s.PingableCount, s.TotalComputers)}) responded to ping.");
        Console.WriteLine($" [*] - {s.Port445OpenCount} ({Pct(s.Port445OpenCount, s.TotalComputers)}) had TCP port 445 open.");
        Console.WriteLine($" [*] - {s.ComputersWithNonDefaultShares} ({Pct(s.ComputersWithNonDefaultShares, s.TotalComputers)}) had non-default shares.");
        Console.WriteLine($" [*] - {s.ComputersWithExcessivePrivs} ({Pct(s.ComputersWithExcessivePrivs, s.TotalComputers)}) had shares with excessive privileges.");
        Console.WriteLine($" [*] - {s.ComputersWithRead} ({Pct(s.ComputersWithRead, s.TotalComputers)}) had shares that allowed READ access.");
        Console.WriteLine($" [*] - {s.ComputersWithWrite} ({Pct(s.ComputersWithWrite, s.TotalComputers)}) had shares that allowed WRITE access.");
        Console.WriteLine($" [*] - {s.ComputersWithHighRisk} ({Pct(s.ComputersWithHighRisk, s.TotalComputers)}) had HIGH RISK shares.");
        Console.WriteLine();
        Console.WriteLine($" [*] SHARE SUMMARY");
        Console.WriteLine($" [*] - {s.TotalShares} shares were found.");
        Console.WriteLine($" [*] - {s.NonDefaultShareCount} ({Pct(s.NonDefaultShareCount, s.TotalShares)}) shares were non-default.");
        Console.WriteLine($" [*] - {s.ExcessiveAclCount} ACLs across shares had potentially excessive privileges.");
        Console.WriteLine($" [*] - {s.SharesWithReadCount} ({Pct(s.SharesWithReadCount, s.TotalShares)}) shares allowed READ access.");
        Console.WriteLine($" [*] - {s.SharesWithWriteCount} ({Pct(s.SharesWithWriteCount, s.TotalShares)}) shares allowed WRITE access.");
        Console.WriteLine($" [*] - {s.HighRiskShareCount} ({Pct(s.HighRiskShareCount, s.TotalShares)}) shares are HIGH RISK.");
        Console.WriteLine($" [*] - {_results.CredentialFindings.Count} credential findings.");
        Console.WriteLine(" ---------------------------------------------------------------");
        Console.WriteLine($" Output directory: {_outputBase}");
    }

    private static void Log(string message)
    {
        string time = DateTime.Now.ToString("MM/dd/yyyy HH:mm");
        Console.WriteLine($" [*][{time}] {message}");
    }

    private static void Abort(string message)
    {
        string time = DateTime.Now.ToString("MM/dd/yyyy HH:mm");
        Console.WriteLine($" [!][{time}] {message}");
        throw new OperationCanceledException(message);
    }

    private static string Pct(int part, int total) =>
        total == 0 ? "0.00%" : $"{(part * 100.0 / total):F2}%";
}
