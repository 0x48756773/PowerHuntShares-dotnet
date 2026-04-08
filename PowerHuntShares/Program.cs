using PowerHuntShares.Core;

// ─────────────────────────────────────────────────────────────────────────────
// PowerHuntShares — C# port of PowerHuntShares.psm1 by Scott Sutherland, NetSPI
// License: 3-clause BSD  |  Version: 2.1.1
// ─────────────────────────────────────────────────────────────────────────────

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("[!] PowerHuntShares requires Windows " +
        "(Netapi32/advapi32 P/Invoke, System.DirectoryServices).");
    Environment.Exit(1);
}

if (args.Length == 0 || HasFlag(args, "--help") || HasFlag(args, "-h"))
{
    PrintHelp();
    Environment.Exit(0);
}

ScanOptions opts;
try
{
    opts = ParseArgs(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[!] {ex.Message}");
    Console.Error.WriteLine("    Run with --help for usage.");
    Environment.Exit(1);
    return;
}

try
{
    var orchestrator = new HuntOrchestrator(opts);
    orchestrator.Run();
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[!] Fatal error: {ex.Message}");
    if (opts.ShowErrors)
        Console.Error.WriteLine(ex);
    Environment.Exit(2);
}

// ── Argument parser ───────────────────────────────────────────────────────────

static ScanOptions ParseArgs(string[] args)
{
    var opts = new ScanOptions();

    for (int i = 0; i < args.Length; i++)
    {
        string a = args[i];
        switch (a)
        {
            case "-u":
            case "--username":          opts.Username               = Next(args, ref i, a); break;
            case "-p":
            case "--password":          opts.Password               = Next(args, ref i, a); break;
            case "-d":
            case "--domain-controller": opts.DomainController       = Next(args, ref i, a); break;
            case "-t":
            case "--threads":           opts.Threads                = NextInt(args, ref i, a); break;
            case "-o":
            case "--output":            opts.OutputDirectory        = Next(args, ref i, a); break;
            case "--host-list":         opts.HostList               = Next(args, ref i, a); break;
            case "--sample-sum":        opts.SampleSum              = NextInt(args, ref i, a); break;
            case "--timeout":           opts.ConnectionTimeoutSeconds = NextInt(args, ref i, a); break;
            case "--share-creation-days": opts.ShareCreationDays    = NextInt(args, ref i, a); break;
            case "--last-access-days":  opts.LastAccessDays         = NextInt(args, ref i, a); break;
            case "--last-mod-days":     opts.LastModDays            = NextInt(args, ref i, a); break;
            case "--dir-level":         opts.DirLevel               = NextInt(args, ref i, a); break;
            case "--file-keywords":     opts.FileKeywordsPath       = Next(args, ref i, a); break;
            case "--api-key":           opts.ApiKey                 = Next(args, ref i, a); break;
            case "--endpoint":          opts.Endpoint               = Next(args, ref i, a); break;
            case "--export-findings":   opts.ExportFindings         = true; break;
            case "--export-nova":       opts.ExportNova             = true; break;
            case "--no-ping":           opts.NoPing                 = true; break;
            case "--show-errors":       opts.ShowErrors             = true; break;
            case "--suppress-timeline": opts.SuppressTimelineReport = true; break;
            default:
                throw new ArgumentException($"Unknown argument: {a}");
        }
    }

    if (string.IsNullOrWhiteSpace(opts.OutputDirectory))
        throw new ArgumentException("--output / -o is required.");

    return opts;
}

static string Next(string[] args, ref int i, string flag)
{
    if (i + 1 >= args.Length || args[i + 1].StartsWith('-'))
        throw new ArgumentException($"{flag} requires a value.");
    return args[++i];
}

static int NextInt(string[] args, ref int i, string flag)
{
    string val = Next(args, ref i, flag);
    if (!int.TryParse(val, out int n))
        throw new ArgumentException($"{flag} requires an integer value, got: {val}");
    return n;
}

static bool HasFlag(string[] args, string flag) =>
    Array.Exists(args, a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));

// ── Help text ─────────────────────────────────────────────────────────────────

static void PrintHelp()
{
    Console.WriteLine("""
        PowerHuntShares 2.1.1 — SMB Share Hunter (C# port of PowerHuntShares.psm1 by NetSPI)

        USAGE
          PowerHuntShares.exe -o <output-dir> [options]

        REQUIRED
          -o, --output <dir>              Directory to write CSV and HTML output files

        AUTHENTICATION
          -u, --username <domain\user>    Domain user (defaults to current user)
          -p, --password <password>       Domain password
          -d, --domain-controller <host>  Domain controller hostname or IP

        TARGETING
              --host-list <file>          File with target hostnames (one per line); skips AD
              --no-ping                   Skip ICMP sweep, go straight to TCP 445 checks

        TUNING
          -t, --threads <n>               Concurrent tasks (default: 20)
              --timeout <sec>             Per-host connection timeout (default: 15)
              --dir-level <n>             Directory listing depth (default: 3)
              --sample-sum <n>            Summary sample size (default: 200)
              --share-creation-days <n>   Recent-share threshold in days (default: 90)
              --last-access-days <n>      Last-accessed threshold in days (default: 90)
              --last-mod-days <n>         Last-modified threshold in days (default: 90)
              --file-keywords <csv>       CSV file with interesting-file keywords

        OUTPUT
              --export-findings           Export results to CSV files
              --export-nova               Export in NOVA finding format
              --suppress-timeline         Omit timeline section from HTML report

        LLM (OPTIONAL)
              --api-key <key>             API key for LLM share fingerprinting
              --endpoint <url>            OpenAI-compatible endpoint URL

        DIAGNOSTICS
              --show-errors               Print per-host errors to console

        EXAMPLES
          PowerHuntShares.exe -o C:\temp\output
          PowerHuntShares.exe -o C:\temp\output --host-list hosts.txt --threads 50
          PowerHuntShares.exe -o C:\temp\output -u DOMAIN\user -p Password1 -d dc1.domain.local
        """);
}
