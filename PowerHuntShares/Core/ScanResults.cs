using PowerHuntShares.Credentials.Models;
using PowerHuntShares.Discovery.Models;
using PowerHuntShares.Shares.Models;

namespace PowerHuntShares.Core;

/// <summary>
/// Aggregated results produced by HuntOrchestrator. Mirrors all the
/// $DomainComputers, $AllSMBShares, $ShareACLs, … variables in Invoke-HuntSMBShares.
/// </summary>
public class ScanResults
{
    // ── Discovery ───────────────────────────────────────────────────────────
    public string TargetDomain { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }

    public List<ComputerInfo> DomainComputers { get; set; } = [];
    public List<SubnetInfo> DomainSubnets { get; set; } = [];

    public List<ComputerInfo> PingableComputers { get; set; } = [];
    public List<ComputerInfo> Computers445Open { get; set; } = [];

    // ── Shares ──────────────────────────────────────────────────────────────
    public List<ShareInfo> AllShares { get; set; } = [];
    public List<ShareAclEntry> AllShareAcls { get; set; } = [];

    // Excessive = ACL grants access to Everyone / BUILTIN\Users /
    //             Authenticated Users / Domain Users, and share is accessible.
    public List<ShareAclEntry> ExcessiveShareAcls { get; set; } = [];

    public List<ShareAclEntry> AclsWithRead { get; set; } = [];
    public List<ShareAclEntry> AclsWithWrite { get; set; } = [];
    public List<ShareAclEntry> HighRiskAcls { get; set; } = [];

    public List<DirectoryListingEntry> DirectoryListings { get; set; } = [];
    public List<InterestingFile> InterestingFiles { get; set; } = [];

    // ── Credentials ─────────────────────────────────────────────────────────
    public List<CredentialFinding> CredentialFindings { get; set; } = [];

    // ── Share fingerprinting (LLM) ───────────────────────────────────────────
    public List<ShareFingerprintResult> FingerprintResults { get; set; } = [];

    // ── Summary counts (calculated after scan) ──────────────────────────────
    public ScanSummary Summary { get; set; } = new();
}

public class ScanSummary
{
    public int TotalComputers { get; set; }
    public int PingableCount { get; set; }
    public int Port445OpenCount { get; set; }
    public int ComputersWithNonDefaultShares { get; set; }
    public int ComputersWithExcessivePrivs { get; set; }
    public int ComputersWithRead { get; set; }
    public int ComputersWithWrite { get; set; }
    public int ComputersWithHighRisk { get; set; }

    public int TotalShares { get; set; }
    public int NonDefaultShareCount { get; set; }
    public int ExcessiveAclCount { get; set; }
    public int SharesWithReadCount { get; set; }
    public int SharesWithWriteCount { get; set; }
    public int HighRiskShareCount { get; set; }

    public int TotalAcls { get; set; }
    public int ExcessivePrivAclCount { get; set; }
    public int ReadAclCount { get; set; }
    public int WriteAclCount { get; set; }
    public int HighRiskAclCount { get; set; }
}
