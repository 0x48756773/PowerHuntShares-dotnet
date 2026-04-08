namespace PowerHuntShares.Shares.Models;

/// <summary>
/// One ACL entry on one share.
/// Mirrors the $aclObject built in the SMB-share-permissions block
/// (lines 647–670 of Invoke-HuntSMBShares) and the output of Get-PathAcl.
/// </summary>
public class ShareAclEntry
{
    public string ComputerName { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string ShareName { get; set; } = string.Empty;

    /// <summary>Full UNC path to the share root.</summary>
    public string SharePath { get; set; } = string.Empty;

    public string ShareDescription { get; set; } = string.Empty;

    /// <summary>Owner of the share root directory (from Get-Acl .Owner).</summary>
    public string ShareOwner { get; set; } = string.Empty;

    public uint ShareType { get; set; }

    /// <summary>"Yes" / "No" — whether the share was directly accessible.</summary>
    public string ShareAccess { get; set; } = "No";

    // ── Per-ACE fields (from Get-PathAcl output) ────────────────────────────

    /// <summary>Human-readable permission string, e.g. "Read", "FullControl".</summary>
    public string FileSystemRights { get; set; } = string.Empty;

    /// <summary>Resolved identity name, e.g. "BUILTIN\\Users" or "DOMAIN\\GroupName".</summary>
    public string IdentityReference { get; set; } = string.Empty;

    /// <summary>SID string for the identity.</summary>
    public string IdentitySid { get; set; } = string.Empty;

    /// <summary>"Allow" or "Deny".</summary>
    public string AccessControlType { get; set; } = string.Empty;

    // ── Directory metadata ───────────────────────────────────────────────────

    public string CreationDate { get; set; } = string.Empty;
    public string CreationDateYear { get; set; } = string.Empty;
    public string LastModifiedDate { get; set; } = string.Empty;
    public string LastModifiedDateYear { get; set; } = string.Empty;
    public string LastAccessDate { get; set; } = string.Empty;
    public string LastAccessDateYear { get; set; } = string.Empty;

    public int FileCount { get; set; }

    /// <summary>Newline-joined list of top-level file names.</summary>
    public string FileList { get; set; } = string.Empty;

    /// <summary>MD5 hash of the sorted file-listing string (for grouping identical shares).</summary>
    public string FileListGroup { get; set; } = string.Empty;

    public string AuditSettings { get; set; } = string.Empty;
}
