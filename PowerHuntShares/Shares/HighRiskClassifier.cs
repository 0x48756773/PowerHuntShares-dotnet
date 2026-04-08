using PowerHuntShares.Shares.Models;

namespace PowerHuntShares.Shares;

/// <summary>
/// Classifies ACL entries as excessive, readable, writable, or high-risk.
/// Translates the analysis blocks starting at line 700 of Invoke-HuntSMBShares.
/// </summary>
public static class HighRiskClassifier
{
    // ── Identities considered "broad" (excessive by themselves) ──────────────

    // These map to the IdentityReference check in Invoke-HuntSMBShares line 710:
    //   if ($line.IdentityReference -eq "Everyone") -or ... -or (*Domain Users*)
    private static readonly HashSet<string> BroadIdentities = new(StringComparer.OrdinalIgnoreCase)
    {
        "Everyone",
        "BUILTIN\\Users",
        "Authenticated Users",
        "NT AUTHORITY\\Authenticated Users",
    };

    // ── Shares excluded from "excessive" classification ────────────────────
    // PS: ($line.ShareName -notlike "print$") -and ... -and -notlike "sysvol" …
    private static readonly HashSet<string> ExcludedShareNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "print$",
        "prnproc$",
        "sysvol",
        "netlogon",
    };

    // ── High-risk share names (common sensitive shares) ────────────────────
    private static readonly HashSet<string> HighRiskShareNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "c$", "d$", "e$", "admin$", "ipc$",
        "wwwroot", "webroot", "inetpub",
        "backup", "backups",
    };

    // ── Public API ─────────────────────────────────────────────────────────

    /// <summary>
    /// Returns ACL entries that are potentially excessive.
    /// Mirrors lines 707–720 of Invoke-HuntSMBShares:
    ///   broad identity + ShareAccess=Yes + not excluded share name.
    /// </summary>
    public static IReadOnlyList<ShareAclEntry> GetExcessivePrivileges(
        IEnumerable<ShareAclEntry> acls)
    {
        return acls.Where(IsExcessive).ToList();
    }

    /// <summary>Filters excessive ACLs to those with any read right.</summary>
    public static IReadOnlyList<ShareAclEntry> GetReadableShares(
        IEnumerable<ShareAclEntry> excessiveAcls)
    {
        return excessiveAcls
            .Where(e => e.FileSystemRights.Contains("read", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    /// <summary>Filters excessive ACLs to those with any write right.</summary>
    public static IReadOnlyList<ShareAclEntry> GetWritableShares(
        IEnumerable<ShareAclEntry> excessiveAcls)
    {
        return excessiveAcls
            .Where(e => e.FileSystemRights.Contains("write", StringComparison.OrdinalIgnoreCase) ||
                        e.FileSystemRights.Contains("FullControl", StringComparison.OrdinalIgnoreCase) ||
                        e.FileSystemRights.Contains("Modify", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    /// <summary>
    /// Returns ACL entries on shares considered high-risk by name.
    /// Mirrors the high-risk share filtering in the analysis section.
    /// </summary>
    public static IReadOnlyList<ShareAclEntry> GetHighRiskShares(
        IEnumerable<ShareAclEntry> excessiveAcls)
    {
        return excessiveAcls
            .Where(e => HighRiskShareNames.Contains(e.ShareName))
            .ToList();
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static bool IsExcessive(ShareAclEntry entry)
    {
        // Must be accessible
        if (!entry.ShareAccess.Equals("Yes", StringComparison.OrdinalIgnoreCase))
            return false;

        // Must be granted to a broad identity (or contain "Domain Users")
        bool broadIdentity = BroadIdentities.Contains(entry.IdentityReference) ||
                             entry.IdentityReference.Contains("Domain Users",
                                 StringComparison.OrdinalIgnoreCase);
        if (!broadIdentity)
            return false;

        // Must not be one of the excluded share names or contain "printer"
        if (ExcludedShareNames.Contains(entry.ShareName))
            return false;

        if (entry.ShareName.Contains("printer", StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }
}
