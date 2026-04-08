using System.Security.AccessControl;
using System.Security.Principal;
using PowerHuntShares.Shares.Models;
using PowerHuntShares.Utilities;

namespace PowerHuntShares.Shares;

/// <summary>
/// Reads DACL entries and directory metadata for SMB share root paths.
/// Translates Get-PathAcl (line 16553) and the per-ACL script block
/// in Invoke-HuntSMBShares (lines 594–671).
/// </summary>
public class AclEnumerator
{
    private readonly int _threads;

    public AclEnumerator(int threads = 20)
    {
        _threads = threads;
    }

    /// <summary>
    /// Enumerates ACL entries for all provided shares in parallel.
    /// Mirrors $ShareACLs = $AllSMBShares | Invoke-Parallel -ScriptBlock $MyScriptBlock …
    /// </summary>
    public IReadOnlyList<ShareAclEntry> EnumerateAcls(IEnumerable<ShareInfo> shares)
    {
        var results = new System.Collections.Concurrent.ConcurrentBag<ShareAclEntry>();
        var opts = new ParallelOptions { MaxDegreeOfParallelism = _threads };

        Parallel.ForEach(shares, opts, share =>
        {
            var entries = GetAclEntries(share);
            foreach (var entry in entries)
                results.Add(entry);
        });

        return results.Where(e => !string.IsNullOrEmpty(e.ShareName)).ToList();
    }

    // ── Per-share ACL reading ─────────────────────────────────────────────────

    /// <summary>
    /// Reads DACL, ownership, and directory metadata for a single share.
    /// Translates Get-PathAcl and the surrounding metadata-collection code.
    /// </summary>
    public IReadOnlyList<ShareAclEntry> GetAclEntries(ShareInfo share)
    {
        var results = new List<ShareAclEntry>();
        string unc = share.UncPath;

        try
        {
            var dirInfo = new DirectoryInfo(unc);
            DirectorySecurity acl = dirInfo.GetAccessControl(AccessControlSections.Access |
                                                              AccessControlSections.Owner);
            string owner = acl.GetOwner(typeof(NTAccount))?.ToString() ?? string.Empty;

            // ── Directory metadata ──────────────────────────────────────────
            dirInfo.Refresh();
            string creationDate = dirInfo.CreationTime.ToString();
            string creationYear = dirInfo.CreationTime.Year.ToString();
            string lastModDate = dirInfo.LastWriteTime.ToString();
            string lastModYear = dirInfo.LastWriteTime.Year.ToString();
            string lastAccessDate = dirInfo.LastAccessTime.ToString();
            string lastAccessYear = dirInfo.LastAccessTime.Year.ToString();

            // ── Top-level file listing (mirrors lines 615–624) ──────────────
            string fileList = string.Empty;
            int fileCount = 0;
            string fileListGroup = string.Empty;

            try
            {
                var topLevel = dirInfo.GetFileSystemInfos();
                fileCount = topLevel.Length;
                fileList = string.Join("\n", topLevel.Select(f => f.Name));
                fileListGroup = HashHelper.ComputeMd5(string.Join(",",
                    topLevel.Select(f => f.Name).OrderBy(n => n)));
            }
            catch { /* share may be browsable but GetFileSystemInfos can still fail */ }

            // ── Audit settings (mirrors Get-ACL .AuditToString) ─────────────
            string auditSettings = string.Empty;
            try
            {
                auditSettings = acl.GetAuditRules(true, true, typeof(NTAccount))
                    .Cast<FileSystemAuditRule>()
                    .Select(r => $"{r.IdentityReference}: {r.FileSystemRights} ({r.AuditFlags})")
                    .DefaultIfEmpty(string.Empty)
                    .Aggregate((a, b) => $"{a}; {b}");
            }
            catch { }

            // ── Per-ACE iteration (mirrors Get-PathAcl process block) ────────
            var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));

            foreach (FileSystemAccessRule rule in rules)
            {
                string sidStr = rule.IdentityReference.Value;
                string identityName = ResolveIdentityName(sidStr);
                string rightsStr = ConvertFileRights((uint)rule.FileSystemRights);

                results.Add(new ShareAclEntry
                {
                    ComputerName = share.ComputerName,
                    IpAddress = share.IpAddress,
                    ShareName = share.ShareName,
                    SharePath = unc,
                    ShareDescription = share.ShareDescription,
                    ShareOwner = owner,
                    ShareType = share.ShareType,
                    ShareAccess = share.ShareAccess,
                    FileSystemRights = rightsStr,
                    IdentityReference = identityName,
                    IdentitySid = sidStr,
                    AccessControlType = rule.AccessControlType.ToString(),
                    CreationDate = creationDate,
                    CreationDateYear = creationYear,
                    LastModifiedDate = lastModDate,
                    LastModifiedDateYear = lastModYear,
                    LastAccessDate = lastAccessDate,
                    LastAccessDateYear = lastAccessYear,
                    FileCount = fileCount,
                    FileList = fileList,
                    FileListGroup = fileListGroup,
                    AuditSettings = auditSettings,
                });
            }
        }
        catch
        {
            // Inaccessible share — no ACL entries returned.
        }

        return results;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Converts a FileSystemRights bitmask to a human-readable string.
    /// Direct translation of Convert-FileRight (lines 16566–16623).
    ///
    /// The function first checks for "simple" combined permissions (FullControl,
    /// Modify, etc.) and then for individual access-mask bits.
    /// </summary>
    public static string ConvertFileRights(uint fsr)
    {
        // Simple / combined permission masks — checked first, high-specificity first.
        var simple = new (uint Mask, string Name)[]
        {
            (0x1f01ff, "FullControl"),
            (0x0301bf, "Modify"),
            (0x0200a9, "ReadAndExecute"),
            (0x02019f, "ReadAndWrite"),
            (0x020089, "Read"),
            (0x000116, "Write"),
        };

        // Individual access-mask bits (fallback for non-standard combinations).
        var accessMask = new (uint Mask, string Name)[]
        {
            (0x80000000, "GenericRead"),
            (0x40000000, "GenericWrite"),
            (0x20000000, "GenericExecute"),
            (0x10000000, "GenericAll"),
            (0x02000000, "MaximumAllowed"),
            (0x01000000, "AccessSystemSecurity"),
            (0x00100000, "Synchronize"),
            (0x00080000, "WriteOwner"),
            (0x00040000, "WriteDAC"),
            (0x00020000, "ReadControl"),
            (0x00010000, "Delete"),
            (0x00000100, "WriteAttributes"),
            (0x00000080, "ReadAttributes"),
            (0x00000040, "DeleteChild"),
            (0x00000020, "Execute/Traverse"),
            (0x00000010, "WriteExtendedAttributes"),
            (0x00000008, "ReadExtendedAttributes"),
            (0x00000004, "AppendData/AddSubdirectory"),
            (0x00000002, "WriteData/AddFile"),
            (0x00000001, "ReadData/ListDirectory"),
        };

        var parts = new List<string>();
        uint remaining = fsr;

        // Identify simple permissions and zero out matched bits.
        foreach (var (mask, name) in simple)
        {
            if ((remaining & mask) == mask)
            {
                parts.Add(name);
                remaining &= ~mask;
            }
        }

        // Identify remaining individual bits.
        foreach (var (mask, name) in accessMask)
        {
            if ((remaining & mask) != 0)
                parts.Add(name);
        }

        return parts.Count > 0 ? string.Join(",", parts) : fsr.ToString("X");
    }

    /// <summary>
    /// Translates a SID string to an NT account name, mirroring Convert-SidToName.
    /// Falls back to the raw SID string on failure.
    /// </summary>
    private static string ResolveIdentityName(string sidStr)
    {
        try
        {
            var sid = new SecurityIdentifier(sidStr);
            var account = (NTAccount)sid.Translate(typeof(NTAccount));
            return account.Value;
        }
        catch
        {
            return sidStr;
        }
    }
}
