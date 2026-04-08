namespace PowerHuntShares.Shares.Models;

/// <summary>
/// Represents a single SMB share discovered via NetShareEnum.
/// Mirrors the ShareObject PSCustomObject built in Get-MySMBShare (line 20995).
/// </summary>
public class ShareInfo
{
    public string ComputerName { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>shi1_netname from SHARE_INFO_1.</summary>
    public string ShareName { get; set; } = string.Empty;

    /// <summary>shi1_remark — the share description/comment.</summary>
    public string ShareDescription { get; set; } = string.Empty;

    /// <summary>shi1_type as a uint.</summary>
    public uint ShareType { get; set; }

    /// <summary>
    /// "Yes" / "No" — whether IO.Directory.GetFiles succeeded on the share path.
    /// Mirrors the ShareAccess member added in Get-MySMBShare (line 21012).
    /// </summary>
    public string ShareAccess { get; set; } = "No";

    /// <summary>Full UNC path, e.g. \\server\share.</summary>
    public string UncPath => $"\\\\{ComputerName}\\{ShareName}";

    /// <summary>True for admin/hidden shares (IPC$, ADMIN$, C$, etc.).</summary>
    public bool IsDefault =>
        ShareName.Equals("IPC$", StringComparison.OrdinalIgnoreCase) ||
        ShareName.Equals("ADMIN$", StringComparison.OrdinalIgnoreCase) ||
        ShareName.EndsWith("$", StringComparison.OrdinalIgnoreCase);
}
