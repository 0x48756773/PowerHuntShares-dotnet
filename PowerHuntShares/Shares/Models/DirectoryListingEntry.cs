namespace PowerHuntShares.Shares.Models;

/// <summary>
/// One file/folder path discovered during the recursive directory listing phase.
/// Maps to the $aclObject created in the directory-listing script block
/// (lines 773–782 of Invoke-HuntSMBShares).
/// </summary>
public class DirectoryListingEntry
{
    public string ComputerName { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string ShareName { get; set; } = string.Empty;
    public string SharePath { get; set; } = string.Empty;
    public string ShareDescription { get; set; } = string.Empty;

    /// <summary>Full path of the discovered file or folder.</summary>
    public string FilePath { get; set; } = string.Empty;
}
