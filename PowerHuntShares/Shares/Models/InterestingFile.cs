namespace PowerHuntShares.Shares.Models;

/// <summary>
/// A file matched by an interesting-file keyword pattern.
/// Maps to the InterestingFilesAllObjects built in Invoke-HuntSMBShares (lines 1757–1790).
/// </summary>
public class InterestingFile
{
    public string ComputerName { get; set; } = string.Empty;
    public string ShareName { get; set; } = string.Empty;
    public string SharePath { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Keyword { get; set; } = string.Empty;
}
