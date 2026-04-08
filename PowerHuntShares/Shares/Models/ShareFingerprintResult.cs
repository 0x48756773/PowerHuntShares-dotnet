namespace PowerHuntShares.Shares.Models;

/// <summary>
/// One LLM fingerprint result for a single share.
/// Maps to the PSObject built in Invoke-FingerPrintShare (line 28550).
/// </summary>
public class ShareFingerprintResult
{
    public string ShareName        { get; set; } = string.Empty;
    public string ApplicationName  { get; set; } = string.Empty;
    public string ConfidenceScore  { get; set; } = string.Empty;
    public string RelevantFiles    { get; set; } = string.Empty;
    public string Justification    { get; set; } = string.Empty;
    public int    PromptTokens     { get; set; }
    public int    CompletionTokens { get; set; }
    public int    TotalTokens      { get; set; }
    public string FolderGroup      { get; set; } = string.Empty;
}
