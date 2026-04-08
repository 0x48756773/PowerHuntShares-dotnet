namespace PowerHuntShares.Credentials.Models;

/// <summary>
/// A credential or sensitive value extracted from a config file on a share.
/// Mirrors the PSCustomObject schema used by all Get-Pw* functions,
/// e.g. the $connectionObject in Get-PwStandalone (line 24945).
/// </summary>
public class CredentialFinding
{
    public string ComputerName { get; set; } = string.Empty;
    public string ShareName { get; set; } = string.Empty;
    public string UncFilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Section { get; set; } = "NA";
    public string ObjectName { get; set; } = "NA";
    public string TargetUrl { get; set; } = "NA";
    public string TargetServer { get; set; } = "NA";
    public string TargetPort { get; set; } = "NA";
    public string Database { get; set; } = "NA";
    public string Domain { get; set; } = "NA";
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string PasswordEncoded { get; set; } = "NA";
    public string KeyFilePath { get; set; } = "NA";

    /// <summary>Name of the parser that produced this finding.</summary>
    public string SourceParser { get; set; } = string.Empty;
}
