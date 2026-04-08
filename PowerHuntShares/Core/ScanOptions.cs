namespace PowerHuntShares.Core;

/// <summary>
/// All command-line options. Maps to the parameters of Invoke-HuntSMBShares.
/// </summary>
public class ScanOptions
{
    public string? Username                 { get; set; }
    public string? Password                 { get; set; }
    public string? DomainController         { get; set; }
    public int     Threads                  { get; set; } = 20;
    public string  OutputDirectory          { get; set; } = string.Empty;
    public string? HostList                 { get; set; }
    public bool    ExportFindings           { get; set; }
    public bool    ExportNova               { get; set; }
    public int     SampleSum                { get; set; } = 200;
    public int     ConnectionTimeoutSeconds { get; set; } = 15;
    public int     ShareCreationDays        { get; set; } = 90;
    public int     LastAccessDays           { get; set; } = 90;
    public int     LastModDays              { get; set; } = 90;
    public int     DirLevel                 { get; set; } = 3;
    public string? FileKeywordsPath         { get; set; }
    public bool    NoPing                   { get; set; }
    public bool    ShowErrors               { get; set; }
    public bool    SuppressTimelineReport   { get; set; }
    public string? ApiKey                   { get; set; }
    public string? Endpoint                 { get; set; }
}
