namespace PowerHuntShares.Discovery.Models;

/// <summary>
/// Represents a domain computer discovered via LDAP or imported from a host file.
/// Maps to the PSObject produced by the LDAP query loop in Invoke-HuntSMBShares.
/// </summary>
public class ComputerInfo
{
    public string ComputerName { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string ServicePack { get; set; } = string.Empty;

    // Populated during ping / port-scan phases
    public bool PingResponse { get; set; }
    public bool Port445Open { get; set; }
}
