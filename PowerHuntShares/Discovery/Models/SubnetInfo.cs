namespace PowerHuntShares.Discovery.Models;

/// <summary>
/// Represents an AD site subnet from CN=Subnets,CN=Sites,CN=Configuration.
/// Maps to the DataTable built in Get-DomainSubnet.
/// </summary>
public class SubnetInfo
{
    public string Site { get; set; } = string.Empty;
    public string Subnet { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string WhenCreated { get; set; } = string.Empty;
    public string WhenChanged { get; set; } = string.Empty;
    public string DistinguishedName { get; set; } = string.Empty;
}
