using System.Net;

namespace PowerHuntShares.Utilities;

/// <summary>
/// Subnet arithmetic utilities.
/// Translates checkSubnet, CheckNetworkToSubnet, CheckSubnetToNetwork,
/// CheckNetworkToNetwork, SubToBinary, NetworkToBinary (lines 24037–24136).
/// </summary>
public static class SubnetHelper
{
    /// <summary>
    /// Returns true when addr1 and addr2 share the same subnet.
    /// Both arguments are "address/prefix" strings, e.g. "192.168.1.5/24".
    /// Mirrors checkSubnet (line 24037).
    /// </summary>
    public static bool CheckSubnet(string addr1, string addr2)
    {
        try
        {
            (uint network1, uint mask1) = ParseCidr(addr1);
            (uint network2, uint mask2) = ParseCidr(addr2);

            // Same host?
            if (network1 == network2 && mask1 == mask2)
                return true;

            // addr1 is network, addr2 is host?
            if (CheckNetworkToSubnet(network2, mask2, network1))
                return true;

            // addr2 is network, addr1 is host?
            if (CheckNetworkToSubnet(network1, mask1, network2))
                return true;

            // Both are networks?
            if (CheckNetworkToNetwork(network1, network2))
                return true;

            return false;
        }
        catch
        {
            return false;
        }
    }

    // ── Internal helpers — direct translations of the PS functions ────────────

    /// <summary>Mirrors CheckNetworkToSubnet (line 24079).</summary>
    private static bool CheckNetworkToSubnet(uint networkAddr, uint mask, uint hostAddr)
        => (hostAddr & mask) == networkAddr;

    /// <summary>Mirrors CheckNetworkToNetwork (line 24109).</summary>
    private static bool CheckNetworkToNetwork(uint net1, uint net2)
        => net1 == net2;

    /// <summary>
    /// Parses "ip/prefix" into (network address, subnet mask) as uint32 values.
    /// Mirrors NetworkToBinary + SubToBinary (lines 24124–24136).
    /// </summary>
    private static (uint Network, uint Mask) ParseCidr(string cidr)
    {
        string[] parts = cidr.Split('/');
        if (parts.Length != 2)
            throw new FormatException($"Expected CIDR notation, got: {cidr}");

        uint ip = IpToUint(parts[0]);
        int prefix = int.Parse(parts[1]);

        // Build subnet mask from prefix length.
        uint mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
        uint network = ip & mask;

        return (network, mask);
    }

    private static uint IpToUint(string ip)
    {
        byte[] bytes = IPAddress.Parse(ip).GetAddressBytes();
        // GetAddressBytes() returns big-endian; convert to uint.
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }
}
