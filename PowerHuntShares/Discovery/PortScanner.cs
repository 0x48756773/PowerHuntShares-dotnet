using System.Net.Sockets;
using PowerHuntShares.Discovery.Models;

namespace PowerHuntShares.Discovery;

/// <summary>
/// Parallel TCP port 445 scanner.
/// Translates the $MyScriptBlock / Invoke-Parallel TCP-445 block in Invoke-HuntSMBShares.
/// </summary>
public class PortScanner
{
    private readonly int _threads;
    private readonly int _timeoutMs;

    public PortScanner(int threads = 20, int timeoutMs = 3000)
    {
        _threads = threads;
        _timeoutMs = timeoutMs;
    }

    /// <summary>
    /// Tests TCP port 445 on every computer in parallel.
    /// Returns only those hosts where the port is open.
    /// Sets ComputerInfo.Port445Open = true on reachable hosts.
    /// </summary>
    public IReadOnlyList<ComputerInfo> Scan(IEnumerable<ComputerInfo> computers)
    {
        var input = computers.ToList();
        var open = new System.Collections.Concurrent.ConcurrentBag<ComputerInfo>();

        var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = _threads };

        Parallel.ForEach(input, parallelOptions, computer =>
        {
            if (IsPort445Open(computer.ComputerName))
            {
                computer.Port445Open = true;
                open.Add(computer);
            }
        });

        return [.. open];
    }

    /// <summary>
    /// Mirrors the TcpClient-based probe in the PowerShell code:
    ///   $Socket = New-Object System.Net.Sockets.TcpClient($ComputerName, "445")
    /// </summary>
    private bool IsPort445Open(string hostname)
    {
        try
        {
            using var client = new TcpClient();
            // BeginConnect with a manual timeout mirrors the RunspaceTimeout behaviour.
            var result = client.BeginConnect(hostname, 445, null, null);
            bool connected = result.AsyncWaitHandle.WaitOne(_timeoutMs);

            if (connected && client.Connected)
            {
                client.EndConnect(result);
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }
}
