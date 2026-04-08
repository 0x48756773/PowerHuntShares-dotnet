using System.Net.NetworkInformation;
using PowerHuntShares.Discovery.Models;

namespace PowerHuntShares.Discovery;

/// <summary>
/// Parallel ICMP ping sweep.
/// Translates the Invoke-Ping / Invoke-Parallel ping block in Invoke-HuntSMBShares.
/// </summary>
public class PingScanner
{
    private readonly int _threads;
    private readonly int _timeoutMs;

    public PingScanner(int threads = 20, int timeoutMs = 1000)
    {
        _threads = threads;
        _timeoutMs = timeoutMs;
    }

    /// <summary>
    /// Pings all computers in the input list in parallel and returns those that responded.
    /// Sets ComputerInfo.PingResponse = true on responsive hosts.
    /// </summary>
    public IReadOnlyList<ComputerInfo> Scan(IEnumerable<ComputerInfo> computers)
    {
        var input = computers.ToList();
        var responding = new System.Collections.Concurrent.ConcurrentBag<ComputerInfo>();

        var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = _threads };

        Parallel.ForEach(input, parallelOptions, computer =>
        {
            if (IsAlive(computer.ComputerName))
            {
                computer.PingResponse = true;
                responding.Add(computer);
            }
        });

        return [.. responding];
    }

    private bool IsAlive(string hostname)
    {
        try
        {
            using var ping = new Ping();
            var reply = ping.Send(hostname, _timeoutMs);
            return reply.Status == IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }
}
