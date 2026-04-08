using System.Net;
using System.Runtime.InteropServices;
using PowerHuntShares.Discovery.Models;
using PowerHuntShares.Interop;
using PowerHuntShares.Shares.Models;

namespace PowerHuntShares.Shares;

/// <summary>
/// Enumerates SMB shares on remote computers using NetShareEnum (Netapi32).
/// Translates Get-MySMBShare (line 20945) from PowerHuntShares.psm1.
/// </summary>
public class ShareEnumerator
{
    private readonly int _threads;
    private readonly int _timeoutMs;

    public ShareEnumerator(int threads = 20, int timeoutMs = 15000)
    {
        _threads = threads;
        _timeoutMs = timeoutMs;
    }

    /// <summary>
    /// Enumerates shares across all supplied computers in parallel.
    /// Returns every share (accessible or not), mirroring $AllSMBShares.
    /// </summary>
    public IReadOnlyList<ShareInfo> EnumerateShares(IEnumerable<ComputerInfo> computers)
    {
        var results = new System.Collections.Concurrent.ConcurrentBag<ShareInfo>();
        var opts = new ParallelOptions { MaxDegreeOfParallelism = _threads };

        Parallel.ForEach(computers, opts, computer =>
        {
            var shares = GetSharesFromHost(computer.ComputerName);
            foreach (var share in shares)
                results.Add(share);
        });

        return [.. results];
    }

    // ── Per-host share enumeration ────────────────────────────────────────────

    /// <summary>
    /// Calls NetShareEnum at level 1 for the specified host and returns the results.
    /// Mirrors the body of Get-MySMBShare.
    /// </summary>
    public IReadOnlyList<ShareInfo> GetSharesFromHost(string computerName)
    {
        var shares = new List<ShareInfo>();

        IntPtr bufPtr = IntPtr.Zero;
        int entriesRead = 0, totalEntries = 0, resumeHandle = 0;
        int structSize = Marshal.SizeOf<NativeMethods.SHARE_INFO_1>();

        try
        {
            int result = NativeMethods.NetShareEnum(
                computerName,
                1,
                ref bufPtr,
                -1,
                ref entriesRead,
                ref totalEntries,
                ref resumeHandle);

            if (result != 0 || bufPtr == IntPtr.Zero)
                return shares;

            string ipAddress = ResolveIpAddress(computerName);
            long offset = bufPtr.ToInt64();

            for (int i = 0; i < entriesRead; i++)
            {
                var ptr = new IntPtr(offset);
                var info = Marshal.PtrToStructure<NativeMethods.SHARE_INFO_1>(ptr);

                string shareName = info.shi1_netname ?? string.Empty;
                string shareDesc = info.shi1_remark ?? string.Empty;
                uint shareType = info.shi1_type;

                string shareAccess = TestShareAccess(computerName, shareName) ? "Yes" : "No";

                shares.Add(new ShareInfo
                {
                    ComputerName = computerName,
                    IpAddress = ipAddress,
                    ShareName = shareName,
                    ShareDescription = shareDesc,
                    ShareType = shareType,
                    ShareAccess = shareAccess,
                });

                offset += structSize;
            }
        }
        catch (Exception)
        {
            // Swallow per-host errors; the caller decides whether to surface them.
        }
        finally
        {
            if (bufPtr != IntPtr.Zero)
                NativeMethods.NetApiBufferFree(bufPtr);
        }

        return shares;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Mirrors the access-check in Get-MySMBShare:
    ///   $Null = [IO.Directory]::GetFiles($TargetPath)
    /// Returns true if the directory is listable.
    /// </summary>
    private static bool TestShareAccess(string computerName, string shareName)
    {
        try
        {
            string unc = $"\\\\{computerName}\\{shareName}";
            Directory.GetFiles(unc);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string ResolveIpAddress(string hostname)
    {
        try
        {
            var addresses = Dns.GetHostAddresses(hostname);
            return addresses.Length > 0 ? addresses[0].ToString() : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }
}
