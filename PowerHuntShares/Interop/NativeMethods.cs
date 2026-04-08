using System.Runtime.InteropServices;

namespace PowerHuntShares.Interop;

/// <summary>
/// P/Invoke declarations for Windows native APIs used by the scanner.
///
/// Replaces the dynamic assembly approach used in PowerHuntShares.psm1 via
/// New-InMemoryModule / Add-Win32Type / func / struct / field helpers.
/// The structs and signatures are derived from the $Mod / $SHARE_INFO_1 /
/// $FunctionDefinitions blocks around line 22456-22514 of the original script.
/// </summary>
internal static class NativeMethods
{
    // ── Netapi32 ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Retrieves information about each shared resource on a server.
    /// Level 1 returns SHARE_INFO_1 structs (name, type, remark).
    /// PS equivalent: func netapi32 NetShareEnum ([Int]) @([String], [Int], ...)
    /// </summary>
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int NetShareEnum(
        string serverName,
        int level,
        ref IntPtr bufPtr,
        int prefMaxLen,
        ref int entriesRead,
        ref int totalEntries,
        ref int resumeHandle);

    /// <summary>
    /// Frees a buffer allocated by a Net* API call.
    /// </summary>
    [DllImport("Netapi32.dll")]
    internal static extern int NetApiBufferFree(IntPtr buffer);

    // ── advapi32 ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Converts a SID to its string representation (S-1-5-…).
    /// </summary>
    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertSidToStringSid(IntPtr pSid, out string stringSid);

    // ── Structs ───────────────────────────────────────────────────────────────

    /// <summary>
    /// SHARE_INFO_1 — result structure for NetShareEnum level 1.
    /// PS equivalent (line 22510):
    ///   $SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    ///       shi1_netname = field 0 String -MarshalAs @('LPWStr')
    ///       shi1_type    = field 1 UInt32
    ///       shi1_remark  = field 2 String -MarshalAs @('LPWStr')
    ///   }
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SHARE_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi1_netname;

        public uint shi1_type;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string shi1_remark;
    }

    /// <summary>
    /// Share type constants for shi1_type.
    /// </summary>
    internal static class ShareType
    {
        public const uint DiskTree = 0x00000000;
        public const uint PrintQueue = 0x00000001;
        public const uint Device = 0x00000002;
        public const uint Ipc = 0x00000003;
        public const uint Special = 0x80000000;   // hidden/admin share ($)
        public const uint Temporary = 0x40000000;
    }
}
