using System.Security.Cryptography;
using System.Text;

namespace PowerHuntShares.Utilities;

/// <summary>
/// MD5 hashing utility used to produce stable group identifiers for share
/// directory listings.  Translates Get-FolderGroupMd5 (line 14617).
/// </summary>
public static class HashHelper
{
    /// <summary>
    /// Returns the MD5 hex digest of the supplied string.
    /// Mirrors: Get-FolderGroupMd5 -FolderList $FileList
    /// </summary>
    public static string ComputeMd5(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        byte[] bytes = Encoding.UTF8.GetBytes(input);
        byte[] hash = MD5.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
