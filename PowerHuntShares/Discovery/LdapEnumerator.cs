using System.DirectoryServices;
using System.Net;
using PowerHuntShares.Discovery.Models;

namespace PowerHuntShares.Discovery;

/// <summary>
/// Enumerates Active Directory objects via LDAP.
/// Translates Get-LdapQuery and Get-DomainSubnet from PowerHuntShares.psm1.
/// </summary>
public class LdapEnumerator
{
    private readonly string? _domainController;
    private readonly NetworkCredential? _credential;
    private string? _baseDn; // lazily resolved from RootDSE

    public LdapEnumerator(string? domainController = null, NetworkCredential? credential = null)
    {
        _domainController = domainController;
        _credential = credential;
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the first reachable domain controller's DNS hostname and the domain FQDN.
    /// Mirrors the DC detection block at the start of Invoke-HuntSMBShares.
    /// </summary>
    public (string DcHostname, string Domain) DiscoverDomainController()
    {
        const string filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";

        var results = Query(filter, pageSize: 1);
        var first = results.FirstOrDefault();
        if (first is null)
            throw new InvalidOperationException("Could not locate a domain controller via LDAP.");

        string dcHostname = first.Properties["dnshostname"]?.Count > 0
            ? first.Properties["dnshostname"][0]?.ToString() ?? string.Empty
            : string.Empty;

        string dcCn = first.Properties["cn"]?.Count > 0
            ? first.Properties["cn"][0]?.ToString() ?? string.Empty
            : string.Empty;

        // Strip the CN portion to derive the domain FQDN, e.g. dc1.demo.local → demo.local
        string domain = string.IsNullOrEmpty(dcCn)
            ? dcHostname
            : dcHostname.Replace($"{dcCn}.", string.Empty, StringComparison.OrdinalIgnoreCase);

        return (dcHostname, domain);
    }

    /// <summary>
    /// Enumerates all computer objects in the domain.
    /// Maps to Get-LdapQuery -LdapFilter "(objectCategory=Computer)".
    /// </summary>
    public IReadOnlyList<ComputerInfo> GetDomainComputers()
    {
        var results = Query("(objectCategory=Computer)");
        var computers = new List<ComputerInfo>();

        foreach (SearchResult result in results)
        {
            string dns = GetProp(result, "dnshostname");
            if (string.IsNullOrWhiteSpace(dns))
                continue;

            computers.Add(new ComputerInfo
            {
                ComputerName = dns,
                OperatingSystem = GetProp(result, "operatingsystem"),
                ServicePack = GetProp(result, "operatingsystemservicepack"),
            });
        }

        return computers;
    }

    /// <summary>
    /// Enumerates AD site subnets.
    /// Maps to Get-DomainSubnet / Get-LdapQuery -LdapFilter "(objectCategory=subnet)".
    /// </summary>
    public IReadOnlyList<SubnetInfo> GetDomainSubnets()
    {
        const string ldapPath = "CN=Subnets,CN=Sites,CN=Configuration";
        var results = Query("(objectCategory=subnet)", ldapPath: ldapPath);
        var subnets = new List<SubnetInfo>();

        foreach (SearchResult result in results)
        {
            // The site back-link lives in the "siteobject" attribute as a DN;
            // the CN of that DN is the site name.
            string siteObjectDn = GetProp(result, "siteobject");
            string siteName = ExtractCn(siteObjectDn);

            subnets.Add(new SubnetInfo
            {
                Site = siteName,
                Subnet = GetProp(result, "name"),
                Description = GetProp(result, "description"),
                WhenCreated = GetProp(result, "whencreated"),
                WhenChanged = GetProp(result, "whenchanged"),
                DistinguishedName = GetProp(result, "distinguishedname"),
            });
        }

        return subnets;
    }

    // ── Core query engine ────────────────────────────────────────────────────

    /// <summary>
    /// Executes an LDAP search and returns raw SearchResults.
    /// Translates the Begin block of Get-LdapQuery.
    /// </summary>
    public IReadOnlyList<SearchResult> Query(
        string ldapFilter,
        string? ldapPath = null,
        int pageSize = 1000,
        SearchScope scope = SearchScope.Subtree)
    {
        DirectoryEntry rootEntry = BuildDirectoryEntry(ldapPath);

        using var searcher = new DirectorySearcher(rootEntry)
        {
            Filter = ldapFilter,
            SearchScope = scope,
            PageSize = pageSize,
        };

        try
        {
            using var results = searcher.FindAll();
            // Copy into a list before disposing the SearchResultCollection
            return results.Cast<SearchResult>().ToList();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"LDAP query failed (filter={ldapFilter}): {ex.Message}", ex);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Resolves the domain base DN (e.g. DC=domain,DC=local) from RootDSE.
    /// Cached after the first call. Needed to turn partial paths like
    /// CN=Subnets,CN=Sites,CN=Configuration into a fully-qualified DN.
    /// </summary>
    private string GetBaseDn()
    {
        if (_baseDn is not null)
            return _baseDn;

        string rootPath = string.IsNullOrEmpty(_domainController)
            ? "LDAP://RootDSE"
            : $"LDAP://{_domainController}/RootDSE";

        try
        {
            using var rootDse = _credential is not null
                ? new DirectoryEntry(rootPath, _credential.UserName, _credential.Password)
                : new DirectoryEntry(rootPath);

            _baseDn = rootDse.Properties["defaultNamingContext"]?[0]?.ToString() ?? string.Empty;
        }
        catch
        {
            _baseDn = string.Empty;
        }

        return _baseDn;
    }

    private DirectoryEntry BuildDirectoryEntry(string? ldapPath)
    {
        // Partial paths (e.g. CN=Subnets,CN=Sites,CN=Configuration) must be
        // qualified with the domain base DN or ADSI throws E_ADS_BAD_PATHNAME.
        string? resolvedPath = null;
        if (!string.IsNullOrEmpty(ldapPath))
        {
            string baseDn = GetBaseDn();
            resolvedPath = string.IsNullOrEmpty(baseDn) ? ldapPath : $"{ldapPath},{baseDn}";
        }

        string ldapUri;
        if (!string.IsNullOrEmpty(_domainController))
        {
            ldapUri = resolvedPath is not null
                ? $"LDAP://{_domainController}/{resolvedPath}"
                : $"LDAP://{_domainController}";
        }
        else
        {
            ldapUri = resolvedPath is not null
                ? $"LDAP://{resolvedPath}"
                : string.Empty;
        }

        // Fall back to "LDAP://" (not empty string) so ADSI uses the LDAP
        // provider against the current domain rather than the WinNT provider.
        if (string.IsNullOrEmpty(ldapUri))
            ldapUri = "LDAP://";

        if (_credential is not null)
            return new DirectoryEntry(ldapUri, _credential.UserName, _credential.Password);

        return new DirectoryEntry(ldapUri);
    }

    private static string GetProp(SearchResult result, string propertyName)
    {
        var prop = result.Properties[propertyName];
        return prop?.Count > 0 ? prop[0]?.ToString() ?? string.Empty : string.Empty;
    }

    /// <summary>Extracts the CN value from a Distinguished Name string.</summary>
    private static string ExtractCn(string dn)
    {
        if (string.IsNullOrEmpty(dn))
            return string.Empty;

        foreach (var part in dn.Split(','))
        {
            var kv = part.Trim().Split('=');
            if (kv.Length == 2 && kv[0].Equals("CN", StringComparison.OrdinalIgnoreCase))
                return kv[1];
        }

        return dn;
    }
}
