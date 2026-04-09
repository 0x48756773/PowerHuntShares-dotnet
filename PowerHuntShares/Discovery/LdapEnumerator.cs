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
    /// Returns the domain controller hostname and domain FQDN.
    ///
    /// When -d is supplied we already have the DC hostname; derive the domain
    /// name from the base DN (DC=domain,DC=local → domain.local) instead of running a
    /// redundant LDAP search that can fail with E_ADS_BAD_PARAMETER on some DCs.
    ///
    /// When no DC is supplied (domain-joined machine) an LDAP search is used to
    /// locate a DC and confirm connectivity, mirroring the PS behaviour.
    /// </summary>
    public (string DcHostname, string Domain) DiscoverDomainController()
    {
        if (!string.IsNullOrEmpty(_domainController))
        {
            // DC explicitly provided — no discovery query needed.
            string baseDn = GetBaseDn();
            string domain = string.Join(".",
                baseDn.Split(',')
                      .Where(p => p.TrimStart().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                      .Select(p => p.TrimStart().Substring(3)));
            return (_domainController, domain);
        }

        // No DC provided — query to find one and confirm connectivity.
        const string filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
        var results = Query(filter);
        var first = results.FirstOrDefault();
        if (first is null)
            throw new InvalidOperationException("Could not locate a domain controller via LDAP.");

        string dcHostname = first.Properties["dnshostname"]?.Count > 0
            ? first.Properties["dnshostname"][0]?.ToString() ?? string.Empty
            : string.Empty;

        string dcCn = first.Properties["cn"]?.Count > 0
            ? first.Properties["cn"][0]?.ToString() ?? string.Empty
            : string.Empty;

        string domainName = string.IsNullOrEmpty(dcCn)
            ? dcHostname
            : dcHostname.Replace($"{dcCn}.", string.Empty, StringComparison.OrdinalIgnoreCase);

        return (dcHostname, domainName);
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
            string hint = string.IsNullOrEmpty(_domainController)
                ? " If this machine is not domain-joined, use --domain-controller to specify a DC."
                : string.Empty;
            throw new InvalidOperationException(
                $"LDAP query failed — root='{rootEntry.Path}' filter='{ldapFilter}' " +
                $"baseDn='{_baseDn ?? "unresolved"}': {ex.GetType().Name}: {ex.Message}{hint}", ex);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Resolves the domain base DN (e.g. DC=domain,DC=local). Cached after the first call.
    ///
    /// Strategies tried in order:
    ///   1. LDAP://{DC}/RootDSE → defaultNamingContext  (best: works for any DC hostname)
    ///   2. LDAP://{DC}         → distinguishedName      (mirrors PS Get-LdapQuery)
    ///   3. Derive from hostname, skipping the machine-name prefix:
    ///      dc1.domain.local (3+ parts) → DC=domain,DC=local
    ///      domain.local            (2  parts) → DC=domain,DC=local
    /// </summary>
    private string GetBaseDn()
    {
        if (_baseDn is not null)
            return _baseDn;

        if (!string.IsNullOrEmpty(_domainController))
        {
            // Strategy 1 — RootDSE on the specific DC (most reliable).
            try
            {
                using var rootDse = MakeEntry($"LDAP://{_domainController}/RootDSE");
                rootDse.RefreshCache(["defaultNamingContext"]);
                _baseDn = rootDse.Properties["defaultNamingContext"]?[0]?.ToString();
            }
            catch { }

            // Strategy 2 — bind to DC root, read distinguishedName (mirrors PS).
            if (string.IsNullOrEmpty(_baseDn))
            {
                try
                {
                    using var root = MakeEntry($"LDAP://{_domainController}");
                    root.RefreshCache(["distinguishedName"]);
                    _baseDn = root.Properties["distinguishedName"]?[0]?.ToString();
                }
                catch { }
            }

            // Strategy 3 — derive from the hostname.
            // DC hostname: machineName.domain.tld (3+ labels) → skip first label.
            // Domain name: domain.tld             (2  labels) → use all labels.
            if (string.IsNullOrEmpty(_baseDn) && _domainController.Contains('.'))
            {
                var parts = _domainController.Split('.');
                var domainParts = parts.Length >= 3 ? parts.Skip(1) : parts;
                _baseDn = string.Join(",", domainParts.Select(p => $"DC={p}"));
            }
        }
        else
        {
            // No DC — RootDSE auto-discovery on a domain-joined machine.
            try
            {
                using var rootDse = MakeEntry("LDAP://RootDSE");
                rootDse.RefreshCache(["defaultNamingContext"]);
                _baseDn = rootDse.Properties["defaultNamingContext"]?[0]?.ToString();
            }
            catch { }
        }

        if (string.IsNullOrEmpty(_baseDn))
            throw new InvalidOperationException(
                $"Could not determine base DN for '{_domainController ?? "auto-discover"}'. " +
                "Verify the DC is reachable and credentials are correct. " +
                "Use -d with a specific DC hostname (e.g. dc1.domain.local), not the domain name.");

        return _baseDn;
    }

    private DirectoryEntry BuildDirectoryEntry(string? ldapPath)
    {
        // GetBaseDn() always returns a non-empty string or throws, so all
        // null/empty guards that existed here are no longer needed.
        string baseDn = GetBaseDn();

        string fullDn = !string.IsNullOrEmpty(ldapPath)
            ? $"{ldapPath},{baseDn}"
            : baseDn;

        string ldapUri = !string.IsNullOrEmpty(_domainController)
            ? $"LDAP://{_domainController}/{fullDn}"
            : $"LDAP://{fullDn}";

        return MakeEntry(ldapUri);
    }

    private DirectoryEntry MakeEntry(string path) =>
        _credential is not null
            ? new DirectoryEntry(path, _credential.UserName, _credential.Password)
            : new DirectoryEntry(path);

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
