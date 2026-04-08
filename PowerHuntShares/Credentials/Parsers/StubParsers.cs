using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using PowerHuntShares.Credentials.Models;

// ─────────────────────────────────────────────────────────────────────────────
// Full implementations for every Get-Pw* parser ported from PowerHuntShares.psm1.
// Each class inherits StubParserBase and overrides Parse().
// ─────────────────────────────────────────────────────────────────────────────

namespace PowerHuntShares.Credentials.Parsers;

// ─── wp-config.php  (Get-PwWordPressConfig, line 24352) ──────────────────────
public class WordPressConfigParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["wp-config.php"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string? dbUser = null, dbPass = null;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                var mu = Regex.Match(line, @"define\(\s*'DB_USER'\s*,\s*'([^']+)'\s*\)");
                if (mu.Success) dbUser = mu.Groups[1].Value;
                var mp = Regex.Match(line, @"define\(\s*'DB_PASSWORD'\s*,\s*'([^']+)'\s*\)");
                if (mp.Success) dbPass = mp.Groups[1].Value;
            }
            if (dbUser is not null && dbPass is not null)
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: dbUser, password: dbPass,
                    parser: nameof(WordPressConfigParser))];
        }
        catch { }
        return [];
    }
}

// ─── vnc.ini  (Get-PwVnc, line 24477) ────────────────────────────────────────
// Fixed-key DES/ECB obfuscation — not real encryption.
public class VncParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["vnc.ini", "*.vnc"];

    private static readonly byte[] DesKey =
        [0x23, 0x52, 0x6A, 0x3B, 0x58, 0x92, 0x67, 0x34];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        try
        {
            string? encHex = null;
            foreach (var line in File.ReadLines(filePath))
            {
                var m = Regex.Match(line.Trim(), @"^Password=(.+)$");
                if (m.Success) { encHex = m.Groups[1].Value.Trim(); break; }
            }
            if (string.IsNullOrEmpty(encHex)) return [];

            byte[] encBytes = Convert.FromHexString(encHex);
            using var des = DES.Create();
            des.Key = DesKey;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            using var dec = des.CreateDecryptor();
            byte[] decBytes = dec.TransformFinalBlock(encBytes, 0, encBytes.Length);
            string password = Encoding.ASCII.GetString(decBytes).TrimEnd('\0');

            return [Mk(computerName, shareName, uncFilePath, fn,
                password: password, passwordEncoded: encHex,
                parser: nameof(VncParser))];
        }
        catch { }
        return [];
    }
}

// ─── unattend.xml  (Get-PwUnattendFile, line 24558) ──────────────────────────
public class UnattendParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns =>
        ["unattend.xml", "unattended.xml", "autounattend.xml"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            XDocument doc = XDocument.Load(filePath);
            XNamespace un = "urn:schemas-microsoft-com:unattend";

            foreach (var comp in doc.Descendants(un + "component")
                .Where(c => (string?)c.Attribute("name") == "Microsoft-Windows-Shell-Setup"))
            {
                var al = comp.Element(un + "AutoLogon");
                if (al is null) continue;
                string? user = (string?)al.Element(un + "Username");
                var pwEl = al.Element(un + "Password");
                string? pwd = (string?)pwEl?.Element(un + "Value");
                bool plain = ((string?)pwEl?.Element(un + "PlainText") ?? "false")
                    .Equals("true", StringComparison.OrdinalIgnoreCase);
                if (!plain && pwd is not null) pwd = TryDecodeBase64(pwd);
                if (user is not null && pwd is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: "AutoLogon", username: user, password: pwd,
                        parser: nameof(UnattendParser)));
            }

            foreach (var acct in doc.Descendants(un + "LocalAccount"))
            {
                string? user = (string?)acct.Element(un + "Name");
                var pwEl = acct.Element(un + "Password");
                string? pwd = (string?)pwEl?.Element(un + "Value");
                bool plain = ((string?)pwEl?.Element(un + "PlainText") ?? "false")
                    .Equals("true", StringComparison.OrdinalIgnoreCase);
                if (!plain && pwd is not null) pwd = TryDecodeBase64(pwd);
                if (user is not null && pwd is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: "LocalAccount", username: user, password: pwd,
                        parser: nameof(UnattendParser)));
            }
        }
        catch { }
        return results;
    }

    private static string TryDecodeBase64(string s)
    {
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(s)); }
        catch { return s; }
    }
}

// ─── tomcat-users.xml  (Get-PwTomcatUsers, line 24672) ───────────────────────
public class TomcatUsersParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["tomcat-users.xml"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            XDocument doc = XDocument.Load(filePath);
            foreach (var user in doc.Descendants("user"))
            {
                string? name = (string?)user.Attribute("name");
                string? pwd = (string?)user.Attribute("password");
                if (name is not null && pwd is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        username: name, password: pwd,
                        parser: nameof(TomcatUsersParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── tnsnames.ora  (Get-PwTnsOra, line 24727) ────────────────────────────────
public class TnsNamesParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["tnsnames.ora"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        string? db = null, user = null, pwd = null;
        try
        {
            void Flush()
            {
                if (db is not null && user is not null && pwd is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        database: db, username: user, password: pwd,
                        parser: nameof(TnsNamesParser)));
            }

            foreach (var rawLine in File.ReadLines(filePath))
            {
                string line = rawLine.Trim();
                if (Regex.IsMatch(line, @"^\w+\s*=\s*$"))
                {
                    Flush();
                    db = line.TrimEnd('=', ' ');
                    user = pwd = null;
                }
                else if (Regex.Match(line, @"USER\s*=\s*(.+)\)$") is { Success: true } mu)
                    user = mu.Groups[1].Value;
                else if (Regex.Match(line, @"PASSWORD\s*=\s*(.+)\)$") is { Success: true } mp)
                    pwd = mp.Groups[1].Value;
            }
            Flush();
        }
        catch { }
        return results;
    }
}

// ─── sysprep.inf  (Get-PwSysprepFile, line 24825) ────────────────────────────
public class SysprepParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["sysprep.inf"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string? adminPwd = null, domain = null, domainAdmin = null, domainPwd = null;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (Regex.Match(line, @"^AdminPassword\s*=\s*(.+)$") is { Success: true } m)
                    adminPwd = m.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"^JoinDomain\s*=\s*(.+)$") is { Success: true } m2)
                    domain = m2.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"^DomainAdmin\s*=\s*(.+)$") is { Success: true } m3)
                    domainAdmin = m3.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"^DomainAdminPassword\s*=\s*(.+)$") is { Success: true } m4)
                    domainPwd = m4.Groups[1].Value.Trim();
            }
        }
        catch { }

        return
        [
            Mk(computerName, shareName, uncFilePath, fn,
                domain: "localhost", username: "Administrator",
                password: adminPwd ?? string.Empty, parser: nameof(SysprepParser)),
            Mk(computerName, shareName, uncFilePath, fn,
                domain: domain ?? string.Empty, username: domainAdmin ?? string.Empty,
                password: domainPwd ?? string.Empty, parser: nameof(SysprepParser))
        ];
    }
}

// ─── standalone.xml  (Get-PwStandalone, line 24918) ──────────────────────────
public class StandaloneXmlParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["standalone.xml"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            XDocument doc = XDocument.Load(filePath);
            var ds = doc.Descendants()
                        .FirstOrDefault(e => e.Name.LocalName == "datasource");

            string connUrl = (string?)ds?.Elements()
                                .FirstOrDefault(e => e.Name.LocalName == "connection-url")
                             ?? string.Empty;
            string server = string.Empty, port = "3306";
            var mu = Regex.Match(connUrl, @"jdbc:mysql://([^:/]+)(?::(\d+))?");
            if (mu.Success) { server = mu.Groups[1].Value; if (mu.Groups[2].Success) port = mu.Groups[2].Value; }

            var sec = ds?.Elements().FirstOrDefault(e => e.Name.LocalName == "security");
            string? user = (string?)sec?.Elements().FirstOrDefault(e => e.Name.LocalName == "user-name");
            string? pwd  = (string?)sec?.Elements().FirstOrDefault(e => e.Name.LocalName == "password");

            results.Add(Mk(computerName, shareName, uncFilePath, fn,
                targetServer: server, targetPort: port,
                username: user ?? string.Empty, password: pwd ?? string.Empty,
                parser: nameof(StandaloneXmlParser)));

            // Vault keystore
            var ke = doc.Descendants()
                        .FirstOrDefault(e => e.Name.LocalName == "vault-option"
                                          && (string?)e.Attribute("name") == "KEYSTORE_PASSWORD");
            results.Add(Mk(computerName, shareName, uncFilePath, fn,
                username: "Keystore",
                password: (string?)ke?.Attribute("value") ?? string.Empty,
                parser: nameof(StandaloneXmlParser)));
        }
        catch { }
        return results;
    }
}

// ─── sssd.conf  (Get-PwSssdConfig, line 25009) ───────────────────────────────
public class SssdParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["sssd.conf"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string? domain = null, server = null, user = null, pwd = null;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (line.TrimStart().StartsWith('#') || string.IsNullOrWhiteSpace(line)) continue;
                if      (Regex.Match(line, @"ad_domain\s*=\s*(.+)")            is { Success: true } m)  domain = m.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"krb5_server\s*=\s*(.+)")          is { Success: true } m2) server = m2.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"ldap_default_bind_dn\s*=\s*(.+)") is { Success: true } m3) user   = m3.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"ldap_default_authtok\s*=\s*(.+)") is { Success: true } m4) pwd    = m4.Groups[1].Value.Trim();
            }
            return [Mk(computerName, shareName, uncFilePath, fn,
                domain: domain ?? "NA", targetServer: server ?? "NA",
                username: user ?? string.Empty, password: pwd ?? string.Empty,
                parser: nameof(SssdParser))];
        }
        catch { }
        return [];
    }
}

// ─── smb.conf  (Get-PwSmbConf, line 25089) ───────────────────────────────────
public class SmbConfParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["smb.conf"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string? user = null, pwd = null;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (line.TrimStart().StartsWith('#') || string.IsNullOrWhiteSpace(line)) continue;
                if      (Regex.Match(line, @"^\s*username\s*=\s*(.+)") is { Success: true } mu) user = mu.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"^\s*password\s*=\s*(.+)") is { Success: true } mp) pwd  = mp.Groups[1].Value.Trim();
            }
            if (user is not null && pwd is not null)
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: user, password: pwd, parser: nameof(SmbConfParser))];
        }
        catch { }
        return [];
    }
}

// ─── SiteManager.xml  (Get-PwSiteManagerConfig, line 25166) ──────────────────
public class SiteManagerParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["sitemanager.xml", "SiteManager.xml"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            XDocument doc = XDocument.Load(filePath);
            foreach (var srv in doc.Descendants("Server"))
            {
                string? host    = (string?)srv.Element("Host");
                string? port    = (string?)srv.Element("Port");
                string? userEl  = (string?)srv.Element("User");
                string? passB64 = srv.Element("Pass")?.Value?.Trim();
                string decoded  = string.Empty;
                if (!string.IsNullOrEmpty(passB64))
                    try { decoded = Encoding.UTF8.GetString(Convert.FromBase64String(passB64)); }
                    catch { decoded = "Error decoding password"; }

                results.Add(Mk(computerName, shareName, uncFilePath, fn,
                    targetServer: host ?? "NA", targetPort: port ?? "NA",
                    username: userEl ?? string.Empty, password: decoded,
                    passwordEncoded: passB64 ?? "NA",
                    parser: nameof(SiteManagerParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── /etc/shadow  (Get-PwShadow, line 25231) ─────────────────────────────────
public class ShadowParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["shadow"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
                var f = line.Split(':');
                if (f.Length >= 2)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        username: f[0], password: "NA",
                        passwordEncoded: f[1], parser: nameof(ShadowParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── *.ini generic  (Get-PwIniFile, line 25301) ──────────────────────────────
public class GenericIniParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["*.ini"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        string section = string.Empty;
        string? user = null, pwd = null;
        try
        {
            void Flush()
            {
                if (user is not null && pwd is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: section, username: user, password: pwd,
                        parser: nameof(GenericIniParser)));
            }

            foreach (var line in File.ReadLines(filePath))
            {
                if (line.TrimStart().StartsWith(';') || string.IsNullOrWhiteSpace(line)) continue;
                var sm = Regex.Match(line, @"^\s*\[(.+)\]\s*$");
                if (sm.Success) { Flush(); user = pwd = null; section = sm.Groups[1].Value.Trim(); continue; }

                if      (Regex.Match(line, @"^\s*(?:username|user)\s*=\s*(.+)$") is { Success: true } mu) user = mu.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"^\s*(?:password|pass)\s*=\s*(.+)$") is { Success: true } mp) pwd  = mp.Groups[1].Value.Trim();
            }
            Flush();
        }
        catch { }
        return results;
    }
}

// ─── server.xml  (Get-PwServerXml, line 25523) ───────────────────────────────
public class ServerXmlParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["server.xml"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            XDocument doc = XDocument.Load(filePath);
            var root = doc.Root;
            if (root is null) return results;

            // basicRegistry users
            foreach (var u in root.Descendants("user")
                .Where(e => e.Parent?.Name.LocalName == "basicRegistry"))
            {
                string? name = (string?)u.Attribute("name");
                string? p    = (string?)u.Attribute("password");
                if (name is not null && p is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: "basicRegistry", username: name, password: p,
                        parser: nameof(ServerXmlParser)));
            }

            // Variable DB_USER / DB_PASS
            string? dbUser = (string?)root.Elements("variable")
                .FirstOrDefault(e => (string?)e.Attribute("name") == "DB_USER")?.Attribute("value");
            string? dbPass = (string?)root.Elements("variable")
                .FirstOrDefault(e => (string?)e.Attribute("name") == "DB_PASS")?.Attribute("value");
            if (dbUser is not null && dbPass is not null)
                results.Add(Mk(computerName, shareName, uncFilePath, fn,
                    section: "variable", username: dbUser, password: dbPass,
                    parser: nameof(ServerXmlParser)));

            foreach (var auth in root.Descendants("containerAuthData"))
            {
                string? u = (string?)auth.Attribute("user");
                string? p = (string?)auth.Attribute("password");
                if (u is not null && p is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: "containerAuthData", username: u, password: p,
                        parser: nameof(ServerXmlParser)));
            }

            foreach (var auth in root.Elements("authData"))
            {
                string? u = (string?)auth.Attribute("user");
                string? p = (string?)auth.Attribute("password");
                if (u is not null && p is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: "authData", username: u, password: p,
                        parser: nameof(ServerXmlParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── pure-ftpd.passwd  (Get-PwPureFtpConfig, line 25637) ─────────────────────
public class PureFtpParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["pure-ftpd.passwd", "pureftpd.passwd"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var f = line.Split(':');
                if (f.Length >= 2)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        username: f[0], password: "NA",
                        passwordEncoded: f[1], parser: nameof(PureFtpParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── php.ini  (Get-PwPhpIni, line 25703) ─────────────────────────────────────
public class PhpIniParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["php.ini"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string? user = null, pwd = null;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (line.TrimStart().StartsWith(';') || string.IsNullOrWhiteSpace(line)) continue;
                if      (Regex.Match(line, @"^\s*mysql\.default_user\s*=\s*""(.+)""")     is { Success: true } mu) user = mu.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"^\s*mysql\.default_password\s*=\s*""(.+)""") is { Success: true } mp) pwd  = mp.Groups[1].Value.Trim();
            }
            if (user is not null && pwd is not null)
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: user, password: pwd, parser: nameof(PhpIniParser))];
        }
        catch { }
        return [];
    }
}

// ─── my.cnf / my.ini  (Get-PwMySQLConfig, line 25771) ────────────────────────
public class MySqlConfigParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["my.cnf", "my.ini"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string? user = null, pwd = null;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if      (Regex.Match(line, @"^\s*user\s*=\s*(.+)$")     is { Success: true } mu) user = mu.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"^\s*password\s*=\s*(.+)$") is { Success: true } mp) pwd  = mp.Groups[1].Value.Trim();
            }
            if (user is not null && pwd is not null)
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: user, password: pwd, parser: nameof(MySqlConfigParser))];
        }
        catch { }
        return [];
    }
}

// ─── machine.config  (Get-PwMachineConfig, line 25836) ───────────────────────
public class MachineConfigParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["machine.config"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            XDocument doc = XDocument.Load(filePath);

            // connectionStrings
            foreach (var add in doc.Descendants("connectionStrings").Elements("add"))
            {
                string cs       = (string?)add.Attribute("connectionString") ?? string.Empty;
                string name     = (string?)add.Attribute("name")             ?? string.Empty;
                string provider = (string?)add.Attribute("providerName")     ?? string.Empty;
                ParseCs(cs, out string srv, out string port, out string db, out string u, out string p);
                if (!string.IsNullOrEmpty(u) && !string.IsNullOrEmpty(p))
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: $"ConnectionStrings ({provider})", objectName: name,
                        targetServer: srv, targetPort: port, database: db,
                        username: u, password: p, parser: nameof(MachineConfigParser)));
            }

            // appSettings
            var app = doc.Descendants("appSettings").Elements("add")
                .ToDictionary(
                    e => ((string?)e.Attribute("key") ?? "").ToLowerInvariant(),
                    e => (string?)e.Attribute("value") ?? "");
            string appUser = FindVal(app, "username", "user", "serviceusername", "apiusername");
            string appPass = FindVal(app, "password", "pwd", "pass", "servicepassword", "apipassword");
            if (!string.IsNullOrEmpty(appUser) && !string.IsNullOrEmpty(appPass))
                results.Add(Mk(computerName, shareName, uncFilePath, fn,
                    section: "appSettings", username: appUser, password: appPass,
                    parser: nameof(MachineConfigParser)));

            // SMTP
            foreach (var smtp in doc.Descendants("smtp"))
            {
                var net = smtp.Element("network");
                if (net is null) continue;
                string? su = (string?)net.Attribute("userName");
                string? sp = (string?)net.Attribute("password");
                if (!string.IsNullOrEmpty(su) && !string.IsNullOrEmpty(sp))
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: "SMTP",
                        targetServer: (string?)net.Attribute("host") ?? "NA",
                        targetPort:   (string?)net.Attribute("port") ?? "NA",
                        username: su, password: sp, parser: nameof(MachineConfigParser)));
            }
        }
        catch { }
        return results;
    }

    private static void ParseCs(string cs, out string server, out string port,
        out string database, out string user, out string password)
    {
        server = database = user = password = port = string.Empty;
        var pg = Regex.Match(cs,
            @"Host\s*=\s*([^;]+).*?Port\s*=\s*(\d+).*?Username\s*=\s*([^;]+).*?Password\s*=\s*([^;]+)",
            RegexOptions.IgnoreCase);
        if (pg.Success)
        {
            server = pg.Groups[1].Value.Trim(); port = pg.Groups[2].Value.Trim();
            user = pg.Groups[3].Value.Trim(); password = pg.Groups[4].Value.Trim(); return;
        }
        var srv = Regex.Match(cs, @"(?:Server|Data Source)\s*=\s*([^;,]+)(?:,(\d+))?", RegexOptions.IgnoreCase);
        if (srv.Success) { server = srv.Groups[1].Value.Trim(); port = srv.Groups[2].Value.Trim(); }
        var db = Regex.Match(cs, @"(?:Initial Catalog|Database)\s*=\s*([^;]+)", RegexOptions.IgnoreCase);
        if (db.Success) database = db.Groups[1].Value.Trim();
        var uid = Regex.Match(cs, @"User\s*Id\s*=\s*([^;]+)", RegexOptions.IgnoreCase);
        if (uid.Success) user = uid.Groups[1].Value.Trim();
        var pwd = Regex.Match(cs, @"Password\s*=\s*([^;]+)", RegexOptions.IgnoreCase);
        if (pwd.Success) password = pwd.Groups[1].Value.Trim();
    }

    private static string FindVal(Dictionary<string, string> d, params string[] keys)
    {
        foreach (var k in keys)
            if (d.TryGetValue(k, out var v) && !string.IsNullOrEmpty(v)) return v;
        return string.Empty;
    }
}

// ─── krb5.conf  (Get-Pwkrb5Conf, line 26030) ─────────────────────────────────
public class Krb5ConfParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["krb5.conf"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string? domain = null, server = null, user = null, pwd = null;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (line.TrimStart().StartsWith('#') || string.IsNullOrWhiteSpace(line)) continue;
                if      (Regex.Match(line, @"default_realm\s*=\s*(.+)")            is { Success: true } m)  domain = m.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"kdc\s*=\s*(.+)")                       is { Success: true } m2) server = m2.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"principal\s*=\s*(.+)")                 is { Success: true } m3) user   = m3.Groups[1].Value.Trim();
                else if (user is null && Regex.Match(line, @"ldap_default_bind_dn\s*=\s*(.+)") is { Success: true } m4) user = m4.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"\bpassword\s*=\s*(.+)")                is { Success: true } m5) pwd    = m5.Groups[1].Value.Trim();
                else if (pwd is null && Regex.Match(line, @"ldap_default_authtok\s*=\s*(.+)") is { Success: true } m6) pwd = m6.Groups[1].Value.Trim();
            }
            return [Mk(computerName, shareName, uncFilePath, fn,
                domain: domain ?? "NA", targetServer: server ?? "NA",
                username: user ?? string.Empty, password: pwd ?? string.Empty,
                parser: nameof(Krb5ConfParser))];
        }
        catch { }
        return [];
    }
}

// ─── jboss-cli.xml  (Get-PwJbossCliConfig, line 26117) ───────────────────────
public class JbossCliParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["jboss-cli.xml"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        try
        {
            XDocument doc = XDocument.Load(filePath);
            var auth = doc.Descendants("authentication").FirstOrDefault();
            string? user = (string?)auth?.Element("username");
            string? pwd  = (string?)auth?.Element("password");
            if (user is not null || pwd is not null)
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: user ?? string.Empty, password: pwd ?? string.Empty,
                    parser: nameof(JbossCliParser))];
        }
        catch { }
        return [];
    }
}

// ─── .htpasswd  (Get-PwHtpasswd, line 26164) ─────────────────────────────────
public class HtpasswdParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => [".htpasswd", "htpasswd"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var p = line.Split(':', 2);
                if (p.Length == 2)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        username: p[0], password: "NA",
                        passwordEncoded: p[1], parser: nameof(HtpasswdParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── dbxdrivers.ini / db.ini  (Get-PwDbxDriverIni, line 26223) ───────────────
public class DbxDriverParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["dbxdrivers.ini", "db.ini"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        string section = string.Empty;
        string? user = null, pwd = null;
        try
        {
            void Flush()
            {
                if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(pwd))
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: section, username: user, password: pwd,
                        parser: nameof(DbxDriverParser)));
            }

            foreach (var line in File.ReadLines(filePath))
            {
                var sm = Regex.Match(line, @"^\[(.+)\]$");
                if (sm.Success) { Flush(); section = sm.Groups[1].Value.Trim(); user = pwd = null; continue; }
                if      (Regex.Match(line, @"^User_Name=(.*)$") is { Success: true } mu) user = mu.Groups[1].Value.Trim();
                else if (Regex.Match(line, @"^Password=(.*)$")  is { Success: true } mp) pwd  = mp.Groups[1].Value.Trim();
            }
            Flush();
        }
        catch { }
        return results;
    }
}

// ─── context.xml  (Get-PwContextXML, line 26323) ─────────────────────────────
public class ContextXmlParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["context.xml"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            XDocument doc = XDocument.Load(filePath);
            foreach (var res in doc.Descendants("Resource"))
            {
                string? user = (string?)res.Attribute("username");
                string? pwd  = (string?)res.Attribute("password");
                if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(pwd))
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        objectName: (string?)res.Attribute("name") ?? "NA",
                        username: user, password: pwd,
                        parser: nameof(ContextXmlParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── config.xml  (Get-PwJenkinsConfig, line 26376) ───────────────────────────
public class JenkinsConfigParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["config.xml"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        try
        {
            string text = File.ReadAllText(filePath)
                .Replace("version='1.1'",  "version='1.0'")
                .Replace("version=\"1.1\"", "version=\"1.0\"");
            XDocument doc = XDocument.Parse(text);
            string? name = (string?)doc.Descendants("fullName").FirstOrDefault();
            string? hash = (string?)doc.Descendants("passwordHash").FirstOrDefault();
            if (name is not null || hash is not null)
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: name ?? string.Empty, password: hash ?? string.Empty,
                    parser: nameof(JenkinsConfigParser))];
        }
        catch { }
        return [];
    }
}

// ─── *.bds  (Get-PwBaramundiPreInst, line 26434) ─────────────────────────────
public class BaramundiParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["*.bds"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        try
        {
            string content = File.ReadAllText(filePath);
            var mu = Regex.Match(content, @"<VALUE>/User=(.*)</VALUE>");
            var mp = Regex.Match(content, @"<VALUE>/PWD=(.*)</VALUE>");
            string? user = mu.Success ? mu.Groups[1].Value : null;
            string? pwd  = mp.Success ? mp.Groups[1].Value : null;
            if (user is not null || pwd is not null)
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: user ?? string.Empty, password: pwd ?? string.Empty,
                    parser: nameof(BaramundiParser))];
        }
        catch { }
        return [];
    }
}

// ─── bootstrap.ini  (Get-PwBootstrapConfig, line 26490) ──────────────────────
public class BootstrapIniParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["bootstrap.ini"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        string? currentUser = null;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if      (Regex.Match(line, @"username\s*=\s*(.*)") is { Success: true } mu) { currentUser = mu.Groups[1].Value.Trim(); }
                else if (Regex.Match(line, @"password\s*=\s*(.*)")  is { Success: true } m1) results.Add(Mk(computerName, shareName, uncFilePath, fn, username: currentUser ?? string.Empty, password: m1.Groups[1].Value.Trim(), parser: nameof(BootstrapIniParser)));
                else if (Regex.Match(line, @"public\s*=\s*(.*)")    is { Success: true } m2) results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "Public",  password: m2.Groups[1].Value.Trim(), parser: nameof(BootstrapIniParser)));
                else if (Regex.Match(line, @"private\s*=\s*(.*)")   is { Success: true } m3) results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "Private", password: m3.Groups[1].Value.Trim(), parser: nameof(BootstrapIniParser)));
                else if (Regex.Match(line, @"\bkey\s*=\s*(.*)")     is { Success: true } m4) results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "Key",     password: m4.Groups[1].Value.Trim(), parser: nameof(BootstrapIniParser)));
                else if (Regex.Match(line, @"secret\s*=\s*(.*)")    is { Success: true } m5) results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "Secret",  password: m5.Groups[1].Value.Trim(), parser: nameof(BootstrapIniParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── .pgpass  (Get-PwPgPass, line 26817) ─────────────────────────────────────
public class PgPassParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => [".pgpass", "pgpass"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#')) continue;
                var f = line.Split(':');
                if (f.Length == 5)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        targetServer: f[0], targetPort: f[1], database: f[2],
                        username: f[3], password: f[4], parser: nameof(PgPassParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── GPP XML files  (Get-PwGPP, line 26886) ──────────────────────────────────
// Decrypts cpassword with the well-known AES key published by Microsoft (MS14-025).
public class GppParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns =>
        ["Groups.xml", "ScheduledTasks.xml", "Services.xml",
         "DataSources.xml", "Printers.xml", "Drives.xml"];

    private static readonly byte[] AesKey =
    [
        0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,
        0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
        0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
    ];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            XDocument doc = XDocument.Load(filePath);

            IEnumerable<(string? user, string? cpass)> pairs =
                fn.ToLowerInvariant() switch
                {
                    "groups.xml"        => doc.Descendants("User").Select(e =>
                                            ((string?)e.Element("Properties")?.Attribute("username"),
                                             (string?)e.Element("Properties")?.Attribute("cpassword"))),
                    "drives.xml"        => doc.Descendants("Drive").Select(e =>
                                            ((string?)e.Element("Properties")?.Attribute("username"),
                                             (string?)e.Element("Properties")?.Attribute("cpassword"))),
                    "services.xml"      => doc.Descendants("NTService").Select(e =>
                                            ((string?)e.Element("Properties")?.Attribute("accountname"),
                                             (string?)e.Element("Properties")?.Attribute("cpassword"))),
                    "scheduledtasks.xml"=> doc.Descendants("Task").Select(e =>
                                            ((string?)e.Element("Properties")?.Attribute("runas"),
                                             (string?)e.Element("Properties")?.Attribute("cpassword"))),
                    "datasources.xml"   => doc.Descendants("DataSource").Select(e =>
                                            ((string?)e.Element("Properties")?.Attribute("username"),
                                             (string?)e.Element("Properties")?.Attribute("cpassword"))),
                    "printers.xml"      => doc.Descendants("SharedPrinter").Select(e =>
                                            ((string?)e.Element("Properties")?.Attribute("username"),
                                             (string?)e.Element("Properties")?.Attribute("cpassword"))),
                    _                   => []
                };

            foreach (var (user, cpass) in pairs)
            {
                string pwd = string.Empty;
                if (!string.IsNullOrEmpty(cpass))
                    try { pwd = DecryptCPassword(cpass); } catch { }
                results.Add(Mk(computerName, shareName, uncFilePath, fn,
                    username: user ?? string.Empty, password: pwd,
                    passwordEncoded: cpass ?? "NA", parser: nameof(GppParser)));
            }
        }
        catch { }
        return results;
    }

    private static string DecryptCPassword(string cpassword)
    {
        int mod = cpassword.Length % 4;
        if (mod == 1) cpassword = cpassword[..^1];
        else if (mod == 2) cpassword += "==";
        else if (mod == 3) cpassword += "=";

        byte[] data = Convert.FromBase64String(cpassword);
        using var aes = Aes.Create();
        aes.Key = AesKey;
        aes.IV = new byte[16];
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        byte[] plain = dec.TransformFinalBlock(data, 0, data.Length);
        return Encoding.Unicode.GetString(plain).TrimEnd('\0');
    }
}

// ─── *.dtsx  (Get-PwSsisDtsx, line 27189) ────────────────────────────────────
public class DtsxParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["*.dtsx"];

    private const string DtsNs = "http://schemas.microsoft.com/sqlserver/Dts";

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.Load(filePath);
            var ns = new XmlNamespaceManager(xmlDoc.NameTable);
            ns.AddNamespace("DTS", DtsNs);

            string Prop(XmlNode? node, string name) =>
                node?.SelectSingleNode($"DTS:Property[@DTS:Name='{name}']", ns)?.InnerText
                ?? string.Empty;

            // OLEDB
            var oledbNodes = xmlDoc.SelectNodes(
                "//DTS:ConnectionManager[@DTS:CreationName='OLEDB']/DTS:Properties", ns);
            if (oledbNodes != null)
                foreach (XmlNode? cm in oledbNodes)
                {
                    if (cm is null) continue;
                    string cs = Prop(cm, "ConnectionString");
                    var m = Regex.Match(cs,
                        @"Data Source=([^;]+);.*User ID=([^;]+);.*Password=([^;]+);",
                        RegexOptions.IgnoreCase);
                    if (m.Success)
                        results.Add(Mk(computerName, shareName, uncFilePath, fn,
                            section: "Database", targetServer: m.Groups[1].Value,
                            username: m.Groups[2].Value, password: m.Groups[3].Value,
                            parser: nameof(DtsxParser)));
                }

            // FTP
            var ftpNodes = xmlDoc.SelectNodes(
                "//DTS:ConnectionManager[@DTS:CreationName='FTP']/DTS:Properties", ns);
            if (ftpNodes != null)
                foreach (XmlNode? cm in ftpNodes)
                {
                    if (cm is null) continue;
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: "FTP",
                        targetServer: Prop(cm, "ServerName"),
                        targetPort:   Prop(cm, "ServerPort"),
                        username:     Prop(cm, "ServerUserName"),
                        password:     Prop(cm, "ServerPassword"),
                        parser: nameof(DtsxParser)));
                }

            // SMTP
            var smtpNodes = xmlDoc.SelectNodes(
                "//DTS:ConnectionManager[@DTS:CreationName='SMTP']/DTS:Properties", ns);
            if (smtpNodes != null)
                foreach (XmlNode? cm in smtpNodes)
                {
                    if (cm is null) continue;
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: "SMTP",
                        targetServer: Prop(cm, "SmtpServer"),
                        targetPort:   Prop(cm, "Port"),
                        username:     Prop(cm, "UserName"),
                        password:     Prop(cm, "Password"),
                        parser: nameof(DtsxParser)));
                }
        }
        catch { }
        return results;
    }
}

// ─── *.rdp  (Get-PwRdpInfo, line 27310) ──────────────────────────────────────
public class RdpParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["*.rdp"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string user = string.Empty, encPwd = string.Empty, pwd = string.Empty;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (Regex.Match(line, @"^username:s:(.+)$")       is { Success: true } mu) user   = mu.Groups[1].Value;
                if (Regex.Match(line, @"^password 51:b:(.+)$")    is { Success: true } mp) encPwd = mp.Groups[1].Value;
            }
            if (!string.IsNullOrEmpty(encPwd))
            {
                try
                {
                    byte[] enc = Convert.FromBase64String(encPwd);
                    byte[] dec = System.Security.Cryptography.ProtectedData.Unprotect(
                        enc, null, System.Security.Cryptography.DataProtectionScope.CurrentUser);
                    pwd = Encoding.Unicode.GetString(dec);
                }
                catch { pwd = "Unable to decrypt; must run on target system"; }
            }
            if (!string.IsNullOrEmpty(user) || !string.IsNullOrEmpty(encPwd))
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: user, password: pwd, passwordEncoded: encPwd,
                    parser: nameof(RdpParser))];
        }
        catch { }
        return [];
    }
}

// ─── Private key files  (Get-PrivateKeyFilePath, line 27386) ─────────────────
public class PrivateKeyPathParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns =>
        ["id_rsa", "id_dsa", "id_ecdsa", "*.pem", "*.ppk"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
        => [Mk(computerName, shareName, uncFilePath, Path.GetFileName(filePath),
               keyFilePath: filePath, parser: nameof(PrivateKeyPathParser))];
}

// ─── Cisco IOS configs  (Get-PwCiscoConfig, line 27426) ──────────────────────
public class CiscoConfigParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["*.cfg", "cisco*.conf"];

    private static readonly byte[] Xlat =
    [
        0x64,0x73,0x66,0x64,0x3b,0x6b,0x66,0x6f,0x41,0x2c,0x2e,0x69,
        0x79,0x65,0x77,0x72,0x6b,0x6c,0x64,0x4a,0x4b,0x44,0x48,0x53,
        0x55,0x42,0x73,0x67,0x76,0x63,0x61,0x36,0x39,0x38,0x33,0x34,
        0x6e,0x63,0x78,0x76,0x39,0x38,0x37,0x33,0x32,0x35,0x34,0x6b,
        0x3b,0x66,0x67,0x38,0x37
    ];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                // enable secret 5 (MD5 — not decodable)
                if (Regex.Match(line, @"enable secret 5 (\S+)") is { Success: true } m1)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        objectName: "EnableSecret (MD5 Encrypted)",
                        passwordEncoded: m1.Groups[1].Value.Trim(),
                        parser: nameof(CiscoConfigParser)));

                // enable password (cleartext or Type 7)
                if (Regex.Match(line, @"enable password (\d*) *(\S+)") is { Success: true } m2)
                {
                    string type = m2.Groups[1].Value.Trim();
                    string val  = m2.Groups[2].Value.Trim();
                    if (type == "7") results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "EnablePassword (Type 7 Decrypted)", password: DecodeType7(val), passwordEncoded: val, parser: nameof(CiscoConfigParser)));
                    else             results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "EnablePassword (Cleartext)",         password: val,               parser: nameof(CiscoConfigParser)));
                }

                // username password/secret
                if (Regex.Match(line, @"username (\S+) (?:password|secret) (\d) (\S+)") is { Success: true } m3)
                {
                    string user = m3.Groups[1].Value.Trim(), type = m3.Groups[2].Value.Trim(), val = m3.Groups[3].Value.Trim();
                    if      (type == "7") results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "Username Password (Type 7 Decrypted)", username: user, password: DecodeType7(val), passwordEncoded: val, parser: nameof(CiscoConfigParser)));
                    else if (type == "5") results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "Username Password (MD5 Encrypted)",    username: user, passwordEncoded: val, parser: nameof(CiscoConfigParser)));
                    else                  results.Add(Mk(computerName, shareName, uncFilePath, fn, objectName: "Username Password (Cleartext)",         username: user, password: val, parser: nameof(CiscoConfigParser)));
                }

                // SNMP community string
                if (Regex.Match(line, @"snmp-server community (\S+) (RO|RW)") is { Success: true } m4)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        objectName: $"SNMP Community String ({m4.Groups[2].Value})",
                        password: m4.Groups[1].Value.Trim(),
                        parser: nameof(CiscoConfigParser)));

                // WPA PSK
                if (Regex.Match(line, @"wpa-psk ascii 0 (\S+)") is { Success: true } m5)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        objectName: "Wi-Fi WPA Pre-Shared Key (Cleartext)",
                        password: m5.Groups[1].Value.Trim(),
                        parser: nameof(CiscoConfigParser)));
            }
        }
        catch { }
        return results;
    }

    private string DecodeType7(string encoded)
    {
        if (encoded.Length < 2) return encoded;
        int seed = Convert.ToInt32(encoded[..2]);
        string enc = encoded[2..];
        var sb = new StringBuilder();
        for (int i = 0; i < enc.Length - 1; i += 2)
        {
            byte b = Convert.ToByte(enc.Substring(i, 2), 16);
            sb.Append((char)(b ^ Xlat[seed % Xlat.Length]));
            seed = (seed + 1) % Xlat.Length;
        }
        return sb.ToString();
    }
}

// ─── grub.cfg  (Get-PwGrubConfig, line 27664) ────────────────────────────────
public class GrubParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["grub.cfg"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        try
        {
            string content = File.ReadAllText(filePath);
            string? user = null, pwd = null;
            var mu = Regex.Match(content, @"set superusers\s*=\s*""([^""]+)""");
            if (mu.Success) user = mu.Groups[1].Value.Trim();
            if (user is not null)
            {
                var mp = Regex.Match(content, $@"password\s+{Regex.Escape(user)}\s+(\S+)");
                if (mp.Success) pwd = mp.Groups[1].Value.Trim();
            }
            if (user is not null || pwd is not null)
                return [Mk(computerName, shareName, uncFilePath, fn,
                    username: user ?? string.Empty, password: pwd ?? string.Empty,
                    parser: nameof(GrubParser))];
        }
        catch { }
        return [];
    }
}

// ─── .netrc  (Get-PwNetrc, line 27734) ───────────────────────────────────────
public class NetrcParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => [".netrc", "netrc"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        string? server = null, user = null, pwd = null;
        try
        {
            void Flush()
            {
                if (server is not null)
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        targetServer: server, username: user ?? string.Empty,
                        password: pwd ?? string.Empty, parser: nameof(NetrcParser)));
            }

            foreach (var line in File.ReadLines(filePath))
            {
                if      (Regex.Match(line, @"^machine\s+(\S+)")  is { Success: true } mm) { Flush(); server = mm.Groups[1].Value; user = pwd = null; }
                else if (Regex.Match(line, @"^login\s+(\S+)")    is { Success: true } ml) user = ml.Groups[1].Value;
                else if (Regex.Match(line, @"^password\s+(\S+)") is { Success: true } mp) pwd  = mp.Groups[1].Value;
            }
            Flush();
        }
        catch { }
        return results;
    }
}

// ─── *.remmina  (Get-PwRemmina, line 27800) ──────────────────────────────────
public class RemminaParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["*.remmina"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        string vncSrv = "NA", vncPort = "NA", vncUser = "NA", vncPwd = "NA";
        string sshSrv = "NA", sshUser = "NA", sshKey = "NA";
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                Match rm;
                if      ((rm = Regex.Match(line, @"^server=(.+)")).Success)          vncSrv  = rm.Groups[1].Value.Trim();
                else if ((rm = Regex.Match(line, @"^listenport=(\d+)")).Success)     vncPort = rm.Groups[1].Value.Trim();
                else if ((rm = Regex.Match(line, @"^username=(.+)")).Success)        vncUser = rm.Groups[1].Value.Trim();
                else if ((rm = Regex.Match(line, @"^password=(.+)")).Success)        vncPwd  = rm.Groups[1].Value.Trim();
                else if ((rm = Regex.Match(line, @"^ssh_server=(.+)")).Success)      sshSrv  = rm.Groups[1].Value.Trim();
                else if ((rm = Regex.Match(line, @"^ssh_username=(.+)")).Success)    sshUser = rm.Groups[1].Value.Trim();
                else if ((rm = Regex.Match(line, @"^ssh_privatekey=(.+)")).Success)  sshKey  = rm.Groups[1].Value.Trim();
            }
        }
        catch { }

        return
        [
            Mk(computerName, shareName, uncFilePath, fn, objectName: "VNC",
                targetServer: vncSrv, targetPort: vncPort,
                username: vncUser, password: vncPwd, parser: nameof(RemminaParser)),
            Mk(computerName, shareName, uncFilePath, fn, objectName: "SSH",
                targetServer: sshSrv, username: sshUser,
                keyFilePath: sshKey, parser: nameof(RemminaParser))
        ];
    }
}

// ─── remmina.pref  (Get-PwRemminaPref, line 27896) ───────────────────────────
public class RemminaPrefParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["remmina.pref"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        bool inSection = false;
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                if (line.Trim() == "[remmina_pref]") { inSection = true; continue; }
                if (line.StartsWith('[')) { inSection = false; continue; }
                if (inSection && Regex.Match(line, @"^secret=(.+)") is { Success: true } m)
                    return [Mk(computerName, shareName, uncFilePath, fn,
                        section: "remmina_pref", objectName: "Remmina Configuration",
                        passwordEncoded: m.Groups[1].Value.Trim(),
                        parser: nameof(RemminaPrefParser))];
            }
        }
        catch { }
        return [];
    }
}

// ─── dbvis.xml  (Get-PwDbvisxml, line 27956) ─────────────────────────────────
// DbVisualizer encrypts passwords with PBEWithMD5AndDES (hard-coded key "qinda").
public class DbvisParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => ["dbvis.xml"];

    private static readonly byte[] Salt = [142, 18, 57, 156, 7, 114, 111, 90];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        try
        {
            XDocument doc = XDocument.Load(filePath);
            var conn = doc.Descendants("connection").FirstOrDefault();
            if (conn is null) return [];

            string url = (string?)conn.Element("url") ?? string.Empty;
            string server  = Regex.Replace(url, @"jdbc:\w+://([^:/]+).*", "$1");
            string port    = Regex.Replace(url, @".*:(\d+)/.*", "$1");
            string? user   = (string?)conn.Element("user");
            string? encPwd = (string?)conn.Element("password");
            string decPwd  = string.Empty;
            if (!string.IsNullOrEmpty(encPwd))
                try { decPwd = DbvDecrypt(encPwd); } catch { }

            return [Mk(computerName, shareName, uncFilePath, fn,
                targetServer: server, targetPort: port,
                username: user ?? string.Empty, password: decPwd,
                passwordEncoded: encPwd ?? "NA",
                parser: nameof(DbvisParser))];
        }
        catch { }
        return [];
    }

    private static string DbvDecrypt(string encBase64)
    {
        using var pbkdf = new Rfc2898DeriveBytes("qinda", Salt, 10, HashAlgorithmName.SHA1);
        byte[] key = pbkdf.GetBytes(8);
        using var des = DES.Create();
        des.Key = key;
        des.IV = Salt;
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.PKCS7;
        using var dec = des.CreateDecryptor();
        byte[] enc = Convert.FromBase64String(encBase64);
        return Encoding.UTF8.GetString(dec.TransformFinalBlock(enc, 0, enc.Length));
    }
}

// ─── .git-credentials  (Get-PwGitCredentials, line 28021) ───────────────────
public class GitCredentialsParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => [".git-credentials", "git-credentials"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                var m = Regex.Match(line.Trim(), @"https://([^:]+):([^@]+)@(.*)");
                if (!m.Success) continue;
                string rawTarget = m.Groups[3].Value;
                results.Add(Mk(computerName, shareName, uncFilePath, fn,
                    targetUrl: rawTarget,
                    targetServer: Regex.Replace(rawTarget, @"/.*", ""),
                    username: m.Groups[1].Value, password: m.Groups[2].Value,
                    parser: nameof(GitCredentialsParser)));
            }
        }
        catch { }
        return results;
    }
}

// ─── .fetchmailrc  (Get-PwFetchmailrc, line 28078) ───────────────────────────
public class FetchmailrcParser : StubParserBase
{
    public override IReadOnlyList<string> FilePatterns => [".fetchmailrc", "fetchmailrc"];

    public override IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
    {
        string fn = Path.GetFileName(filePath);
        var results = new List<CredentialFinding>();
        try
        {
            var lines = File.ReadLines(filePath)
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrEmpty(l) && !l.StartsWith('#'))
                .ToList();

            // Consolidate continuation lines into their stanza
            for (int i = lines.Count - 1; i > 0; i--)
            {
                if (!Regex.IsMatch(lines[i], @"^(defaults|poll|skip)\s+"))
                {
                    lines[i - 1] += " " + lines[i];
                    lines.RemoveAt(i);
                }
            }

            FetchCred defaults = new();
            foreach (var line in lines)
            {
                if (line.StartsWith("defaults")) { defaults = ParseFetchLine(line); continue; }
                var cred = ParseFetchLine(line);
                if (string.IsNullOrEmpty(cred.Server))   cred.Server   = defaults.Server;
                if (string.IsNullOrEmpty(cred.User))     cred.User     = defaults.User;
                if (string.IsNullOrEmpty(cred.Pass))     cred.Pass     = defaults.Pass;
                if (string.IsNullOrEmpty(cred.Protocol)) cred.Protocol = defaults.Protocol;
                if (string.IsNullOrEmpty(cred.Port))     cred.Port     = defaults.Port;

                if (!string.IsNullOrEmpty(cred.Server) && !string.IsNullOrEmpty(cred.User)
                                                       && !string.IsNullOrEmpty(cred.Pass))
                    results.Add(Mk(computerName, shareName, uncFilePath, fn,
                        section: cred.Protocol, targetServer: cred.Server, targetPort: cred.Port,
                        username: cred.User, password: cred.Pass,
                        parser: nameof(FetchmailrcParser)));
            }
        }
        catch { }
        return results;
    }

    private sealed class FetchCred
    {
        public string Server   { get; set; } = string.Empty;
        public string User     { get; set; } = string.Empty;
        public string Pass     { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public string Port     { get; set; } = string.Empty;
    }

    private static FetchCred ParseFetchLine(string line)
    {
        var c = new FetchCred();
        var ms  = Regex.Match(line, @"^(?:poll|skip)\s+(\S+)");        if (ms.Success)  c.Server   = ms.Groups[1].Value;
        var mu  = Regex.Match(line, @"\s+user(?:name)?\s+""([^""]+)"""); if (mu.Success)  c.User     = mu.Groups[1].Value;
        var mp  = Regex.Match(line, @"\s+pass(?:word)?\s+""([^""]+)"""); if (mp.Success)  c.Pass     = mp.Groups[1].Value;
        var mpr = Regex.Match(line, @"\s+proto(?:col)?\s+(\S+)");       if (mpr.Success) c.Protocol = mpr.Groups[1].Value;
        var mpo = Regex.Match(line, @"\s+(?:port|service)\s+(\S+)");    if (mpo.Success) c.Port     = mpo.Groups[1].Value;
        return c;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract base — subclasses override Parse() with real implementations above.
// ─────────────────────────────────────────────────────────────────────────────
public abstract class StubParserBase : IConfigParser
{
    public abstract IReadOnlyList<string> FilePatterns { get; }

    public virtual IReadOnlyList<CredentialFinding> Parse(
        string filePath, string computerName, string shareName, string uncFilePath)
        => [];

    protected static CredentialFinding Mk(
        string computerName, string shareName, string uncFilePath, string fileName,
        string section = "NA", string objectName = "NA",
        string targetUrl = "NA", string targetServer = "NA", string targetPort = "NA",
        string database = "NA", string domain = "NA",
        string username = "", string password = "",
        string passwordEncoded = "NA", string keyFilePath = "NA",
        string parser = "")
        => new()
        {
            ComputerName    = computerName,
            ShareName       = shareName,
            UncFilePath     = uncFilePath,
            FileName        = fileName,
            Section         = section,
            ObjectName      = objectName,
            TargetUrl       = targetUrl,
            TargetServer    = targetServer,
            TargetPort      = targetPort,
            Database        = database,
            Domain          = domain,
            Username        = username,
            Password        = password,
            PasswordEncoded = passwordEncoded,
            KeyFilePath     = keyFilePath,
            SourceParser    = parser,
        };
}
