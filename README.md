# PowerHuntShares (C#)

A native Windows tool for identifying, analyzing, and reporting on excessive SMB share permissions in Active Directory environments. Built for penetration testers and blue teams.

This is a C# .NET 8 port of [PowerHuntShares](https://github.com/NetSPI/PowerHuntShares) by Scott Sutherland ([@_nullbind](https://twitter.com/_nullbind)) at [NetSPI](https://www.netspi.com/). It ships as a single self-contained executable with no dependencies.

## What It Does

PowerHuntShares automates the full workflow of SMB share auditing across an Active Directory domain:

1. **Discover** computers via LDAP queries against Active Directory
2. **Scan** for live hosts (ICMP ping sweep + TCP 445 port check)
3. **Enumerate** SMB shares on every reachable host via NetShareEnum
4. **Analyze** share ACLs to identify excessive privileges
5. **Classify** high-risk shares (wwwroot, inetpub, c$, admin$, etc.)
6. **List** directory contents on accessible shares (configurable depth)
7. **Detect** interesting files by keyword pattern matching
8. **Hunt** for credentials embedded in configuration files (40+ parsers)
9. **Fingerprint** shares via LLM for contextual analysis (optional)
10. **Report** everything in an interactive HTML dashboard and CSV exports

### Key Definitions

- **Excessive Privileges** -- Share ACLs that grant access to `Everyone`, `Authenticated Users`, `BUILTIN\Users`, `Domain Users`, or `Domain Computers`.
- **High-Risk Shares** -- Shares that provide unauthorized remote access to systems or applications, such as `wwwroot`, `inetpub`, `c$`, and `admin$`.

## Quick Start

```
PowerHuntShares.exe -o C:\temp\output
```

That's it. On a domain-joined machine this will auto-discover a DC, enumerate all domain computers, scan them, and produce a full report in the output directory.

## Usage

```
PowerHuntShares.exe -o <output-dir> [options]
```

### Required

| Flag | Description |
|------|-------------|
| `-o`, `--output <dir>` | Directory to write CSV and HTML output files |

### Authentication

| Flag | Description |
|------|-------------|
| `-u`, `--username <DOMAIN\user>` | Domain user (defaults to current user) |
| `-p`, `--password <password>` | Domain password |
| `-d`, `--domain-controller <host>` | Domain controller hostname or IP |

### Targeting

| Flag | Description |
|------|-------------|
| `--host-list <file>` | File with target hostnames (one per line); skips AD discovery |
| `--no-ping` | Skip ICMP sweep, go straight to TCP 445 checks |

### Tuning

| Flag | Description |
|------|-------------|
| `-t`, `--threads <n>` | Concurrent tasks (default: 20) |
| `--timeout <sec>` | Per-host connection timeout in seconds (default: 15) |
| `--dir-level <n>` | Directory listing depth (default: 3) |
| `--file-keywords <csv>` | CSV file with custom interesting-file keywords |

### LLM (Optional)

| Flag | Description |
|------|-------------|
| `--api-key <key>` | API key for LLM share fingerprinting |
| `--endpoint <url>` | OpenAI-compatible endpoint URL |

### Diagnostics

| Flag | Description |
|------|-------------|
| `--show-errors` | Print per-host errors to console |

## Examples

**Domain-joined machine, default settings:**
```
PowerHuntShares.exe -o C:\temp\output
```

**Explicit credentials and domain controller:**
```
PowerHuntShares.exe -o C:\temp\output -u DOMAIN\user -p Password1 -d dc1.domain.local
```

**Target a specific host list, skip ping, 50 threads:**
```
PowerHuntShares.exe -o C:\temp\output --host-list hosts.txt --no-ping --threads 50
```

**Custom interesting-file keywords:**
```
PowerHuntShares.exe -o C:\temp\output --file-keywords keywords.csv
```

The keywords CSV should have `Keyword` and `Category` columns:
```csv
Keyword,Category
*password*,Sensitive
*.config,Secret
*.bak,Backup
```

## Output

Each scan creates a timestamped directory (`SmbShareHunt-MMddyyyyHHmmss`) containing:

- **HTML Report** -- Interactive dashboard with summary metrics, share inventory, ACL analysis, credential findings, interesting files, and remediation guidance
- **CSV Exports** -- Machine-readable files for each scan phase:
  - Domain computers, subnets
  - Share inventory and ACL details
  - Excessive privilege, read, and write ACL breakdowns
  - Directory listings
  - Interesting files (by keyword match)
  - Credential findings

## Credential Parsers

PowerHuntShares includes 40+ parsers that extract credentials from configuration files found on accessible shares:

| Parser | Target Files |
|--------|-------------|
| Web.config | ASP.NET connection strings, app settings |
| WinSCP | WinSCP.ini sessions |
| PuTTY | PuTTY registry exports |
| WordPress | wp-config.php |
| Tomcat | tomcat-users.xml, server.xml, context.xml |
| JBoss | standalone.xml, jboss-cli.xml |
| Database | tnsnames.ora, my.cnf, .pgpass, dbvis.xml |
| SSH Keys | id_rsa, id_dsa, id_ecdsa, *.pem, *.ppk |
| GPP | Groups.xml (Group Policy Preferences) |
| SSIS | *.dtsx packages |
| Unattend | unattend.xml, sysprep.inf |
| Linux | shadow, .htpasswd, krb5.conf, sssd.conf, smb.conf |
| Remote Desktop | *.rdp, *.remmina |
| Git | .git-credentials, .netrc, .fetchmailrc |
| And more... | bootstrap.ini, grub.cfg, pure-ftpd.passwd, etc. |

## Building from Source

Requires .NET 8 SDK on Windows.

```bash
# Build
dotnet build PowerHuntShares\PowerHuntShares.csproj -c Release

# Publish self-contained single-file executable
dotnet publish PowerHuntShares\PowerHuntShares.csproj -c Release -r win-x64 --self-contained
```

The published binary will be at `PowerHuntShares\bin\Release\net8.0-windows\win-x64\publish\PowerHuntShares.exe`.

## Platform

Windows only. The tool relies on:
- `Netapi32.dll` (NetShareEnum) for SMB share enumeration
- `System.DirectoryServices` (ADSI/COM) for LDAP queries
- `advapi32.dll` for ACL operations

## Credits

- Original [PowerHuntShares](https://github.com/NetSPI/PowerHuntShares) PowerShell module by [Scott Sutherland](https://twitter.com/_nullbind) at [NetSPI](https://www.netspi.com/)
- C# port by [Johnathan Drozdowski](https://github.com/0x48756773)

## License

[BSD 3-Clause](LICENSE)
