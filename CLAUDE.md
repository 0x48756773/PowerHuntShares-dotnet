# PowerHuntShares — C# Port

## Project context

This is a C# .NET 8 port of `PowerHuntShares.psm1` (Scott Sutherland, NetSPI).
The original PowerShell module is one directory up at `../PowerHuntShares.psm1` (28,629 lines).

**Solution:** `PowerHuntShares.sln` (Visual Studio 2022)
**Project:** `PowerHuntShares/PowerHuntShares.csproj` (.NET 8, `net8.0-windows`, Windows-only)
**NuGet deps:** `CommandLineParser 2.9.1`, `System.DirectoryServices 8.0.1`, `System.DirectoryServices.AccountManagement 8.0.1`

---

## Architecture

```
PowerHuntShares/
├── Program.cs                        Entry point, CommandLineParser routing
├── Core/
│   ├── ScanOptions.cs                All CLI args (maps to Invoke-HuntSMBShares params)
│   ├── ScanResults.cs                Aggregated results container
│   └── HuntOrchestrator.cs          10-phase scan pipeline (main logic)
├── Discovery/
│   ├── Models/ComputerInfo.cs
│   ├── Models/SubnetInfo.cs
│   ├── LdapEnumerator.cs            Get-LdapQuery + Get-DomainSubnet → DirectorySearcher
│   ├── PingScanner.cs               Parallel ICMP sweep → Ping.Send
│   └── PortScanner.cs               Parallel TCP 445 probe → TcpClient
├── Shares/
│   ├── Models/ShareInfo.cs
│   ├── Models/ShareAclEntry.cs
│   ├── Models/DirectoryListingEntry.cs
│   ├── ShareEnumerator.cs           Get-MySMBShare → NetShareEnum P/Invoke
│   ├── AclEnumerator.cs             Get-PathAcl + Convert-FileRight → DirectoryInfo.GetAccessControl
│   └── HighRiskClassifier.cs        Excessive/Read/Write/HighRisk ACL classification
├── Credentials/
│   ├── Models/CredentialFinding.cs
│   ├── Parsers/IConfigParser.cs     Interface all parsers implement
│   ├── Parsers/WebConfigParser.cs   Get-PwWebConfig  (FULL — connectionStrings + appSettings)
│   ├── Parsers/WinScpParser.cs      Get-PwWinSCPConfig (FULL)
│   ├── Parsers/PuttyParser.cs       Get-PwPuttyRegFile (FULL)
│   ├── Parsers/StubParsers.cs       32 remaining Get-Pw* parsers (stubs — see below)
│   └── FileCredentialHunter.cs      Routes files to parsers, runs in parallel
├── Reporting/
│   ├── CsvExporter.cs               Export-Csv -NoTypeInformation equivalent
│   └── HtmlReportGenerator.cs       HTML summary report (basic structure, see TODO)
├── Interop/
│   └── NativeMethods.cs             SHARE_INFO_1 struct, NetShareEnum, NetApiBufferFree
└── Utilities/
    ├── HashHelper.cs                Get-FolderGroupMd5 → MD5.HashData
    ├── SubnetHelper.cs              checkSubnet / CIDR arithmetic
    └── LlmClient.cs                 Invoke-LLMRequest → HttpClient (OpenAI-compatible)
```

---

## Scan pipeline (HuntOrchestrator.cs)

The 10-phase pipeline mirrors the `Begin` block of `Invoke-HuntSMBShares`:

| Phase | Method | PS lines |
|-------|--------|----------|
| 1 | `SetupOutputDirectory` | 308–337 |
| 2 | `Phase2_DiscoverComputers` | 342–435 |
| 3 | `Phase3_PingSweep` | 442–480 |
| 4 | `Phase4_PortScan` | 487–544 |
| 5 | `Phase5_EnumerateShares` | 549–584 |
| 6 | `Phase6_EnumerateAcls` | 586–695 |
| 7 | `Phase7_ClassifyRisk` | 700–848 |
| 8 | `Phase8_DirectoryListings` | 747–807 |
| 9 | `Phase9_CredentialHunting` | (via Invoke-FingerPrintShare) |
| 10 | `Phase10_GenerateReports` | end of function |

---

## TODO — remaining work

### 1. Stub parsers (`Credentials/Parsers/StubParsers.cs`) ✓ COMPLETE

All parsers implemented and build-verified. StubParsers.cs contains all classes below.

| Class | PS function | PS line | Target file |
|---|---|---|---|
| `WordPressConfigParser` | `Get-PwWordPressConfig` | 24352 | `wp-config.php` |
| `VncParser` | `Get-PwVnc` | 24477 | `vnc.ini` |
| `UnattendParser` | `Get-PwUnattendFile` | 24558 | `unattend.xml` |
| `TomcatUsersParser` | `Get-PwTomcatUsers` | 24672 | `tomcat-users.xml` |
| `TnsNamesParser` | `Get-PwTnsOra` | 24727 | `tnsnames.ora` |
| `SysprepParser` | `Get-PwSysprepFile` | 24825 | `sysprep.inf` |
| `StandaloneXmlParser` | `Get-PwStandalone` | 25009 | `standalone.xml` |
| `SssdParser` | `Get-PwSssdConfig` | 25009 | `sssd.conf` |
| `SmbConfParser` | `Get-PwSmbConf` | 25089 | `smb.conf` |
| `SiteManagerParser` | `Get-PwSiteManagerConfig` | 25166 | `sitemanager.xml` |
| `ShadowParser` | `Get-PwShadow` | 25231 | `shadow` |
| `GenericIniParser` | `Get-PwIniFile` | 25301 | `*.ini` |
| `ServerXmlParser` | `Get-PwServerXml` | 25523 | `server.xml` |
| `PureFtpParser` | `Get-PwPureFtpConfig` | 25637 | `pure-ftpd.passwd` |
| `PhpIniParser` | `Get-PwPhpIni` | 25703 | `php.ini` |
| `MySqlConfigParser` | `Get-PwMySQLConfig` | 25771 | `my.cnf` |
| `MachineConfigParser` | `Get-PwMachineConfig` | 25836 | `machine.config` |
| `Krb5ConfParser` | `Get-Pwkrb5Conf` | 26030 | `krb5.conf` |
| `JbossCliParser` | `Get-PwJbossCliConfig` | 26117 | `jboss-cli.xml` |
| `HtpasswdParser` | `Get-PwHtpasswd` | 26164 | `.htpasswd` |
| `DbxDriverParser` | `Get-PwDbxDriverIni` | 26223 | `db.ini` |
| `ContextXmlParser` | `Get-PwContextXML` | 26323 | `context.xml` |
| `JenkinsConfigParser` | `Get-PwJenkinsConfig` | 26376 | `config.xml` |
| `BootstrapIniParser` | `Get-PwBootstrapConfig` | 26490 | `bootstrap.ini` |
| `PgPassParser` | `Get-PwPgPass` | 26817 | `.pgpass` |
| `GppParser` | `Get-PwGPP` | 26886 | `Groups.xml` (GPP) |
| `DtsxParser` | `Get-PwSsisDtsx` | 27189 | `*.dtsx` |
| `RdpParser` | `Get-PwRdpInfo` | 27310 | `*.rdp` |
| `PrivateKeyPathParser` | `Get-PrivateKeyFilePath` | 27386 | `id_rsa`, `*.pem` |
| `CiscoConfigParser` | `Get-PwCiscoConfig` | 27426 | `*.cfg` |
| `GrubParser` | `Get-PwGrubConfig` | 27664 | `grub.cfg` |
| `NetrcParser` | `Get-PwNetrc` | 27734 | `.netrc` |
| `RemminaParser` | `Get-PwRemmina` | 27800 | `*.remmina` |
| `RemminaPrefParser` | `Get-PwRemminaPref` | 27896 | `remmina.pref` |
| `DbvisParser` | `Get-PwDbvisxml` | 27956 | `dbvis.xml` |
| `GitCredentialsParser` | `Get-PwGitCredentials` | 28021 | `.git-credentials` |
| `FetchmailrcParser` | `Get-PwFetchmailrc` | 28078 | `.fetchmailrc` |

### 2. HTML report dashboard (`Reporting/HtmlReportGenerator.cs`) ✓ COMPLETE

Full interactive dashboard implemented with ApexCharts, CSS tab navigation, all 10 pages
(home, dashboard, computers, share names, folder groups, ACEs, credentials, exploit, detect,
remediation). Three Get-Card* timeline functions collapsed into generic BuildMonthStats helper.

### 3. Share fingerprinting ✓ COMPLETE

`Shares/ShareFingerprinter.cs` — ports `Invoke-FingerPrintShare` (PS line 28325).
`Shares/Models/ShareFingerprintResult.cs` — result model.
`ScanResults.FingerprintResults` — list added to aggregated results.
`LlmClient.SendWithUsageAsync` + `LlmResult` record added to `Utilities/LlmClient.cs`.

---

## Key PS→C# translation reference

| PowerShell | C# |
|---|---|
| `Invoke-Parallel -Throttle N` | `Parallel.ForEach` with `MaxDegreeOfParallelism = N` |
| `New-InMemoryModule` + `Add-Win32Type` | `[DllImport]` in `Interop/NativeMethods.cs` |
| `Get-Acl` | `DirectoryInfo.GetAccessControl()` |
| `[System.DirectoryServices.DirectoryEntry]` | Same class, direct reference |
| `Export-Csv -NoTypeInformation` | `CsvExporter.Export<T>()` |
| `[IO.Directory]::GetFiles($unc)` | `Directory.GetFiles(unc)` |
| `$Netapi32::NetShareEnum(...)` | `NativeMethods.NetShareEnum(...)` |

---

## How to build

```
# Visual Studio 2022 (recommended)
Open PowerHuntShares.sln → Build Solution (Ctrl+Shift+B)

# CLI (requires .NET 8 SDK on Windows)
dotnet build PowerHuntShares\PowerHuntShares.csproj -c Release
dotnet publish PowerHuntShares\PowerHuntShares.csproj -c Release -r win-x64 --self-contained
```

## Example usage (after build)

```
PowerHuntShares.exe -o C:\temp\output
PowerHuntShares.exe -o C:\temp\output --host-list hosts.txt --threads 50
PowerHuntShares.exe -o C:\temp\output -u DOMAIN\user -p Password1 -d dc1.domain.local
```
