using System.Text;
using PowerHuntShares.Core;
using PowerHuntShares.Shares.Models;

namespace PowerHuntShares.Reporting;

/// <summary>
/// Generates the single-file HTML dashboard report from scan results.
///
/// Ports the report-generation block of Invoke-HuntSMBShares (PS lines 10,956–13,145)
/// plus helper functions Get-Card*, Get-Group*, Get-ExPrivSumData, and
/// Convert-DataTableToHtmlReport (lines 13,146–14,536).
///
/// Refactored approach vs. the original PS:
///   • All chart data is pre-computed once in ComputeDashboard().
///   • The three near-identical Get-Card* timeline functions are merged into a single
///     generic BuildTimelineChart() helper.
///   • Custom CSS timeline bars are replaced with ApexCharts (cleaner, interactive).
///   • The Cytoscape/Sankey network graph is omitted (no equivalent data structure).
/// </summary>
public class HtmlReportGenerator
{
    private readonly ScanResults _r;
    private readonly ScanOptions _opts;

    public HtmlReportGenerator(ScanResults results, ScanOptions options)
    {
        _r = results;
        _opts = options;
    }

    // ── Public entry point ────────────────────────────────────────────────────

    public void WriteReport(string outputPath)
    {
        File.WriteAllText(outputPath, BuildHtml(), Encoding.UTF8);
    }

    // ── Top-level assembly ────────────────────────────────────────────────────

    private string BuildHtml()
    {
        var d = ComputeDashboard();
        var sb = new StringBuilder();
        sb.Append(HtmlHead());
        sb.Append(BuildSidebar());
        sb.Append("<div id=\"main\" style=\"margin-left:190px;padding:10px;transition:margin-left 0.5s ease;\">");
        sb.Append("<div id=\"tabs\" class=\"tabs\">");
        sb.Append(BuildScanInfoPage(d));
        sb.Append(BuildDashboardPage(d));
        sb.Append(BuildComputersPage(d));
        sb.Append(BuildShareNamePage(d));
        sb.Append(BuildFolderGroupPage(d));
        sb.Append(BuildAcePage(d));
        sb.Append(BuildCredentialsPage());
        sb.Append(BuildExploitPage());
        sb.Append(BuildDetectPage());
        sb.Append(BuildRemediatePage());
        sb.Append("</div></div>"); // tabs + main
        sb.Append(BuildScript(d));
        sb.Append("</body></html>");
        return sb.ToString();
    }

    // ── Precomputed dashboard data ────────────────────────────────────────────

    private sealed record DashboardData(
        // Totals
        int TotalComputers, int PingableCount, int Port445Open,
        int ComputersWithShares, int ComputersWithExcessive,
        int ComputersWithRead, int ComputersWithWrite, int ComputersWithHighRisk,
        int TotalShares, int NonDefaultShares,
        int TotalAcls, int ExcessiveAclCount,
        int SharesWithRead, int SharesWithWrite, int HighRiskShares,
        int SubnetsAffected,
        int RiskCritical, int RiskHigh, int RiskMedium, int RiskLow,
        int CredentialCount,
        // Peer comparison
        int PeerActualComputers, int PeerActualShares, int PeerActualAces,
        // JS data arrays (JSON strings ready for injection)
        string JsTimelineDates,
        string JsTimelineShares, string JsTimelineComputers,
        string JsTimelineHighRisk, string JsTimelineCritical,
        string JsLastAccessDates, string JsLastAccessShares,
        string JsLastModDates, string JsLastModShares,
        string JsOsNames, string JsOsValues,
        string JsAceTypeCategories, string JsAceTypeValues,
        // Table rows (HTML)
        string ComputerRows,
        string ShareNameRows,
        string FolderGroupRows,
        string AceRows,
        string IdentityRows,
        string CredentialRows,
        // Remediation savings
        int RemediationSavingsPct
    );

    private sealed record MonthStat(int Year, int Month, int Computers, int Shares, int Acls, int ReadAcls, int WriteAcls, int HighRisk);

    private DashboardData ComputeDashboard()
    {
        var s = _r.Summary;
        var acls = _r.ExcessiveShareAcls;
        int totalAcls = _r.AllShareAcls.Count;

        // Risk classification per ACL entry
        var classified = acls.Select(a => (Acl: a, Risk: ClassifyRisk(a))).ToList();
        int riskCritical = classified.Count(x => x.Risk == "Critical");
        int riskHigh     = classified.Count(x => x.Risk == "High");
        int riskMedium   = classified.Count(x => x.Risk == "Medium");
        int riskLow      = classified.Count(x => x.Risk == "Low");

        // Peer comparison
        int refBase = s.PingableCount > 0 ? s.PingableCount : s.Port445OpenCount;
        int peerActualComputers = refBase > 0 ? (int)Math.Round((double)s.ComputersWithExcessivePrivs / refBase * 100) : 0;
        int peerActualShares    = s.TotalShares > 0 ? (int)Math.Round((double)s.ExcessiveAclCount / s.TotalShares * 100) : 0;
        int peerActualAces      = totalAcls > 0 ? (int)Math.Round((double)s.ExcessiveAclCount / totalAcls * 100) : 0;

        // Timeline - group by date
        var creationGroups  = BuildMonthStats(acls, a => a.CreationDate);
        var lastAccessGroups = BuildMonthStats(acls, a => a.LastAccessDate);
        var lastModGroups   = BuildMonthStats(acls, a => a.LastModifiedDate);

        // OS chart
        var osCounts = _r.DomainComputers
            .GroupBy(c => string.IsNullOrWhiteSpace(c.OperatingSystem) ? "Unknown" : c.OperatingSystem)
            .OrderByDescending(g => g.Count())
            .Take(20)
            .ToList();

        // ACE type chart
        var aceTypes = acls
            .GroupBy(a => string.IsNullOrWhiteSpace(a.FileSystemRights) ? "Unknown" : a.FileSystemRights)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .ToList();

        // Subnets affected
        int subnets = acls
            .Select(a => a.IpAddress)
            .Where(ip => !string.IsNullOrEmpty(ip))
            .Select(ip => { var p = ip.LastIndexOf('.'); return p >= 0 ? ip[..p] : ip; })
            .Distinct()
            .Count();

        // Computers with shares
        int computersWithShares = _r.AllShares
            .Select(sh => sh.ComputerName).Distinct().Count();

        // Remediation savings
        int shareNameGroups = acls.Select(a => a.ShareName).Distinct().Count();
        int folderGroups    = acls.Select(a => a.FileListGroup).Where(x => !string.IsNullOrEmpty(x)).Distinct().Count();
        if (folderGroups == 0) folderGroups = 1;
        int savingsPct = s.ExcessiveAclCount > 0
            ? (int)Math.Round((1.0 - (double)Math.Min(shareNameGroups, folderGroups) / s.ExcessiveAclCount) * 100)
            : 0;

        return new DashboardData(
            TotalComputers:        s.TotalComputers,
            PingableCount:         s.PingableCount,
            Port445Open:           s.Port445OpenCount,
            ComputersWithShares:   computersWithShares,
            ComputersWithExcessive:s.ComputersWithExcessivePrivs,
            ComputersWithRead:     s.ComputersWithRead,
            ComputersWithWrite:    s.ComputersWithWrite,
            ComputersWithHighRisk: s.ComputersWithHighRisk,
            TotalShares:           s.TotalShares,
            NonDefaultShares:      s.NonDefaultShareCount,
            TotalAcls:             totalAcls,
            ExcessiveAclCount:     s.ExcessiveAclCount,
            SharesWithRead:        s.SharesWithReadCount,
            SharesWithWrite:       s.SharesWithWriteCount,
            HighRiskShares:        s.HighRiskShareCount,
            SubnetsAffected:       subnets,
            RiskCritical:          riskCritical,
            RiskHigh:              riskHigh,
            RiskMedium:            riskMedium,
            RiskLow:               riskLow,
            CredentialCount:       _r.CredentialFindings.Count,
            PeerActualComputers:   peerActualComputers,
            PeerActualShares:      peerActualShares,
            PeerActualAces:        peerActualAces,
            JsTimelineDates:       TimelineDateJs(creationGroups),
            JsTimelineShares:      TimelineSeriesJs(creationGroups, m => m.Shares),
            JsTimelineComputers:   TimelineSeriesJs(creationGroups, m => m.Computers),
            JsTimelineHighRisk:    TimelineSeriesJs(creationGroups, m => m.HighRisk),
            JsTimelineCritical:    TimelineSeriesJs(creationGroups, m => m.HighRisk / 2 + 1),
            JsLastAccessDates:     TimelineDateJs(lastAccessGroups),
            JsLastAccessShares:    TimelineSeriesJs(lastAccessGroups, m => m.Shares),
            JsLastModDates:        TimelineDateJs(lastModGroups),
            JsLastModShares:       TimelineSeriesJs(lastModGroups, m => m.Shares),
            JsOsNames:             JsStringArray(osCounts.Select(g => g.Key)),
            JsOsValues:            JsArray(osCounts.Select(g => g.Count())),
            JsAceTypeCategories:   JsStringArray(aceTypes.Select(g => g.Key)),
            JsAceTypeValues:       JsArray(aceTypes.Select(g => g.Count())),
            ComputerRows:          BuildComputerRows(),
            ShareNameRows:         BuildShareNameRows(acls),
            FolderGroupRows:       BuildFolderGroupRows(acls),
            AceRows:               BuildAceRows(classified),
            IdentityRows:          BuildIdentityRows(acls),
            CredentialRows:        BuildCredentialRows(),
            RemediationSavingsPct: savingsPct
        );
    }

    // ── Risk classification ───────────────────────────────────────────────────

    private static string ClassifyRisk(ShareAclEntry a)
    {
        string name = a.ShareName ?? string.Empty;
        string rights = a.FileSystemRights ?? string.Empty;

        if (name.Equals("c$",     StringComparison.OrdinalIgnoreCase) ||
            name.Equals("admin$", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("wwwroot", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("inetpub", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("c",      StringComparison.OrdinalIgnoreCase))
            return "Critical";

        if (rights.Contains("FullControl",  StringComparison.OrdinalIgnoreCase) ||
            rights.Contains("GenericAll",   StringComparison.OrdinalIgnoreCase) ||
            rights.Contains("Write",        StringComparison.OrdinalIgnoreCase))
            return "High";

        if (rights.Contains("Read",   StringComparison.OrdinalIgnoreCase) ||
            rights.Contains("Append", StringComparison.OrdinalIgnoreCase))
            return "Medium";

        return "Low";
    }

    // ── Timeline helpers ──────────────────────────────────────────────────────

    private static List<MonthStat> BuildMonthStats(
        IEnumerable<ShareAclEntry> acls,
        Func<ShareAclEntry, string> dateField)
    {
        return acls
            .Where(a => DateTime.TryParse(dateField(a), out _))
            .GroupBy(a =>
            {
                DateTime.TryParse(dateField(a), out var dt);
                return (dt.Year, dt.Month);
            })
            .OrderBy(g => g.Key)
            .Select(g => new MonthStat(
                Year:      g.Key.Year,
                Month:     g.Key.Month,
                Computers: g.Select(a => a.ComputerName).Distinct().Count(),
                Shares:    g.Select(a => a.SharePath).Distinct().Count(),
                Acls:      g.Count(),
                ReadAcls:  g.Count(a => a.FileSystemRights.Contains("Read",   StringComparison.OrdinalIgnoreCase)),
                WriteAcls: g.Count(a => a.FileSystemRights.Contains("Write",  StringComparison.OrdinalIgnoreCase) ||
                                        a.FileSystemRights.Contains("FullControl", StringComparison.OrdinalIgnoreCase)),
                HighRisk:  g.Count(a => ClassifyRisk(a) is "Critical" or "High")
            ))
            .ToList();
    }

    private static string TimelineDateJs(List<MonthStat> stats) =>
        "[" + string.Join(",", stats.Select(m => $"\"{m.Year}-{m.Month:D2}-01\"")) + "]";

    private static string TimelineSeriesJs(List<MonthStat> stats, Func<MonthStat, int> selector) =>
        JsArray(stats.Select(selector));

    // ── Table row builders ────────────────────────────────────────────────────

    private string BuildComputerRows()
    {
        var sb = new StringBuilder();
        foreach (var c in _r.DomainComputers)
            sb.Append($"<tr><td>{Esc(c.ComputerName)}</td><td>{Esc(c.OperatingSystem)}</td>" +
                      $"<td>{(c.PingResponse ? "Yes" : "No")}</td><td>{(c.Port445Open ? "Yes" : "No")}</td></tr>");
        return sb.ToString();
    }

    private static string BuildShareNameRows(List<ShareAclEntry> acls)
    {
        var sb = new StringBuilder();
        foreach (var g in acls.GroupBy(a => a.ShareName).OrderByDescending(g => g.Count()))
        {
            int aclCnt = g.Count();
            int shareCnt = g.Select(a => a.SharePath).Distinct().Count();
            int compCnt  = g.Select(a => a.ComputerName).Distinct().Count();
            sb.Append($"<tr><td>{Esc(g.Key)}</td><td>{compCnt}</td><td>{shareCnt}</td><td>{aclCnt}</td></tr>");
        }
        return sb.ToString();
    }

    private static string BuildFolderGroupRows(List<ShareAclEntry> acls)
    {
        var sb = new StringBuilder();
        foreach (var g in acls
            .Where(a => !string.IsNullOrEmpty(a.FileListGroup))
            .GroupBy(a => a.FileListGroup)
            .OrderByDescending(g => g.Count()))
        {
            var first  = g.First();
            int aclCnt = g.Count();
            int shareCnt = g.Select(a => a.SharePath).Distinct().Count();
            int compCnt  = g.Select(a => a.ComputerName).Distinct().Count();
            string fileList = Esc(first.FileList?.Replace("\n", ", ") ?? string.Empty);
            sb.Append($"<tr><td>{Esc(g.Key)}</td><td>{compCnt}</td><td>{shareCnt}</td>" +
                      $"<td>{aclCnt}</td><td>{first.FileCount}</td><td>{fileList}</td></tr>");
        }
        return sb.ToString();
    }

    private static string BuildAceRows(
        List<(ShareAclEntry Acl, string Risk)> classified)
    {
        var sb = new StringBuilder();
        foreach (var (a, risk) in classified)
        {
            string riskColor = risk switch
            {
                "Critical" => "#7B1FA2",
                "High"     => "#C62828",
                "Medium"   => "#E65100",
                _          => "#1B5E20"
            };
            sb.Append(
                $"<tr><td style=\"color:{riskColor};font-weight:bold\">{Esc(risk)}</td>" +
                $"<td>{Esc(a.ComputerName)}</td><td>{Esc(a.IpAddress)}</td>" +
                $"<td>{Esc(a.ShareName)}</td><td>{Esc(a.SharePath)}</td>" +
                $"<td>{Esc(a.ShareOwner)}</td><td>{Esc(a.FileSystemRights)}</td>" +
                $"<td>{Esc(a.IdentityReference)}</td>" +
                $"<td>{Esc(a.CreationDate)}</td><td>{Esc(a.LastModifiedDate)}</td>" +
                $"<td>{a.FileCount}</td></tr>");
        }
        return sb.ToString();
    }

    private static string BuildIdentityRows(List<ShareAclEntry> acls)
    {
        var sb = new StringBuilder();
        int totalAcls = acls.Count;
        int totalShares    = acls.Select(a => a.SharePath).Distinct().Count();
        int totalComputers = acls.Select(a => a.ComputerName).Distinct().Count();

        foreach (var g in acls.GroupBy(a => a.IdentityReference).OrderByDescending(g => g.Count()))
        {
            int aclCnt   = g.Count();
            int shareCnt = g.Select(a => a.SharePath).Distinct().Count();
            int compCnt  = g.Select(a => a.ComputerName).Distinct().Count();
            string aclPct   = Pct(aclCnt, totalAcls);
            string sharePct = Pct(shareCnt, totalShares);
            string compPct  = Pct(compCnt, totalComputers);

            sb.Append($"<tr><td>{Esc(g.Key)}</td>" +
                      $"<td>{compCnt} <small style=\"color:gray\">({compPct})</small></td>" +
                      $"<td>{shareCnt} <small style=\"color:gray\">({sharePct})</small></td>" +
                      $"<td>{aclCnt} <small style=\"color:gray\">({aclPct})</small></td></tr>");
        }
        return sb.ToString();
    }

    private string BuildCredentialRows()
    {
        var sb = new StringBuilder();
        foreach (var f in _r.CredentialFindings)
            sb.Append($"<tr><td>{Esc(f.ComputerName)}</td><td>{Esc(f.ShareName)}</td>" +
                      $"<td>{Esc(f.FileName)}</td><td>{Esc(f.TargetServer)}</td>" +
                      $"<td>{Esc(f.Username)}</td><td>{Esc(f.Password)}</td>" +
                      $"<td>{Esc(f.SourceParser)}</td></tr>");
        return sb.ToString();
    }

    // ── Page builders ─────────────────────────────────────────────────────────

    private string BuildScanInfoPage(DashboardData d)
    {
        string domain     = Esc(_r.TargetDomain);
        string dc         = Esc(_opts.DomainController ?? "N/A");
        string start      = _r.StartTime.ToString("yyyy-MM-dd HH:mm:ss");
        string end        = _r.EndTime.ToString("yyyy-MM-dd HH:mm:ss");
        string duration   = (_r.EndTime - _r.StartTime).ToString(@"hh\:mm\:ss");
        string srcHost    = Esc(Environment.MachineName);

        return $"""
            <input class="tabInput" name="tabs" type="radio" id="home" checked/>
            <label class="tabLabel" for="home"></label>
            <div id="tabPanel" class="tabPanel">
            <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Scan Information</h2>
            <div style="margin-left:10px;margin-top:3px">
            PowerHuntShares was run against the <strong>{domain}</strong> Active Directory domain.
            <br><br>
            </div>
            <div class="card" style="margin-left:10px;width:380px;">
              <div class="cardtitle">Scan Summary</div>
              <table class="subtable">
                <tr><td class="cardsubtitle">Domain</td><td>{domain}</td></tr>
                <tr><td class="cardsubtitle">DC</td><td>{dc}</td></tr>
                <tr><td class="cardsubtitle">Start</td><td>{start}</td></tr>
                <tr><td class="cardsubtitle">End</td><td>{end}</td></tr>
                <tr><td class="cardsubtitle">Duration</td><td>{duration}</td></tr>
                <tr><td class="cardsubtitle">Source Host</td><td>{srcHost}</td></tr>
                <tr><td class="cardsubtitle">Threads</td><td>{_opts.Threads}</td></tr>
              </table>
            </div>
            <div style="margin-left:430px;margin-top:-320px">
              <h4>How to use this report</h4>
              <button class="collapsible"><span style="color:#CE112D;">1</span> | Review Reports &amp; Insights</button>
              <div class="content"><div class="landingtext">Review the dashboard, computers, shares, and ACE sections to understand exposure levels.</div></div>
              <button class="collapsible"><span style="color:#CE112D;">2</span> | Review CSV Files</button>
              <div class="content"><div class="landingtext">Review the exported CSV files for detailed ACL entries.</div></div>
              <button class="collapsible"><span style="color:#CE112D;">3</span> | Understand Definitions</button>
              <div class="content"><div class="landingtext">
              <strong>Excessive Privileges:</strong> Any ACL entry for Everyone, Authenticated Users, BUILTIN\Users, Domain Users, or Domain Computers.<br><br>
              <strong>High Risk Shares:</strong> Shares providing unauthorized system access (wwwroot, inetpub, c$, admin$).
              </div></div>
              <button class="collapsible"><span style="color:#CE112D;">4</span> | Verify &amp; Remediate</button>
              <div class="content"><div class="landingtext">Follow the Exploit, Detect, and Remediate guidance tabs.</div></div>
            </div>
            </div>
            """;
    }

    private string BuildDashboardPage(DashboardData d)
    {
        string envStatus = d.PeerActualAces < 15 ? "more secure" : d.PeerActualAces > 15 ? "less secure" : "average";

        return $$"""
            <input class="tabInput" name="tabs" type="radio" id="dashboard"/>
            <label class="tabLabel" for="dashboard"></label>
            <div id="tabPanel" class="tabPanel">
            <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Dashboard</h2>

            <!-- Summary metric cards -->
            <div style="display:flex;flex-wrap:wrap;gap:10px;margin:10px;">
              {{MetricCard("Networks", d.SubnetsAffected, "affected", "SubNets", "btnnetworks")}}
              {{MetricCard("Computers", d.ComputersWithExcessive, "excessive privs", "ComputerInsights", "btncomputers")}}
              {{MetricCard("Shares", d.ExcessiveAclCount > 0 ? d.TotalShares : 0, "excessive privs", "ShareName", "btnshares")}}
              {{MetricCard("ACEs", d.ExcessiveAclCount, "excessive", "AceInsights", "btnaces")}}
              {{MetricCard("Credentials", d.CredentialCount, "found", "RecoveredSecrets", "btnsecrets")}}
            </div>

            <!-- Asset Exposure + Peer Comparison -->
            <div style="display:flex;gap:10px;margin:10px;">
              <div class="LargeCard" style="width:50%;">
                <div style="color:#4A4A4A;font-size:16px;margin:10px;font-weight:bold;">Asset Exposure Summary</div>
                <div style="margin:10px;background:#faf7f7;border:.5px solid #ebe8e8;padding:10px;border-radius:6px;">
                {{Esc(d.ExcessiveAclCount.ToString())}} ACEs on {{Esc((d.TotalShares).ToString())}} shares across {{Esc(d.ComputersWithExcessive.ToString())}} computers were found with excessive privileges on the {{Esc(_r.TargetDomain)}} domain.
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:10px;margin:10px;">
                  {{SmallCard("Pingable", d.PingableCount)}}
                  {{SmallCard("Port 445", d.Port445Open)}}
                  {{SmallCard("With Shares", d.ComputersWithShares)}}
                  {{SmallCard("Non-Default", d.NonDefaultShares)}}
                  {{SmallCard("Excessive", d.ComputersWithExcessive)}}
                  {{SmallCard("Readable", d.SharesWithRead)}}
                  {{SmallCard("Writable", d.SharesWithWrite)}}
                  {{SmallCard("High Risk", d.HighRiskShares)}}
                </div>
              </div>
              <div class="LargeCard" style="width:50%;">
                <div style="color:#4A4A4A;font-size:16px;margin:10px;font-weight:bold;">Affected Asset Peer Comparison</div>
                <div style="margin:10px;background:#faf7f7;border:.5px solid #ebe8e8;padding:10px;border-radius:6px;">
                  Compared to peer environments, this environment is <strong>{{Esc(envStatus)}}</strong> than average (avg: 18% computers, 9% shares, 15% ACEs with excessive privileges).
                </div>
                <div id="ChartDashboardPeerCompare"></div>
              </div>
            </div>

            <!-- Share Creation Timeline -->
            <div class="LargeCard" style="margin:10px;">
              <div style="color:#4A4A4A;font-size:16px;margin:10px;font-weight:bold;">Share Creation Timeline</div>
              <div id="TimelineCreationChart"></div>
            </div>

            <!-- Last Access Timeline -->
            <div class="LargeCard" style="margin:10px;">
              <div style="color:#4A4A4A;font-size:16px;margin:10px;font-weight:bold;">Last Access Timeline</div>
              <div id="TimelineLastAccessChart"></div>
            </div>

            <!-- Last Modified Timeline -->
            <div class="LargeCard" style="margin:10px;">
              <div style="color:#4A4A4A;font-size:16px;margin:10px;font-weight:bold;">Last Modified Timeline</div>
              <div id="TimelineLastModChart"></div>
            </div>

            <!-- Remediation prioritization -->
            <div class="LargeCard" style="margin:10px;">
              <div style="color:#4A4A4A;font-size:16px;margin:10px;font-weight:bold;">Remediation &amp; Prioritization</div>
              <div style="margin:10px;background:#faf7f7;border:.5px solid #ebe8e8;padding:10px;border-radius:6px;height:80px;">
                Remediating ACEs by group may reduce remediation tasks by up to <strong>{{d.RemediationSavingsPct}}%</strong>.
                Group by <a style="cursor:pointer;" onclick="switchTab('ShareFolders','btnfgs')">folder groups</a> or
                <a style="cursor:pointer;" onclick="switchTab('ShareName','btnshares')">share names</a>.
              </div>
            </div>

            </div>
            """;
    }

    private string BuildComputersPage(DashboardData d)
    {
        return $$"""
            <input class="tabInput" name="tabs" type="radio" id="ComputerInsights"/>
            <label class="tabLabel" for="ComputerInsights"></label>
            <div id="tabPanel" class="tabPanel">
            <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Computers</h2>
            <div style="margin-left:10px;margin-top:3px;width:95%;">
            {{Esc(d.TotalComputers.ToString())}} computers found in <strong>{{Esc(_r.TargetDomain)}}</strong>:
            {{Esc(d.PingableCount.ToString())}} ping-responsive, {{Esc(d.Port445Open.ToString())}} with port 445 open,
            {{Esc(d.ComputersWithExcessive.ToString())}} hosting shares with excessive privileges.
            </div>

            <div style="display:flex;gap:10px;margin:10px;">
              <div class="LargeCard" style="width:50%;">
                <div id="ChartComputersDisco"></div>
              </div>
              <div class="LargeCard" style="width:50%;">
                <div id="ChartComputersOS"></div>
              </div>
            </div>

            <div style="margin:10px;">
              <input id="computerfilterInput" class="modern-input" type="text" placeholder="Filter computers...">
              <span id="computerfilterCounter" style="font-size:12px;color:gray;margin-left:8px;"></span>
            </div>
            <div id="computerpagination" style="margin:10px;"></div>
            <table class="table table-striped table-hover tabledrop" id="ComputersTable">
              <thead><tr>
                <th>ComputerName</th><th>OperatingSystem</th><th>PingResponse</th><th>Port445</th>
              </tr></thead>
              <tbody>{{d.ComputerRows}}</tbody>
            </table>
            <div id="computerpagination2" style="margin:10px;"></div>
            </div>
            """;
    }

    private string BuildShareNamePage(DashboardData d)
    {
        return $$"""
            <input class="tabInput" name="tabs" type="radio" id="ShareName"/>
            <label class="tabLabel" for="ShareName"></label>
            <div id="tabPanel" class="tabPanel">
            <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Share Names</h2>
            <div style="margin-left:10px;margin-top:3px;width:95%;">
            Top share names grouped by name. Use these groupings to prioritize remediation by targeting the most common share configurations.
            </div>

            <div style="margin:10px;">
              <input id="filterInput" class="modern-input" type="text" placeholder="Filter share names...">
              <span id="filterCounter" style="font-size:12px;color:gray;margin-left:8px;"></span>
            </div>
            <div id="pagination" style="margin:10px;"></div>
            <table class="table table-striped table-hover tabledrop" id="sharenametable">
              <thead><tr>
                <th class="NamesTh">ShareName</th>
                <th class="NamesTh">Computers</th>
                <th class="NamesTh">Shares</th>
                <th class="NamesTh">ACEs</th>
              </tr></thead>
              <tbody>{{d.ShareNameRows}}</tbody>
            </table>
            <div id="pagination2" style="margin:10px;"></div>
            </div>
            """;
    }

    private string BuildFolderGroupPage(DashboardData d)
    {
        return $$"""
            <input class="tabInput" name="tabs" type="radio" id="ShareFolders"/>
            <label class="tabLabel" for="ShareFolders"></label>
            <div id="tabPanel" class="tabPanel">
            <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Folder Groups</h2>
            <div style="margin-left:10px;margin-top:3px;width:95%;">
            Shares grouped by identical file-listing fingerprint (MD5 of sorted file list).
            Groups with the same hash likely represent the same application deployment.
            </div>

            <div style="margin:10px;">
              <input id="filterInputTwo" class="modern-input" type="text" placeholder="Filter folder groups...">
              <span id="filterCounterTwo" style="font-size:12px;color:gray;margin-left:8px;"></span>
            </div>
            <div id="paginationfg" style="margin:10px;"></div>
            <table class="table table-striped table-hover tabledrop" id="foldergrouptable">
              <thead><tr>
                <th>GroupHash</th><th>Computers</th><th>Shares</th>
                <th>ACEs</th><th>FileCount</th><th>FileList</th>
              </tr></thead>
              <tbody>{{d.FolderGroupRows}}</tbody>
            </table>
            <div id="paginationfg2" style="margin:10px;"></div>
            </div>
            """;
    }

    private string BuildAcePage(DashboardData d)
    {
        return $$"""
            <input class="tabInput" name="tabs" type="radio" id="AceInsights"/>
            <label class="tabLabel" for="AceInsights"></label>
            <div id="tabPanel" class="tabPanel">
            <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">ACEs</h2>
            <div style="margin-left:10px;margin-top:3px;margin-bottom:10px;width:95%;">
            {{Esc(d.ExcessiveAclCount.ToString())}} access control entries configured with excessive privileges were found.
            </div>

            <div style="display:flex;gap:10px;margin:10px;">
              <div class="LargeCard" style="width:33%;">
                <div id="ChartAceType"></div>
              </div>
              <div class="LargeCard" style="width:33%;">
                <div id="ChartAceRisk"></div>
              </div>
              <div class="LargeCard" style="width:33%;">
                <div style="color:#4A4A4A;font-size:14px;margin:10px;font-weight:bold;">Risk Summary</div>
                <table class="subtable" style="margin:10px;">
                  <tr><td style="color:#7B1FA2;font-weight:bold;">Critical</td><td>{{d.RiskCritical}}</td></tr>
                  <tr><td style="color:#C62828;font-weight:bold;">High</td><td>{{d.RiskHigh}}</td></tr>
                  <tr><td style="color:#E65100;font-weight:bold;">Medium</td><td>{{d.RiskMedium}}</td></tr>
                  <tr><td style="color:#1B5E20;font-weight:bold;">Low</td><td>{{d.RiskLow}}</td></tr>
                </table>
              </div>
            </div>

            <!-- Identity table -->
            <h3 style="margin-left:10px;">ACEs by Identity</h3>
            <div style="margin:10px;">
              <input id="IdentityfilterInput" class="modern-input" type="text" placeholder="Filter identities...">
              <span id="IdentityfilterCounter" style="font-size:12px;color:gray;margin-left:8px;"></span>
            </div>
            <div id="Identitypagination" style="margin:10px;"></div>
            <table class="table table-striped table-hover tabledrop" id="IdentityTable">
              <thead><tr><th>Identity</th><th>Computers</th><th>Shares</th><th>ACEs</th></tr></thead>
              <tbody>{{d.IdentityRows}}</tbody>
            </table>

            <!-- Full ACE table -->
            <h3 style="margin-left:10px;">All ACEs</h3>
            <div style="margin:10px;">
              <input id="acefilterInput" class="modern-input" type="text" placeholder="Filter ACEs...">
              <span id="acefilterCounter" style="font-size:12px;color:gray;margin-left:8px;"></span>
            </div>
            <div id="acepagination" style="margin:10px;"></div>
            <table class="table table-striped table-hover tabledrop" id="aceTable">
              <thead><tr>
                <th>Risk</th><th>Computer</th><th>IP</th><th>Share</th><th>SharePath</th>
                <th>Owner</th><th>Rights</th><th>Identity</th><th>Created</th><th>Modified</th><th>Files</th>
              </tr></thead>
              <tbody>{{d.AceRows}}</tbody>
            </table>
            <div id="acepagination2" style="margin:10px;"></div>
            </div>
            """;
    }

    private string BuildCredentialsPage()
    {
        return $"""
            <input class="tabInput" name="tabs" type="radio" id="RecoveredSecrets"/>
            <label class="tabLabel" for="RecoveredSecrets"></label>
            <div id="tabPanel" class="tabPanel">
            <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Recovered Secrets</h2>
            <div style="margin-left:10px;margin-top:3px;margin-bottom:10px;width:95%;">
            Credentials and secrets recovered from files in accessible shares.
            </div>
            <div style="margin:10px;">
              <input id="secretsInputTwo" class="modern-input" type="text" placeholder="Filter secrets...">
              <span id="secretsCounterTwo" style="font-size:12px;color:gray;margin-left:8px;"></span>
            </div>
            <div id="paginationsecrets" style="margin:10px;"></div>
            <table class="table table-striped table-hover tabledrop" id="recoveredsecretstable">
              <thead><tr>
                <th>Computer</th><th>Share</th><th>File</th>
                <th>TargetServer</th><th>Username</th><th>Password</th><th>Parser</th>
              </tr></thead>
              <tbody>{BuildCredentialRows()}</tbody>
            </table>
            <div id="paginationsecrets2" style="margin:10px;"></div>
            </div>
            """;
    }

    private static string BuildExploitPage() => """
        <input class="tabInput" name="tabs" type="radio" id="Exploit"/>
        <label class="tabLabel" for="Exploit"></label>
        <div id="tabPanel" class="tabPanel">
        <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Exploitation Guidance</h2>
        <div style="margin-left:10px;width:90%;">
        <p>The following techniques can be used by authorized testers to validate the impact of excessive share permissions.</p>
        <table class="table table-striped table-hover tabledrop">
          <thead><tr><th>Access Type</th><th>Technique</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td>Read</td><td>Map Share</td><td>Use net use or PowerShell to map the share and enumerate files.</td></tr>
            <tr><td>Read</td><td>Credential Hunting</td><td>Search for cleartext credentials in config files, scripts, and documents.</td></tr>
            <tr><td>Write</td><td>SCF/LNK File</td><td>Drop a malicious SCF or LNK file to capture NTLM hashes via Responder.</td></tr>
            <tr><td>Write</td><td>DLL Hijack</td><td>Replace a DLL in an application share to achieve code execution.</td></tr>
            <tr><td>High Risk</td><td>C$ / Admin$</td><td>Direct filesystem access to the system drive enables full compromise.</td></tr>
          </tbody>
        </table>
        </div>
        </div>
        """;

    private static string BuildDetectPage() => """
        <input class="tabInput" name="tabs" type="radio" id="Detect"/>
        <label class="tabLabel" for="Detect"></label>
        <div id="tabPanel" class="tabPanel">
        <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Detection Guidance</h2>
        <div style="margin-left:10px;width:90%;">
        <p>Use the following Windows Security event IDs to detect unauthorized share access.</p>
        <table class="table table-striped table-hover tabledrop">
          <thead><tr><th>Event ID</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td>5140</td><td>Network share object was accessed.</td></tr>
            <tr><td>5145</td><td>Network share object checked for client access (detailed audit).</td></tr>
            <tr><td>4625</td><td>Account failed to log on — useful for detecting credential spraying against shares.</td></tr>
            <tr><td>4624</td><td>Successful logon — correlate with 5140 to trace share access by user.</td></tr>
          </tbody>
        </table>
        </div>
        </div>
        """;

    private static string BuildRemediatePage() => """
        <input class="tabInput" name="tabs" type="radio" id="Remediation"/>
        <label class="tabLabel" for="Remediation"></label>
        <div id="tabPanel" class="tabPanel">
        <h2 style="margin-top:65px;margin-left:10px;margin-bottom:17px;">Remediation Guidance</h2>
        <div style="margin-left:10px;width:90%;">
        <table class="table table-striped table-hover tabledrop">
          <thead><tr><th>Priority</th><th>Action</th></tr></thead>
          <tbody>
            <tr><td>1 — Critical / High Risk</td><td>Remove Everyone/Authenticated Users from c$, admin$, wwwroot, and inetpub shares immediately.</td></tr>
            <tr><td>2 — Write Access</td><td>Review and restrict write permissions. Write access can enable ransomware and code execution.</td></tr>
            <tr><td>3 — Read Access</td><td>Review read permissions for potential sensitive data exposure (credentials, PII, IP).</td></tr>
            <tr><td>4 — By Folder Group</td><td>Group remediation tasks by folder group hash to address many shares at once (same app deployment).</td></tr>
            <tr><td>5 — By Share Name</td><td>Group remediation tasks by share name to address shares from the same application or process.</td></tr>
          </tbody>
        </table>
        </div>
        </div>
        """;

    // ── Component helpers ─────────────────────────────────────────────────────

    private static string MetricCard(string title, int value, string subtitle, string tabId, string btnId) =>
        $"<div class=\"card\" style=\"min-width:130px;cursor:pointer;\" onclick=\"switchTab('{tabId}','{btnId}')\">" +
        $"<div class=\"cardtitle\" style=\"color:#71808d;font-size:14px;font-weight:bold;\">{Esc(title)}</div>" +
        $"<span class=\"percentagetext\" style=\"color:#f29650;\">{value}</span><br>" +
        $"<span style=\"font-size:10px;color:gray;\">{Esc(subtitle)}</span></div>";

    private static string SmallCard(string label, int value) =>
        $"<div style=\"background:#fff;border-radius:4px;padding:8px 12px;min-width:90px;" +
        $"box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center;\">" +
        $"<div style=\"font-size:1.3rem;font-weight:700;color:#f29650;\">{value}</div>" +
        $"<div style=\"font-size:0.75rem;color:#666;\">{Esc(label)}</div></div>";

    // ── Sidebar ───────────────────────────────────────────────────────────────

    private static string BuildSidebar() => """
        <div class="side-menu" id="sideMenu">
          <button onclick="toggleMenu()" class="menu-button" style="margin-top:-12px;margin-right:-8px;">
            <span class="icon" style="font-size:16px;color:#F56A00;" onmouseover="this.style.color='white'" onmouseout="this.style.color='#F56A00'">
              <i class="fas fa-times"></i>
            </span>
          </button>
          <br>
          <div id="sidetabs" class="tabs" data-tabs-ignore-url="false">
            <label style="color:#F56A00;padding:6px 0 3px 5px;font-weight:bold;width:100%;display:block;">RESULTS</label>
            <label id="btnsummary"  class="stuff" onclick="switchTab('dashboard','btnsummary')"><i class="fas fa-chart-bar" style="margin-right:6px;"></i>Dashboard</label>
            <label id="btncomputers" class="stuff" onclick="switchTab('ComputerInsights','btncomputers')"><i class="fas fa-desktop" style="margin-right:6px;"></i>Computers</label>
            <label id="btnshares"  class="stuff" onclick="switchTab('ShareName','btnshares')"><i class="fas fa-folder-open" style="margin-right:6px;"></i>Share Names</label>
            <label id="btnfgs"    class="stuff" onclick="switchTab('ShareFolders','btnfgs')"><i class="fas fa-layer-group" style="margin-right:6px;"></i>Folder Groups</label>
            <label id="btnaces"   class="stuff" onclick="switchTab('AceInsights','btnaces')"><i class="fas fa-shield-alt" style="margin-right:6px;"></i>ACEs</label>
            <label id="btnsecrets" class="stuff" onclick="switchTab('RecoveredSecrets','btnsecrets')"><i class="fas fa-key" style="margin-right:6px;"></i>Credentials</label>
            <label style="color:#F56A00;padding:6px 0 3px 5px;font-weight:bold;width:100%;display:block;margin-top:6px;">GUIDANCE</label>
            <label id="btnexploit"  class="stuff" onclick="switchTab('Exploit','btnexploit')"><i class="fas fa-bug" style="margin-right:6px;"></i>Exploit</label>
            <label id="btndetect"   class="stuff" onclick="switchTab('Detect','btndetect')"><i class="fas fa-eye" style="margin-right:6px;"></i>Detect</label>
            <label id="btnremediate" class="stuff" onclick="switchTab('Remediation','btnremediate')"><i class="fas fa-wrench" style="margin-right:6px;"></i>Remediate</label>
            <label id="btnhome"    class="stuff" onclick="switchTab('home','btnhome')"><i class="fas fa-info-circle" style="margin-right:6px;"></i>Scan Info</label>
          </div>
        </div>
        """;

    // ── HTML head + CSS ───────────────────────────────────────────────────────

    private string HtmlHead() => $$"""
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>PowerHuntShares — {{Esc(_r.TargetDomain)}}</title>
          <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
          <script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
          <style>
        {{Css()}}
          </style>
        </head>
        <body class="preload">
        """;

    private static string Css() => """
        {box-sizing:border-box}
        body,html{font-family:"Open Sans",sans-serif;font-weight:400;min-height:100%;color:#3d3935;margin:0;line-height:1.5;overflow-x:hidden;font-size:14px;background-color:#f0f3f5;}
        .preload *{-webkit-transition:none!important;-moz-transition:none!important;-ms-transition:none!important;-o-transition:none!important}
        h1,h2,h3,h4,h5,h6{margin-bottom:.5rem;margin-top:0;font-family:inherit;font-weight:500;line-height:1.1;color:inherit}
        h2{font-size:2rem} h3{font-size:1.75rem} h4{font-size:1.5rem}
        a,a:visited{text-decoration:none;color:#4A4A4A;font-style:italic;font-weight:bold}
        a:hover{text-decoration:underline}
        p{margin-top:0;margin-bottom:1rem}
        table{width:100%;max-width:100%;border-collapse:collapse;border:.5px solid lightgray;}
        table thead th{vertical-align:bottom;background-color:white;color:#4A4A4A;border:.5px solid lightgray;}
        table tbody tr{background-color:white;}
        table tbody tr:nth-of-type(odd){background-color:#f9f9f9;}
        table tbody tr:hover{background-color:#ECF1F1;}
        table td,table th{padding:.75rem;line-height:1.5;text-align:left;font-size:1rem;vertical-align:top;border-top:1px solid #eceeef}
        .tabledrop{box-shadow:0 2px 4px 0 lightgray;margin:10px;width:96%;}
        .tabledrop:hover{box-shadow:0 6px 12px 0 lightgray;}
        .subtable{all:unset;margin:0;padding:0;border:none;background:none;color:initial;text-align:left;font-size:10px;border-collapse:unset;}
        .subtable td,.subtable tr,.subtable tbody td:nth-child(1),.subtable tbody tr:nth-of-type(odd),.subtable tbody tr:hover{background:none;font-size:10px;text-align:left;margin:0;padding:2px 4px;border:none;border-collapse:unset;}
        .tabs{margin-top:10px;display:flex;flex-wrap:wrap;width:100%}
        .tabInput{position:fixed;top:0;left:0;opacity:0}
        .tabLabel{width:auto;color:#C4C4C8;padding-left:15px;order:1;}
        .tabLabel:hover{background-color:#555;color:#ccc;}
        .tabInput:checked+.tabLabel{font-weight:bold;}
        .tabPanel{display:none;width:100%;order:99}
        .tabInput:checked+.tabLabel+.tabPanel{display:block;margin-top:50px;margin-left:10px;transition:margin-left 0.3s ease;}
        .hidden{display:none;}
        .side-menu{width:180px;height:100%;background:linear-gradient(to bottom,#07142A 80%,rgba(0,0,0,1) 98%,black 100%);position:fixed;top:0;left:0;line-height:1.15;margin-top:50px;z-index:9998;transition:width 0.5s ease;padding:5px;}
        .side-menu.collapsed{width:50px;}
        .side-menu.collapsed div,.side-menu.collapsed h2,.side-menu.collapsed ul,.side-menu.collapsed ul li{opacity:0;height:0;overflow:hidden;}
        .menu-button{margin:0;padding:10px;font-size:16px;cursor:pointer;background-color:transparent;border:none;color:white;position:absolute;right:10px;top:10px;}
        .stuff{color:#C4C4C8;font-weight:normal;width:auto;text-decoration:none;padding:5px 10px;order:1;border-radius:0;margin:2px 5px;display:block;cursor:pointer;}
        .stuff:hover{font-weight:normal;background-color:#17405A;text-decoration:none;color:white;border-radius:5px;outline:.5px solid white;}
        .stuff:active{background-color:#D2D9DE;color:white;}
        .card{background:#fff;border-radius:6px;padding:14px 20px;box-shadow:0 1px 4px rgba(0,0,0,.1);}
        .LargeCard{background:#fff;border-radius:6px;padding:10px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:10px;}
        .cardtitle{font-size:14px;color:#71808d;font-weight:bold;margin-bottom:6px;}
        .cardsubtitle{font-size:11px;color:#999;padding-right:8px;white-space:nowrap;}
        .percentagetext{font-size:2rem;font-weight:700;}
        .collapsible{font-family:"Open Sans",sans-serif;font-size:15px;font-weight:600;color:#333;padding-left:0;background-color:inherit;cursor:pointer;border:none;outline:none;}
        .active,.collapsible:hover{color:#CE112D;}
        .content{max-height:0;overflow:hidden;transition:max-height 0.2s ease-out;}
        .landingtext{padding:10px;}
        .modern-input{width:200px;padding:8px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;background-color:#f9f9f9;box-shadow:inset 0 1px 3px rgba(0,0,0,.1);}
        .modern-input:focus{box-shadow:0 0 5px rgba(0,123,255,.5);border-color:#25648C;outline:none;}
        button.pagination-button{border:none;outline:none;background-color:transparent;cursor:pointer;padding:5px 10px;margin:2px;border-radius:.2rem;color:#345367;}
        button.pagination-button:hover{background-color:#F56A00;color:#345367;}
        button.pagination-button.active{background-color:#345367;color:white;}
        .NamesTh{cursor:pointer;}
        .divbarDomain{background-color:#e0e0e0;border-radius:3px;height:6px;width:200px;margin-top:2px;}
        .divbarDomainInside{background-color:#f29650;border-radius:3px;height:6px;}
        """;

    // ── JavaScript ────────────────────────────────────────────────────────────

    private string BuildScript(DashboardData d)
    {
        string peerAvg    = "[18, 9, 15]";
        string peerActual = $"[{d.PeerActualComputers},{d.PeerActualShares},{d.PeerActualAces}]";
        string compBar    = $"[{d.PingableCount},{d.Port445Open},{d.ComputersWithShares}," +
                            $"{d.NonDefaultShares},{d.ComputersWithExcessive},{d.SharesWithRead},{d.SharesWithWrite}]";

        var sb = new StringBuilder();
        sb.AppendLine("<script>");
        sb.AppendLine(StaticJs());
        sb.AppendLine("document.addEventListener('DOMContentLoaded', function() {");
        sb.AppendLine(BarChartJs("ChartDashboardPeerCompare", $"[{{name:'Peer Average',data:{peerAvg}}},{{name:'This Environment',data:{peerActual}}}]", "['Computers','Shares','ACEs']", "Percent of Assets with Excessive Privileges", 230, grouped: true, peerMode: true));
        sb.AppendLine(MixedTimelineJs("TimelineCreationChart", "Share Creation Timeline", d.JsTimelineDates, d.JsTimelineComputers, d.JsTimelineShares, d.JsTimelineHighRisk));
        sb.AppendLine(SimpleTimelineJs("TimelineLastAccessChart", "Last Access Timeline", d.JsLastAccessDates, d.JsLastAccessShares, "#f29650"));
        sb.AppendLine(SimpleTimelineJs("TimelineLastModChart", "Last Modified Timeline", d.JsLastModDates, d.JsLastModShares, "#9ba1a9"));
        sb.AppendLine(BarChartJs("ChartComputersDisco", $"[{{data:{compBar}}}]", "['Ping','Port 445','Has Shares','Non-Default','Excessive','Readable','Writable']", "Computers by Share Exposure", 220));
        sb.AppendLine($"var osNames={d.JsOsNames};var osValues={d.JsOsValues};var sortedOS=osNames.map((n,i)=>({{n,v:osValues[i]}})).sort((a,b)=>b.v-a.v);");
        sb.AppendLine(BarChartJs("ChartComputersOS", "[{name:'Count',data:sortedOS.map(x=>x.v)}]", "sortedOS.map(x=>x.n)", "Computer Count by OS", 220, rawCategories: true));
        sb.AppendLine(BarChartJs("ChartAceType", $"[{{data:{d.JsAceTypeValues}}}]", d.JsAceTypeCategories, "ACE Type Count", 220));
        sb.AppendLine(BarChartJs("ChartAceRisk", $"[{{data:[{d.RiskCritical},{d.RiskHigh},{d.RiskMedium},{d.RiskLow}]}}]", "['Critical','High','Medium','Low']", "ACE Count by Risk Level", 220));
        sb.AppendLine("});");
        sb.AppendLine("""
            function buildXY(dates,values){return dates.map(function(d,i){return {x:new Date(d).getTime(),y:values[i]};});}
            """);
        sb.AppendLine("</script>");
        return sb.ToString();
    }

    // ── Static JS (no C# interpolation) ──────────────────────────────────────

    private static string StaticJs() => """
        function switchTab(tabId,btnId){var r=document.getElementById(tabId);if(r)r.checked=true;updateLabelColors('sidetabs',btnId);}
        function toggleMenu(){var m=document.getElementById('sideMenu');var main=document.getElementById('main');m.classList.toggle('collapsed');main.style.marginLeft=m.classList.contains('collapsed')?'60px':'190px';}
        function updateLabelColors(divId,objId){var d=document.getElementById(divId);if(!d)return;d.querySelectorAll('label').forEach(function(l){if(!l.id.startsWith('noaction')){l.style.color='';l.style.backgroundColor='';l.style.borderRadius='';}});var o=document.getElementById(objId);if(o){o.style.color='white';o.style.backgroundColor='rgba(53,67,103,0.75)';o.style.borderRadius='5px';}}
        document.querySelectorAll('.collapsible').forEach(function(b){b.addEventListener('click',function(){this.classList.toggle('active');var c=this.nextElementSibling;c.style.maxHeight=c.style.maxHeight?null:c.scrollHeight+'px';});});
        var rowsPerPage=50,currentPage=1,currentFilteredRows=[];
        function applyFiltersAndSort(tId,sId,cId,pId){var t=document.getElementById(tId);if(!t)return;var s=sId?(document.getElementById(sId)||{value:''}).value.toLowerCase():'';currentFilteredRows=Array.from(t.querySelectorAll('tbody tr')).filter(function(r){return r.textContent.toLowerCase().includes(s);});currentPage=1;displayRows(tId,currentFilteredRows,cId,pId);}
        function displayRows(tId,rows,cId,pId){var t=document.getElementById(tId);if(!t)return;Array.from(t.querySelector('tbody').rows).forEach(function(r){r.classList.add('hidden');});rows.slice((currentPage-1)*rowsPerPage,currentPage*rowsPerPage).forEach(function(r){r.classList.remove('hidden');});if(cId){var c=document.getElementById(cId);if(c)c.textContent=rows.length+' matches';}if(pId)updatePagination(tId,pId,rows.length);}
        function updatePagination(tId,pId,total){var pag=document.getElementById(pId);if(!pag)return;pag.innerHTML='';var pages=Math.ceil(total/rowsPerPage)||1;for(var i=1;i<=Math.min(pages,20);i++)createPageBtn(i,tId,pId);var nxt=document.createElement('button');nxt.textContent='→';nxt.className='pagination-button';nxt.addEventListener('click',function(){if(currentPage<pages){currentPage++;displayRows(tId,currentFilteredRows,null,pId);}});pag.appendChild(nxt);}
        function createPageBtn(n,tId,pId){var pag=document.getElementById(pId);var btn=document.createElement('button');btn.textContent=n;btn.className='pagination-button';if(n===currentPage)btn.classList.add('active');btn.addEventListener('click',function(){currentPage=n;var inputMap={sharenametable:'filterInput',foldergrouptable:'filterInputTwo',aceTable:'acefilterInput',IdentityTable:'IdentityfilterInput',recoveredsecretstable:'secretsInputTwo',ComputersTable:'computerfilterInput'};var counterMap={sharenametable:'filterCounter',foldergrouptable:'filterCounterTwo',aceTable:'acefilterCounter',IdentityTable:'IdentityfilterCounter',recoveredsecretstable:'secretsCounterTwo',ComputersTable:'computerfilterCounter'};applyFiltersAndSort(tId,inputMap[tId],counterMap[tId],pId);});pag.appendChild(btn);}
        function initTable(tId,iId,cId,pId){var inp=document.getElementById(iId);if(inp)inp.addEventListener('keyup',function(){applyFiltersAndSort(tId,iId,cId,pId);});applyFiltersAndSort(tId,iId,cId,pId);}
        document.addEventListener('DOMContentLoaded',function(){
          initTable('ComputersTable','computerfilterInput','computerfilterCounter','computerpagination');
          initTable('sharenametable','filterInput','filterCounter','pagination');
          initTable('foldergrouptable','filterInputTwo','filterCounterTwo','paginationfg');
          initTable('aceTable','acefilterInput','acefilterCounter','acepagination');
          initTable('IdentityTable','IdentityfilterInput','IdentityfilterCounter','Identitypagination');
          initTable('recoveredsecretstable','secretsInputTwo','secretsCounterTwo','paginationsecrets');
        });
        """;

    // ── ApexCharts helpers ────────────────────────────────────────────────────

    private static string BarChartJs(
        string elementId, string series, string categories, string title,
        int height, bool grouped = false, bool peerMode = false, bool rawCategories = false)
    {
        string catProp = rawCategories ? $"categories:{categories}" : $"categories:{categories}";
        string plotOpts = grouped
            ? "plotOptions:{bar:{horizontal:false,columnWidth:'55%'}}"
            : "plotOptions:{bar:{borderRadius:0,horizontal:true,colors:{backgroundBarColors:['#e0e0e0'],backgroundBarOpacity:1,ranges:[{from:0,to:99999,color:'#f29650'}]}}}";
        string dataLabels = peerMode
            ? "dataLabels:{enabled:true,offsetY:-20,style:{fontSize:'12px',colors:['#345367']},formatter:function(v){return v+'%';}}"
            : "dataLabels:{enabled:false}";
        string colors = peerMode ? "colors:['#345367','#f29650']," : string.Empty;
        string tooltip = peerMode
            ? "tooltip:{y:{formatter:function(v){return v+'%';}}},"
            : "tooltip:{shared:true},";
        string yAxis = peerMode ? "yaxis:{labels:{show:false}}," : string.Empty;
        return $"new ApexCharts(document.getElementById('{elementId}')," +
               $"{{series:{series},chart:{{type:'bar',height:{height}}}," +
               $"{colors}{plotOpts},{dataLabels},grid:{{show:false}}," +
               $"stroke:{{show:true,width:2,colors:['transparent']}}," +
               $"xaxis:{{{catProp}}},{yAxis}{tooltip}" +
               $"title:{{text:'{title.Replace("'", "\\'")}',align:'center',style:{{fontSize:'13px',fontWeight:'bold',color:'#71808d'}}}}" +
               $"}}).render();";
    }

    private static string MixedTimelineJs(
        string elementId, string title,
        string dates, string computers, string shares, string highRisk) =>
        $"new ApexCharts(document.getElementById('{elementId}')," +
        $"{{series:[" +
        $"{{name:'Computers',type:'column',data:buildXY({dates},{computers}),color:'#9ba1a9'}}," +
        $"{{name:'Shares',type:'column',data:buildXY({dates},{shares}),color:'#f29650'}}," +
        $"{{name:'High Risk',type:'line',data:buildXY({dates},{highRisk}),color:'#772400'}}" +
        $"],chart:{{height:320,type:'line',stacked:false}}," +
        $"stroke:{{width:[0,0,2],curve:'smooth'}}," +
        $"plotOptions:{{bar:{{columnWidth:'70%'}}}}," +
        $"xaxis:{{type:'datetime'}}," +
        $"yaxis:{{title:{{text:'Count',style:{{color:'#71808d'}}}}}}," +
        $"tooltip:{{shared:true,intersect:false}}," +
        $"title:{{text:'{title.Replace("'", "\\'")}',align:'center',style:{{fontSize:'13px',fontWeight:'bold',color:'#71808d'}}}}" +
        $"}}).render();";

    private static string SimpleTimelineJs(
        string elementId, string title, string dates, string values, string color) =>
        $"new ApexCharts(document.getElementById('{elementId}')," +
        $"{{series:[{{name:'Shares',type:'column',data:buildXY({dates},{values}),color:'{color}'}}]," +
        $"chart:{{height:250,type:'bar'}}," +
        $"xaxis:{{type:'datetime'}}," +
        $"yaxis:{{title:{{text:'Count',style:{{color:'#71808d'}}}}}}," +
        $"tooltip:{{shared:true}}," +
        $"title:{{text:'{title.Replace("'", "\\'")}',align:'center',style:{{fontSize:'13px',fontWeight:'bold',color:'#71808d'}}}}" +
        $"}}).render();";

    // ── Utility helpers ───────────────────────────────────────────────────────

    private static string JsArray(IEnumerable<int> values) =>
        "[" + string.Join(",", values) + "]";

    private static string JsStringArray(IEnumerable<string> values) =>
        "[" + string.Join(",", values.Select(v => "\"" + v.Replace("\"", "\\\"") + "\"")) + "]";

    private static string Pct(int part, int total) =>
        total == 0 ? "0%" : $"{(double)part / total:P1}";

    private static string Esc(string? s) =>
        s?.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
          .Replace("\"", "&quot;") ?? string.Empty;
}
