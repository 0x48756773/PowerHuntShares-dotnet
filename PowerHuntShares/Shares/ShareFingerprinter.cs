using System.Xml;
using PowerHuntShares.Shares.Models;
using PowerHuntShares.Utilities;

namespace PowerHuntShares.Shares;

/// <summary>
/// Sends a share name and file list to an LLM and parses the structured XML
/// response to identify the application associated with each share.
///
/// Ports Invoke-FingerPrintShare (PowerHuntShares.psm1 line 28325).
/// </summary>
public class ShareFingerprinter
{
    private readonly LlmClient _llm;

    public ShareFingerprinter(LlmClient llm)
    {
        _llm = llm;
    }

    /// <summary>
    /// Fingerprints a single share. Returns null if the LLM returns no
    /// confident match (confidence score ≤ 3) or an unparseable response.
    /// </summary>
    /// <param name="shareName">The share name, e.g. "sccm".</param>
    /// <param name="fileList">
    ///   Comma-separated or newline-separated list of file names found in the share.
    /// </param>
    /// <param name="folderGroup">
    ///   Optional folder group hash — carried through to the result for
    ///   cross-referencing with other records.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<ShareFingerprintResult?> FingerprintAsync(
        string shareName,
        string fileList,
        string folderGroup = "",
        CancellationToken ct = default)
    {
        string prompt = BuildPrompt(shareName, fileList);

        LlmResult raw;
        try
        {
            raw = await _llm.SendWithUsageAsync(prompt, ct: ct);
        }
        catch
        {
            return null;
        }

        string xml = raw.Content?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(xml))
            return null;

        var parsed = TryParseXml(xml);
        if (parsed is null)
            return null;

        parsed.PromptTokens     = raw.PromptTokens;
        parsed.CompletionTokens = raw.CompletionTokens;
        parsed.TotalTokens      = raw.TotalTokens;
        parsed.FolderGroup      = folderGroup;

        return parsed;
    }

    /// <summary>
    /// Fingerprints a batch of shares in parallel. Results where the LLM
    /// returned no confident match are omitted from the returned list.
    /// </summary>
    public async Task<IReadOnlyList<ShareFingerprintResult>> FingerprintBatchAsync(
        IEnumerable<(string ShareName, string FileList, string FolderGroup)> shares,
        int maxConcurrency = 4,
        CancellationToken ct = default)
    {
        var results = new System.Collections.Concurrent.ConcurrentBag<ShareFingerprintResult>();

        await Parallel.ForEachAsync(shares,
            new ParallelOptions { MaxDegreeOfParallelism = maxConcurrency, CancellationToken = ct },
            async (item, token) =>
            {
                var r = await FingerprintAsync(item.ShareName, item.FileList, item.FolderGroup, token);
                if (r is not null)
                    results.Add(r);
            });

        return [.. results];
    }

    // ── Prompt construction ───────────────────────────────────────────────────

    // Mirrors the $MyPrompt here-string from Invoke-FingerPrintShare (line 28494).
    private static string BuildPrompt(string shareName, string fileList) => $$"""
        You will be provided with a share name and a list of file names. Your task is to:

        1. Analyze the provided share name to determine it is related to a known application.  Please ensure your only return a application guess if you know of an existing application or operating system by name. Do not make things up or refer generic product categories.
        2. Analyze all provided file names to determine if one or more are related to a known application or operating system. Make sure to take into analyze file names, file name prefixes, and file extensions. Run the analysis 5 times on the backend and select the one that is most accurate.
        3. Define a confidence score ranging from 1 to 5, where 5 represents very high confidence.
        4. If any identified applications have a confidence score above 3, return the top one application and it's confidence score.
        5. If no application has a confidence score above 3, then don't return anything.
        6. For each identified application where the confidence score is above 3, return the following information in XML format:
        - Share Name
        - Application Name
        - Confidence Score
        - A list of the top 10 most relevant files that have been comma seperated on one line.
        - A two-sentence justification of the match. Include the justification based on the share name in the first sentance, the justification based on the top 5 file names in the second, and link to a real and relevant application page at the end.
        Ensure the output is formatted as XML. Please only return the XML formatted response with nothing else. Please DO NOT wrap the XML response with any comments or labeling. For example, do not include "```xml". Please do not wrap responses in nested {}.

        Please ensure the xml follows the structure below:
        Applications.Application.ShareName
        Applications.Application.ApplicationName
        Applications.Application.ConfidenceScore
        Applications.Application.RelevantFiles
        Applications.Application.Justification

        If no link can be found to a real and relevant application page, don't return the xml or anything else.

        Input:

        Share Name:
        {{shareName}}

        File Names:
        {{fileList}}
        """;

    // ── XML parsing ───────────────────────────────────────────────────────────

    private static ShareFingerprintResult? TryParseXml(string xml)
    {
        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);

            // Expected shape: <Applications><Application>...</Application></Applications>
            XmlNode? app = doc.SelectSingleNode("//Application");
            if (app is null)
                return null;

            string? shareName = app.SelectSingleNode("ShareName")?.InnerText;
            if (string.IsNullOrWhiteSpace(shareName))
                return null;

            return new ShareFingerprintResult
            {
                ShareName       = shareName.Trim(),
                ApplicationName = app.SelectSingleNode("ApplicationName")?.InnerText?.Trim() ?? string.Empty,
                ConfidenceScore = app.SelectSingleNode("ConfidenceScore")?.InnerText?.Trim() ?? string.Empty,
                RelevantFiles   = app.SelectSingleNode("RelevantFiles")?.InnerText?.Trim()   ?? string.Empty,
                Justification   = app.SelectSingleNode("Justification")?.InnerText?.Trim()   ?? string.Empty,
            };
        }
        catch
        {
            return null;
        }
    }
}
