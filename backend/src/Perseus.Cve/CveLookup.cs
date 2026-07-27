using Perseus.Audit;
using Perseus.Reporting;

namespace Perseus.Cve;

public static class CveLookup
{
    public static async Task RunAsync(FindingStore store, IReadOnlyList<SoftwareItem> software,
        AuditSettings settings, AuditSignatures signatures)
    {
        Console.WriteLine("\n[*] Cross-referencing software against NVD (informational)...");
        Console.WriteLine("    Uses CPE-based version matching where possible (falls back to a");
        Console.WriteLine("    labeled keyword search only if a product has no CPE dictionary entry).");

        NvdClient.SetApiKey(settings.NvdApiKey);

        var pattern = new System.Text.RegularExpressions.Regex(signatures.CveWatchlistPattern,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        var targets = software.Where(s => pattern.IsMatch(s.Name)).Take(settings.MaxCveTargets).ToList();

        if (targets.Count == 0)
        {
            ConsoleUi.WriteStatus("i", "No high-signal software matched for CVE lookup", ConsoleColor.DarkGray);
            return;
        }

        // Sequential by design: NVD's public rate limit is shared and unauthenticated
        // by default, so parallelizing here would just trip the limit faster - unlike
        // local checks, waiting out the polite delay is the actual bottleneck to respect,
        // not something to race past.
        foreach (var item in targets)
        {
            var cpe = await NvdClient.ResolveCpeAsync(item.Name, settings.NvdDelayMs);
            List<CveResult> results;
            string matchedVia;

            if (cpe is not null)
            {
                var versionedCpe = $"cpe:2.3:a:{cpe.Vendor}:{cpe.Product}:{item.Version}:*:*:*:*:*:*:*";
                results = await NvdClient.GetCvesForVersionedCpeAsync(versionedCpe, settings.NvdDelayMs);
                matchedVia = "cpe";
            }
            else
            {
                results = await NvdClient.KeywordSearchAsync($"{item.Name} {item.Version}", settings.NvdDelayMs);
                matchedVia = "keyword";
            }

            if (results.Count == 0)
            {
                ConsoleUi.WriteStatus("OK", $"{item.Name} {item.Version}: no CVEs matched via {matchedVia}", ConsoleColor.Green);
                continue;
            }

            foreach (var r in results)
            {
                var confidence = matchedVia == "cpe" ? "CPE version-matched" : "keyword match - low confidence";
                var severity = r.Severity switch
                {
                    "Critical" => Severity.Critical,
                    "High" => Severity.High,
                    "Medium" => Severity.Medium,
                    _ => Severity.Low
                };

                store.Add("CVE", $"{item.Name} {item.Version} - {r.CveId}", FindingStatus.Warning,
                    $"{r.Description} (CVSS: {r.CvssScore?.ToString("0.0") ?? "n/a"}, {confidence})",
                    "Verify applicability against the vendor advisory and patch to the latest version.", severity);
                ConsoleUi.WriteStatus("!", $"{item.Name}: {r.CveId} [{matchedVia}]", ConsoleColor.Yellow);
            }
        }

        Console.WriteLine("\n    Note: even CPE-matched results are best-effort against public NVD data.");
        Console.WriteLine("    Always verify against vendor advisories before treating a match as confirmed.");
    }
}
