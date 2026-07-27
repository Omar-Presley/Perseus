using System.Text.Json;

namespace Perseus.Cve;

public sealed record CpeMatch(string Vendor, string Product);

public sealed record CveResult(string CveId, string Description, double? CvssScore, string Severity);

public static class NvdClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    public static void SetApiKey(string? apiKey)
    {
        Http.DefaultRequestHeaders.Remove("apiKey");
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            Http.DefaultRequestHeaders.Add("apiKey", apiKey);
        }
    }

    /// <summary>
    /// Resolves a product name to a vendor:product pair via the NVD CPE
    /// dictionary, so callers can build a fully-versioned CPE 2.3 string
    /// and get real version-range matching server-side, instead of a
    /// keyword text search.
    /// </summary>
    public static async Task<CpeMatch?> ResolveCpeAsync(string productName, int delayMs)
    {
        var uri = $"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={Uri.EscapeDataString(productName)}&resultsPerPage=5";
        try
        {
            using var response = await Http.GetAsync(uri);
            await Task.Delay(delayMs);
            if (!response.IsSuccessStatusCode) return null;

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var products = doc.RootElement.GetProperty("products");
            if (products.GetArrayLength() == 0) return null;

            var cpeName = products[0].GetProperty("cpe").GetProperty("cpeName").GetString();
            if (cpeName is null) return null;

            var parts = cpeName.Split(':');
            if (parts.Length < 6) return null;

            return new CpeMatch(parts[3], parts[4]);
        }
        catch
        {
            return null;
        }
    }

    public static async Task<List<CveResult>> GetCvesForVersionedCpeAsync(string cpeName, int delayMs)
    {
        var uri = $"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={Uri.EscapeDataString(cpeName)}&resultsPerPage=5";
        var results = new List<CveResult>();
        try
        {
            using var response = await Http.GetAsync(uri);
            await Task.Delay(delayMs);
            if (!response.IsSuccessStatusCode) return results;

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulns)) return results;

            foreach (var v in vulns.EnumerateArray())
            {
                var cve = v.GetProperty("cve");
                var cveId = cve.GetProperty("id").GetString() ?? "unknown";
                var description = cve.GetProperty("descriptions").EnumerateArray()
                    .FirstOrDefault(d => d.GetProperty("lang").GetString() == "en")
                    .GetProperty("value").GetString() ?? "";

                double? cvss = null;
                if (cve.TryGetProperty("metrics", out var metrics))
                {
                    if (metrics.TryGetProperty("cvssMetricV31", out var v31) && v31.GetArrayLength() > 0)
                        cvss = v31[0].GetProperty("cvssData").GetProperty("baseScore").GetDouble();
                    else if (metrics.TryGetProperty("cvssMetricV30", out var v30) && v30.GetArrayLength() > 0)
                        cvss = v30[0].GetProperty("cvssData").GetProperty("baseScore").GetDouble();
                    else if (metrics.TryGetProperty("cvssMetricV2", out var v2) && v2.GetArrayLength() > 0)
                        cvss = v2[0].GetProperty("cvssData").GetProperty("baseScore").GetDouble();
                }

                var severity = cvss switch
                {
                    >= 9 => "Critical",
                    >= 7 => "High",
                    >= 4 => "Medium",
                    _ => "Low"
                };

                results.Add(new CveResult(cveId, description, cvss, severity));
            }
        }
        catch
        {
            // network/parse failure - return what we have (possibly empty)
        }
        return results;
    }

    public static async Task<List<CveResult>> KeywordSearchAsync(string query, int delayMs)
    {
        var uri = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={Uri.EscapeDataString(query)}&resultsPerPage=3";
        var results = new List<CveResult>();
        try
        {
            using var response = await Http.GetAsync(uri);
            await Task.Delay(delayMs);
            if (!response.IsSuccessStatusCode) return results;

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulns)) return results;

            foreach (var v in vulns.EnumerateArray())
            {
                var cve = v.GetProperty("cve");
                var cveId = cve.GetProperty("id").GetString() ?? "unknown";
                var description = cve.GetProperty("descriptions").EnumerateArray()
                    .FirstOrDefault(d => d.GetProperty("lang").GetString() == "en")
                    .GetProperty("value").GetString() ?? "";
                results.Add(new CveResult(cveId, description, null, "Low"));
            }
        }
        catch { /* best effort */ }
        return results;
    }
}
