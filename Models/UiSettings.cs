using System.IO;
using System.Text.Json;

namespace Perseus.Models;

public sealed class UiSettings
{
    public bool EnableCveLookup { get; set; } = true;
    public bool GenerateHtml { get; set; } = true;
    public bool GenerateJson { get; set; } = true;
    public bool EnableParallelAudit { get; set; }
    public string ReportFolder { get; set; } = string.Empty;

    public static UiSettings Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                var settings = JsonSerializer.Deserialize<UiSettings>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (settings is not null)
                {
                    return settings;
                }
            }
        }
        catch
        {
            // best effort
        }

        return new UiSettings();
    }

    public void Save(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}
