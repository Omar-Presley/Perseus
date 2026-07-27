using System.IO;

namespace Perseus.Models;

public static class AnthropicKeyStore
{
    public static string Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return string.Empty;
            return SecretProtector.Unprotect(File.ReadAllText(path));
        }
        catch
        {
            return string.Empty;
        }
    }

    public static void Save(string path, string apiKey)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(path, SecretProtector.Protect(apiKey));
    }
}
