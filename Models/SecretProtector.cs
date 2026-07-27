using System;
using System.Security.Cryptography;
using System.Text;
using Perseus.Reporting;

namespace Perseus.Models;

public static class SecretProtector
{
    public static string Protect(string plaintext)
    {
        if (string.IsNullOrEmpty(plaintext)) return string.Empty;

        var bytes = Encoding.UTF8.GetBytes(plaintext);

        if (PlatformHelper.Current == Platform.Windows)
        {
            bytes = ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        }

        return Convert.ToBase64String(bytes);
    }

    public static string Unprotect(string protectedText)
    {
        if (string.IsNullOrEmpty(protectedText)) return string.Empty;

        try
        {
            var bytes = Convert.FromBase64String(protectedText);

            if (PlatformHelper.Current == Platform.Windows)
            {
                bytes = ProtectedData.Unprotect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
            }

            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return string.Empty;
        }
    }
}
