namespace SunamoSecurity;

public static class SecureStringHelper
{
    public static SecureString ToSecureString(this string text)
    {
        SecureString secureString = new NetworkCredential(string.Empty, text).SecurePassword;
        return secureString;
    }

    public static SecureString ToSecureString2(string text)
    {
        SecureString secureString = new();
        foreach (char character in text)
        {
            secureString.AppendChar(character);
        }
        secureString.MakeReadOnly();
        return secureString;
    }

    public static string ToInsecureString2(SecureString secureString)
    {
        string result = string.Empty;
        nint pointer = Marshal.SecureStringToBSTR(secureString);
        try
        {
            result = Marshal.PtrToStringBSTR(pointer);
        }
        finally
        {
            Marshal.ZeroFreeBSTR(pointer);
        }
        return result;
    }

    public static string? ToInsecureString(SecureString secureString)
    {
        nint unmanagedString = 0;
        try
        {
            unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            return Marshal.PtrToStringUni(unmanagedString);
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
        }
    }

    [SupportedOSPlatform("windows")]
    public static string? DecryptString(string salt, string encryptedText)
    {
        return ToInsecureString(ProtectedDataHelper.DecryptString(salt, encryptedText));
    }

    [SupportedOSPlatform("windows")]
    public static string? EncryptString(string salt, string text)
    {
        SecureString secureString = text.ToSecureString();
        return ProtectedDataHelper.EncryptString(salt, secureString);
    }

    [SupportedOSPlatform("windows")]
    public static CryptDelegates CreateCryptDelegates()
    {
        CryptDelegates cryptDelegates = new(DecryptString, EncryptString);
        return cryptDelegates;
    }
}
