namespace SunamoSecurity;

/// <summary>
/// Represents the secure string helper type.
/// </summary>
public static class SecureStringHelper
{
    /// <summary>
    /// To secure string.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns>The to secure string result.</returns>
    public static SecureString ToSecureString(this string text)
    {
        SecureString secureString = new NetworkCredential(string.Empty, text).SecurePassword;
        return secureString;
    }

    /// <summary>
    /// To secure string 2.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns>The to secure string 2 result.</returns>
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

    /// <summary>
    /// To insecure string 2.
    /// </summary>
    /// <param name="secureString">The secure string.</param>
    /// <returns>The to insecure string 2 result.</returns>
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

    /// <summary>
    /// To insecure string.
    /// </summary>
    /// <param name="secureString">The secure string.</param>
    /// <returns>The to insecure string result.</returns>
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

    /// <summary>
    /// Decrypt string.
    /// </summary>
    /// <param name="salt">The salt.</param>
    /// <param name="encryptedText">The encrypted text.</param>
    /// <returns>The decrypt string result.</returns>
    [SupportedOSPlatform("windows")]
    public static string? DecryptString(string salt, string encryptedText)
    {
        return ToInsecureString(ProtectedDataHelper.DecryptString(salt, encryptedText));
    }

    /// <summary>
    /// Encrypt string.
    /// </summary>
    /// <param name="salt">The salt.</param>
    /// <param name="text">The text.</param>
    /// <returns>The encrypt string result.</returns>
    [SupportedOSPlatform("windows")]
    public static string? EncryptString(string salt, string text)
    {
        SecureString secureString = text.ToSecureString();
        return ProtectedDataHelper.EncryptString(salt, secureString);
    }

    /// <summary>
    /// Create crypt delegates.
    /// </summary>
    /// <returns>The create crypt delegates result.</returns>
    [SupportedOSPlatform("windows")]
    public static CryptDelegates CreateCryptDelegates()
    {
        CryptDelegates cryptDelegates = new(DecryptString, EncryptString);
        return cryptDelegates;
    }
}
