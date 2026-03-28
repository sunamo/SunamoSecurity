namespace SunamoSecurity;

/// <summary>
/// Provides conversion methods between <see cref="SecureString"/> and regular strings,
/// and convenience methods for encrypting and decrypting strings.
/// </summary>
public static class SecureStringHelper
{
    /// <summary>
    /// Converts a regular string to a <see cref="SecureString"/> using <see cref="NetworkCredential"/>.
    /// </summary>
    /// <param name="text">The string to convert to a secure string.</param>
    /// <returns>A <see cref="SecureString"/> containing the value of the input string.</returns>
    public static SecureString ToSecureString(this string text)
    {
        SecureString secureString = new NetworkCredential(string.Empty, text).SecurePassword;
        return secureString;
    }

    /// <summary>
    /// Converts a regular string to a <see cref="SecureString"/> by appending each character individually.
    /// </summary>
    /// <param name="text">The string to convert to a secure string.</param>
    /// <returns>A read-only <see cref="SecureString"/> containing the value of the input string.</returns>
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
    /// Converts a <see cref="SecureString"/> to a regular string using BSTR marshalling.
    /// </summary>
    /// <param name="secureString">The secure string to convert.</param>
    /// <returns>The plain text representation of the secure string.</returns>
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
    /// Converts a <see cref="SecureString"/> to a regular string using Unicode global allocation.
    /// </summary>
    /// <param name="secureString">The secure string to convert.</param>
    /// <returns>The plain text representation of the secure string, or <c>null</c> if conversion fails.</returns>
    public static string? ToInsecureString(SecureString secureString)
    {
        nint unmanagedString = nint.Zero;
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
    /// Decrypts an encrypted string using DPAPI with the specified salt.
    /// </summary>
    /// <param name="salt">The salt used as additional entropy for decryption.</param>
    /// <param name="encryptedText">The Base64-encoded encrypted string to decrypt.</param>
    /// <returns>The decrypted plain text string, or <c>null</c> if decryption fails.</returns>
    [SupportedOSPlatform("windows")]
    public static string? DecryptString(string salt, string encryptedText)
    {
        return ToInsecureString(ProtectedDataHelper.DecryptString(salt, encryptedText));
    }

    /// <summary>
    /// Encrypts a plain text string using DPAPI with the specified salt.
    /// </summary>
    /// <param name="salt">The salt used as additional entropy for encryption.</param>
    /// <param name="text">The plain text string to encrypt.</param>
    /// <returns>The encrypted string as a Base64-encoded value, or <c>null</c> if encryption fails.</returns>
    [SupportedOSPlatform("windows")]
    public static string? EncryptString(string salt, string text)
    {
        SecureString secureString = text.ToSecureString();
        return ProtectedDataHelper.EncryptString(salt, secureString);
    }

    /// <summary>
    /// Creates a <see cref="CryptDelegates"/> instance with the default encryption and decryption methods.
    /// </summary>
    /// <returns>A new <see cref="CryptDelegates"/> with <see cref="DecryptString"/> and <see cref="EncryptString"/> as delegates.</returns>
    [SupportedOSPlatform("windows")]
    public static CryptDelegates CreateCryptDelegates()
    {
        CryptDelegates cryptDelegates = new(DecryptString, EncryptString);
        return cryptDelegates;
    }
}