namespace SunamoSecurity;

/// <summary>
/// Provides methods to encrypt and decrypt strings using the Windows Data Protection API (DPAPI).
/// </summary>
[SupportedOSPlatform("windows")]
public static class ProtectedDataHelper
{
    /// <summary>
    /// Encrypts a <see cref="SecureString"/> using DPAPI with the specified salt.
    /// </summary>
    /// <param name="salt">The salt used as additional entropy for encryption.</param>
    /// <param name="secureString">The secure string to encrypt.</param>
    /// <param name="dataProtectionScope">The scope of data protection (current user or local machine).</param>
    /// <returns>The encrypted string as a Base64-encoded value, or <c>null</c> if the input is null.</returns>
    public static string? EncryptString(string salt, SecureString secureString, DataProtectionScope dataProtectionScope = DataProtectionScope.CurrentUser)
    {
        byte[] entropy = Encoding.Unicode.GetBytes(salt);
        var insecureString = SecureStringHelper.ToInsecureString(secureString);
        if (insecureString == null)
        {
            return null;
        }
        byte[] encryptedData = ProtectedData.Protect(
            Encoding.Unicode.GetBytes(insecureString),
            entropy,
            dataProtectionScope);
        return Convert.ToBase64String(encryptedData);
    }

    /// <summary>
    /// Decrypts a Base64-encoded encrypted string using DPAPI with the specified salt.
    /// </summary>
    /// <param name="salt">The salt used as additional entropy for decryption.</param>
    /// <param name="encryptedText">The Base64-encoded encrypted string to decrypt.</param>
    /// <param name="dataProtectionScope">The scope of data protection (current user or local machine).</param>
    /// <returns>The decrypted value as a <see cref="SecureString"/>. Returns an empty <see cref="SecureString"/> if decryption fails.</returns>
    public static SecureString DecryptString(string salt, string encryptedText, DataProtectionScope dataProtectionScope = DataProtectionScope.CurrentUser)
    {
        try
        {
            byte[] entropy = Encoding.Unicode.GetBytes(salt);
            byte[] decryptedData = [];
            try
            {
                decryptedData = ProtectedData.Unprotect(
                Convert.FromBase64String(encryptedText),
                entropy,
                dataProtectionScope);
            }
            catch (Exception ex)
            {
                ThrowEx.Custom(ex.Message);
                return new SecureString();
            }
            return Encoding.Unicode.GetString(decryptedData).ToSecureString();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"DecryptString failed: {ex.GetType().Name}: {ex.Message}");
            return new SecureString();
        }
    }
}