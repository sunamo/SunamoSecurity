namespace SunamoSecurity;

[SupportedOSPlatform("windows")]
public static class ProtectedDataHelper
{
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
