namespace SunamoShared.Helpers.Secure;
public static class ProtectedDataHelper
{
    public static dynamic DataProtectionScope { get; private set; }

    public static string EncryptString(string salt, SecureString input)
    {
        byte[] entropy = Encoding.Unicode.GetBytes(salt);
        byte[] encryptedData = ProtectedData.Protect(
            Encoding.Unicode.GetBytes(SecureStringHelper.ToInsecureString(input)),
            entropy,
            DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(encryptedData);
    }

    public static SecureString DecryptString(string salt, string encryptedData)
    {
        try
        {
            byte[] entropy = Encoding.Unicode.GetBytes(salt);
            byte[] decryptedData = null;
            try
            {
                decryptedData = ProtectedData.Unprotect(
                Convert.FromBase64String(encryptedData),
                entropy,
                DataProtectionScope.CurrentUser);
            }
            catch (Exception ex)
            {
                ThrowEx.Custom(ex);
                return new SecureString();
            }
            return Encoding.Unicode.GetString(decryptedData).ToSecureString();
        }
        catch
        {
            return new SecureString();
        }
    }
}
