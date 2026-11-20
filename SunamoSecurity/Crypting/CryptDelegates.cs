namespace SunamoSecurity.Crypting;

/// <summary>
/// Represents the crypt delegates type.
/// </summary>
public class CryptDelegates
{
    /// <summary>
    /// Initializes a new instance of the crypt delegates class.
    /// </summary>
    /// <param name="decryptString">The decrypt string.</param>
    /// <param name="encryptString">The encrypt string.</param>
    public CryptDelegates(Func<string, string, string?> decryptString, Func<string, string, string?> encryptString)
    {
        DecryptString = decryptString;
        EncryptString = encryptString;
    }

    /// <summary>
    /// Gets or sets the decrypt string.
    /// </summary>
    public Func<string, string, string?> DecryptString { get; set; }

    /// <summary>
    /// Gets or sets the encrypt string.
    /// </summary>
    public Func<string, string, string?> EncryptString { get; set; }
}
