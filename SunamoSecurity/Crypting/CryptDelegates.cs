namespace SunamoSecurity.Crypting;

/// <summary>
/// Holds delegate references for string encryption and decryption operations.
/// </summary>
public class CryptDelegates
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CryptDelegates"/> class.
    /// </summary>
    /// <param name="decryptString">The function to decrypt a string using salt and encrypted text.</param>
    /// <param name="encryptString">The function to encrypt a string using salt and plain text.</param>
    public CryptDelegates(Func<string, string, string?> decryptString, Func<string, string, string?> encryptString)
    {
        this.DecryptString = decryptString;
        this.EncryptString = encryptString;
    }

    /// <summary>
    /// Gets or sets the decryption function that takes salt and encrypted text, returning the decrypted string.
    /// </summary>
    public Func<string, string, string?> DecryptString { get; set; }

    /// <summary>
    /// Gets or sets the encryption function that takes salt and plain text, returning the encrypted string.
    /// </summary>
    public Func<string, string, string?> EncryptString { get; set; }
}