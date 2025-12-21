namespace SunamoSecurity.Crypting;

// EN: Variable names have been checked and replaced with self-descriptive names
// CZ: Názvy proměnných byly zkontrolovány a nahrazeny samopopisnými názvy
public class CryptDelegates
{
    public CryptDelegates(Func<string, string, string?> decryptString, Func<string, string, string?> encryptString)
    {
        this.DecryptString = decryptString;
        this.EncryptString = encryptString;
    }

    public Func<string, string, string?> DecryptString { get; set; }
    public Func<string, string, string?> EncryptString { get; set; }


}