using System.Security;
using SunamoSecurity.Crypting;

namespace SunamoSecurity.Tests;

/// <summary>
/// Tests for the SunamoSecurity library covering SecureString conversions and encryption operations.
/// </summary>
public class SecurityTests
{
    /// <summary>
    /// Verifies that converting a string to SecureString and back returns the original text.
    /// </summary>
    [Fact]
    public void ToSecureString_AndToInsecureString_RoundTrip_ReturnsOriginalText()
    {
        string text = "TestPassword123!@#";
        SecureString secureString = text.ToSecureString();
        string? result = SecureStringHelper.ToInsecureString(secureString);
        Assert.Equal(text, result);
    }

    /// <summary>
    /// Verifies that converting a string to SecureString2 and back via ToInsecureString2 returns the original text.
    /// </summary>
    [Fact]
    public void ToSecureString2_AndToInsecureString2_RoundTrip_ReturnsOriginalText()
    {
        string text = "AnotherPassword456!";
        SecureString secureString = SecureStringHelper.ToSecureString2(text);
        string result = SecureStringHelper.ToInsecureString2(secureString);
        Assert.Equal(text, result);
    }

    /// <summary>
    /// Verifies that an empty string can be converted to SecureString and back.
    /// </summary>
    [Fact]
    public void ToSecureString_EmptyString_ReturnsEmptyString()
    {
        string text = string.Empty;
        SecureString secureString = text.ToSecureString();
        string? result = SecureStringHelper.ToInsecureString(secureString);
        Assert.Equal(string.Empty, result);
    }

    /// <summary>
    /// Verifies that CreateCryptDelegates returns an instance with valid delegate references.
    /// This test only runs on Windows because CreateCryptDelegates wraps DPAPI methods.
    /// </summary>
    [Fact]
    public void CreateCryptDelegates_ReturnsDelegatesWithValidReferences()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        CryptDelegates cryptDelegates = SecureStringHelper.CreateCryptDelegates();
        Assert.NotNull(cryptDelegates.DecryptString);
        Assert.NotNull(cryptDelegates.EncryptString);
    }

    /// <summary>
    /// Verifies that encrypting and decrypting a string returns the original text.
    /// This test only runs on Windows because DPAPI is a Windows-only API.
    /// </summary>
    [Fact]
    public void EncryptString_AndDecryptString_RoundTrip_ReturnsOriginalText()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        string salt = "TestSalt";
        string text = "SecretMessage";
        string? encryptedText = SecureStringHelper.EncryptString(salt, text);
        Assert.NotNull(encryptedText);
        Assert.NotEqual(text, encryptedText);

        string? decryptedText = SecureStringHelper.DecryptString(salt, encryptedText);
        Assert.Equal(text, decryptedText);
    }

    /// <summary>
    /// Verifies that ProtectedDataHelper.EncryptString returns null when given a null-equivalent SecureString.
    /// This test only runs on Windows because DPAPI is a Windows-only API.
    /// </summary>
    [Fact]
    public void ProtectedDataHelper_EncryptString_AndDecryptString_RoundTrip()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        string salt = "MySalt";
        SecureString secureString = "HelloWorld".ToSecureString();
        string? encryptedText = ProtectedDataHelper.EncryptString(salt, secureString);
        Assert.NotNull(encryptedText);

        SecureString decryptedSecureString = ProtectedDataHelper.DecryptString(salt, encryptedText);
        string? decryptedText = SecureStringHelper.ToInsecureString(decryptedSecureString);
        Assert.Equal("HelloWorld", decryptedText);
    }

    /// <summary>
    /// Verifies that ToSecureString2 creates a read-only SecureString.
    /// </summary>
    [Fact]
    public void ToSecureString2_CreatesReadOnlySecureString()
    {
        SecureString secureString = SecureStringHelper.ToSecureString2("Test");
        Assert.True(secureString.IsReadOnly());
    }

    /// <summary>
    /// Verifies that special characters survive the SecureString round trip.
    /// </summary>
    [Fact]
    public void ToSecureString_SpecialCharacters_PreservesContent()
    {
        string text = "P@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?";
        SecureString secureString = text.ToSecureString();
        string? result = SecureStringHelper.ToInsecureString(secureString);
        Assert.Equal(text, result);
    }
}