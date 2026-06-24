namespace SunamoSecurity._sunamo;

internal class ThrowEx
{
    internal static void Custom(string message)
    {
        Debugger.Break();
        throw new Exception(message);
    }
}
