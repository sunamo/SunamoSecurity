namespace SunamoSecurity._sunamo;

internal class ThrowEx
{
    internal static void Custom(string ex)
    {
        Debugger.Break();
        throw new Exception(ex);
    }
}