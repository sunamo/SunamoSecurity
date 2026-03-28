namespace SunamoSecurity._sunamo;

/// <summary>
/// Internal helper for throwing exceptions with debugger breakpoints.
/// </summary>
internal class ThrowEx
{
    /// <summary>
    /// Breaks the debugger and throws an exception with the specified message.
    /// </summary>
    /// <param name="message">The exception message to throw.</param>
    internal static void Custom(string message)
    {
        Debugger.Break();
        throw new Exception(message);
    }
}