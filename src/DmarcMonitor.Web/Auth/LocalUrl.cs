namespace DmarcMonitor.Web.Auth;

/// <summary>
/// Where a redirect is allowed to send somebody: back into this site, or to
/// the front page. Never anywhere else.
/// </summary>
/// <remarks>
/// An open redirect on an internal tool is a phishing primitive: a link that
/// genuinely begins with this instance's own address, which an operator has
/// been told to trust, and ends up somewhere that asks them for their
/// Microsoft password.
///
/// Two endpoints take a return address - the local sign-in and the
/// organization switch - and both already refused a URL beginning "//",
/// which is protocol-relative and means another host. They did not refuse
/// "/\", which several browsers normalize to exactly the same thing:
///
///     /\evil.example  ->  //evil.example  ->  https://evil.example
///
/// No legitimate path inside this app begins with a backslash, so refusing it
/// costs nothing. This is the check ASP.NET's own IsLocalUrl makes, kept here
/// rather than reached for through an MVC helper this app does not otherwise
/// use.
/// </remarks>
public static class LocalUrl
{
    /// <summary>
    /// The given URL when it points inside this site, and "/" otherwise.
    /// </summary>
    public static string OrRoot(string? url)
    {
        if (string.IsNullOrEmpty(url)) { return "/"; }

        // Must be rooted, and the character after the slash decides it: a
        // second slash or a backslash both name another host.
        if (url[0] != '/') { return "/"; }
        if (url.Length == 1) { return url; }
        if (url[1] == '/' || url[1] == '\\') { return "/"; }

        // A control character in a Location header is how a response gets
        // split. Kestrel refuses to send one, so this is belt and braces,
        // but it is the sort of thing that stops being true elsewhere.
        foreach (var c in url)
        {
            if (char.IsControl(c)) { return "/"; }
        }

        return url;
    }
}
