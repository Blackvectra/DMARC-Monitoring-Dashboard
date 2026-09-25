using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace DmarcMonitor.Web.Auth;

/// <summary>
/// Running behind something that terminates TLS.
///
/// Every way of deploying this puts a reverse proxy in front - Caddy, nginx,
/// IIS, an AWS load balancer - because that is what holds the certificate. The
/// app then sees every request as plain HTTP arriving from 127.0.0.1, which
/// breaks two things badly enough to stop a deployment dead:
///
///   Sign-in. Microsoft.Identity.Web builds the redirect_uri from the scheme
///   and host it can see. Behind a proxy that is http://, the app registration
///   says https://, Entra refuses the mismatch, and nobody can sign in. The
///   symptom is an error page from Microsoft rather than anything this app
///   logs, which sends people looking in the wrong place for a long time.
///
///   The local-mode guard. It refuses to serve anybody but loopback, and
///   behind a proxy EVERY request looks like loopback. A trial instance put
///   behind a proxy would serve every customer's mail data to the internet
///   while believing it was protected. That is the failure this whole file
///   exists to prevent, so see UseLocalModeGuard for the second half of it.
///
/// Turned on explicitly rather than detected, because trusting forwarded
/// headers from a caller that is not a proxy lets anyone claim any address
/// and any scheme they like.
/// </summary>
public static class ProxySetup
{
    /// <summary>True when the deployment has declared it sits behind a proxy.</summary>
    public static bool IsBehindProxy(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return configuration.GetValue("Proxy:Behind", false);
    }

    public static void AddProxySupport(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (!IsBehindProxy(builder.Configuration)) { return; }

        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

            // The defaults trust loopback only, which is right for a proxy on
            // the same machine and wrong for a load balancer on another. Both
            // lists are cleared first because whatever is configured is meant
            // to be the whole answer.
            options.KnownProxies.Clear();
            options.KnownIPNetworks.Clear();

            var proxies = builder.Configuration.GetSection("Proxy:KnownProxies").Get<string[]>() ?? [];
            foreach (var proxy in proxies)
            {
                if (IPAddress.TryParse(proxy.Trim(), out var address)) { options.KnownProxies.Add(address); }
            }

            var networks = builder.Configuration.GetSection("Proxy:KnownNetworks").Get<string[]>() ?? [];
            foreach (var network in networks)
            {
                if (TryNetwork(network, out var known)) { options.KnownIPNetworks.Add(known); }
            }

            // Nothing named means the commonest case by far: a proxy on this
            // machine, talking to the app over loopback.
            if (options.KnownProxies.Count == 0 && options.KnownIPNetworks.Count == 0)
            {
                options.KnownProxies.Add(IPAddress.Loopback);
                options.KnownProxies.Add(IPAddress.IPv6Loopback);
            }
        });
    }

    /// <summary>Must run before anything that reads the scheme or the caller's address.</summary>
    public static void UseProxyHeaders(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (!IsBehindProxy(app.Configuration)) { return; }

        app.UseForwardedHeaders();
    }

    /// <summary>
    /// Whether this process should redirect HTTP to HTTPS itself.
    /// </summary>
    /// <remarks>
    /// Not behind a proxy: yes. Behind one: no, the proxy already did it, and
    /// redirecting again on a request the proxy forwarded as HTTP is how a
    /// deployment ends up in a loop that looks like the app is down.
    ///
    /// And never in local trial mode, which is the third case and was missing.
    /// That copy serves loopback over plain HTTP by design and has no
    /// certificate to redirect to, so registering the middleware achieved
    /// nothing except a warning on every single start:
    ///
    ///     warn: Microsoft.AspNetCore.HttpsPolicy.HttpsRedirectionMiddleware[3]
    ///           Failed to determine the https port for redirect.
    ///
    /// which is the last line somebody sees before deciding whether the thing
    /// they just downloaded works. It also registered HSTS on an application
    /// answering http://localhost - harmless, because browsers ignore
    /// Strict-Transport-Security on a plain-HTTP response, but it is a header
    /// that means something and it was being sent by mistake.
    /// </remarks>
    /// <remarks>
    /// An install that has Entra configured, or local mode explicitly allowed
    /// remotely, is a deployment somebody set up, and gets the redirect it had
    /// before. <see cref="AuthSetup.IsLocalTrial"/> asks exactly the pair of
    /// questions that decides whether the loopback guard goes in front of
    /// every request, and this used to ask them separately here - two copies
    /// of one definition that a third caller then had to choose between.
    /// </remarks>
    public static bool ShouldRedirectToHttps(IConfiguration configuration) =>
        !IsBehindProxy(configuration) && !AuthSetup.IsLocalTrial(configuration);

    private static bool TryNetwork(string cidr, out System.Net.IPNetwork network)
    {
        network = default;

        var parts = cidr.Split('/', 2);
        if (parts.Length != 2
            || !IPAddress.TryParse(parts[0].Trim(), out var address)
            || !int.TryParse(parts[1].Trim(), out var prefix))
        {
            return false;
        }

        var bits = address.GetAddressBytes();
        if (prefix < 0 || prefix > bits.Length * 8) { return false; }

        // System.Net.IPNetwork refuses a base address with host bits set -
        // "10.0.0.1/8" - where the ASP.NET type it replaces took it. Masked
        // here, so a configuration that worked on .NET 8 keeps working.
        for (var i = 0; i < bits.Length; i++)
        {
            var keep = Math.Clamp(prefix - (i * 8), 0, 8);
            bits[i] &= (byte)(0xFF << (8 - keep));
        }

        network = new System.Net.IPNetwork(new IPAddress(bits), prefix);
        return true;
    }
}
