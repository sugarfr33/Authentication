using System.Net;

namespace Auth.Api.Security;

/// <summary>
/// Conservative rules for the shared-domain cookie Domain (no public-suffix list is available without a package):
/// <list type="bullet">
/// <item>a bare lower-case DNS name: no scheme, port, path, leading or trailing dot, no IP address;</item>
/// <item>at least two labels of 1 to 63 characters (a-z, 0-9, hyphen inside), at most 253 characters, a non-numeric
/// top-level label;</item>
/// <item>not a known two-label public suffix shape (<c>co.uk</c>, <c>com.au</c>, ...: a common second-level label
/// under a two-letter country code);</item>
/// <item>not a known shared-hosting (private) suffix such as <c>github.io</c> or <c>herokuapp.com</c>, nor a name
/// directly under one: every tenant of such a provider could read and toss the cookies;</item>
/// <item>the auth host (from Auth:Issuer, which must be https; compared in its punycode form, <c>Uri.IdnHost</c>) is
/// the Domain itself or a subdomain of it.</item>
/// </list>
/// A Domain that passes can still be a suffix these lists do not know: only use a domain you own, and only for hosts
/// you fully trust (docs/single-logout-and-shared-domain.md).
/// </summary>
internal static class CookieDomainRules
{
    private static readonly HashSet<string> SecondLevelSuffixLabels = new(StringComparer.Ordinal)
    {
        "ac", "co", "com", "edu", "gen", "go", "gob", "gov", "gv", "id", "info", "lg", "ltd", "me", "mil", "ne", "net",
        "nhs", "nic", "nom", "or", "org", "plc", "sch", "web", "gouv", "asso",
    };

    /// <summary>Shared-hosting suffixes where unrelated tenants get sibling subdomains (a small built-in deny list).</summary>
    private static readonly string[] PrivateSuffixes =
    [
        "herokuapp.com", "azurewebsites.net", "cloudapp.net", "azurestaticapps.net", "github.io", "gitlab.io",
        "vercel.app", "now.sh", "netlify.app", "netlify.com", "pages.dev", "workers.dev", "appspot.com", "web.app",
        "firebaseapp.com", "blogspot.com", "amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "onrender.com",
        "fly.dev", "railway.app", "glitch.me", "repl.co", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
        "readthedocs.io", "surge.sh", "wordpress.com", "wixsite.com", "squarespace.com", "shopify.com",
    ];

    public static bool IsAllowed(string domain, string? issuer)
    {
        if (domain.Length is 0 or > 253
            || !string.Equals(domain, domain.ToLowerInvariant(), StringComparison.Ordinal)
            || domain.StartsWith('.') || domain.EndsWith('.')
            || IPAddress.TryParse(domain, out _))
        {
            return false;
        }

        string[] labels = domain.Split('.');
        if (labels.Length < 2 || !labels.All(IsLabel) || labels[^1].All(char.IsAsciiDigit))
        {
            return false;
        }

        if (labels.Length == 2 && labels[1].Length == 2 && SecondLevelSuffixLabels.Contains(labels[0]))
        {
            return false;
        }

        // The suffix itself, or one tenant's name directly under it (a tenant cannot own the parent).
        if (PrivateSuffixes.Any(suffix => domain == suffix || domain.EndsWith("." + suffix, StringComparison.Ordinal)))
        {
            return false;
        }

        return Uri.TryCreate(issuer, UriKind.Absolute, out Uri? auth)
            && auth.Scheme == Uri.UriSchemeHttps
            && (auth.IdnHost == domain || auth.IdnHost.EndsWith("." + domain, StringComparison.Ordinal));
    }

    private static bool IsLabel(string label) =>
        label.Length is >= 1 and <= 63
        && label.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-')
        && !label.StartsWith('-') && !label.EndsWith('-');
}
