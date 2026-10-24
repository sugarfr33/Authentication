using Auth.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Auth.IntegrationTests.Api;

/// <summary>A parsed Set-Cookie header.</summary>
internal sealed record SetCookie(string Name, string Value, IReadOnlyDictionary<string, string> Attributes)
{
    public bool HasFlag(string flag) => Attributes.ContainsKey(flag.ToLowerInvariant());

    public string? this[string attribute] => Attributes.TryGetValue(attribute.ToLowerInvariant(), out string? value) ? value : null;

    public bool IsExpired =>
        this["max-age"] == "0" || (this["expires"] is string expires && DateTimeOffset.TryParse(expires, System.Globalization.CultureInfo.InvariantCulture, out DateTimeOffset at) && at < DateTimeOffset.UtcNow);

    public static IReadOnlyList<SetCookie> From(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? values) ? values.Select(Parse).ToList() : [];

    public static SetCookie Parse(string header)
    {
        string[] parts = header.Split(';', StringSplitOptions.TrimEntries);
        int eq = parts[0].IndexOf('=', StringComparison.Ordinal);
        Dictionary<string, string> attributes = new(StringComparer.Ordinal);
        foreach (string part in parts.Skip(1).Where(p => p.Length > 0))
        {
            int split = part.IndexOf('=', StringComparison.Ordinal);
            attributes[(split < 0 ? part : part[..split]).ToLowerInvariant()] = split < 0 ? string.Empty : part[(split + 1)..];
        }

        return new SetCookie(parts[0][..eq], parts[0][(eq + 1)..], attributes);
    }
}

/// <summary>
/// A minimal browser over the test server: keeps cookies with their paths, sends Origin and the X-XSRF-TOKEN header
/// like the SPA will, and records every response so tests can scan bodies and headers.
/// </summary>
internal sealed class Browser(WebApplicationFactory<Program> factory, string origin = ApiFixture.AppOrigin) : IDisposable
{
    private readonly HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://" + ApiFixture.Host),
        AllowAutoRedirect = false,
        HandleCookies = false,
    });

    private readonly Dictionary<string, (string Value, string Path)> jar = new(StringComparer.Ordinal);

    public List<(HttpResponseMessage Response, string Body)> History { get; } = [];

    public string? Xsrf => jar.TryGetValue(AuthCookieNames.Xsrf, out (string Value, string Path) cookie) ? cookie.Value : null;

    public bool HasCookie(string name) => jar.ContainsKey(name);

    public string CookieValue(string name) => jar[name].Value;

    /// <summary>Drops a cookie, as a browser does when its Max-Age runs out.</summary>
    public void Forget(string name) => jar.Remove(name);

    /// <summary>Puts a cookie into the jar directly (for example a forged or backdated token).</summary>
    public void Plant(string name, string value, string path = "/") => jar[name] = (value, path);

    public Task<HttpResponseMessage> GetAsync(string path) => SendAsync(HttpMethod.Get, path, sendOrigin: false, sendXsrf: false);

    public async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        bool sendOrigin = true,
        bool sendXsrf = true,
        string? originOverride = null,
        string? referer = null,
        string? xsrfOverride = null,
        Action<HttpRequestMessage>? configure = null)
    {
        using HttpRequestMessage request = new(method, path);
        if (sendOrigin)
        {
            request.Headers.TryAddWithoutValidation("Origin", originOverride ?? origin);
        }

        if (referer is not null)
        {
            request.Headers.Referrer = new Uri(referer);
        }

        string? xsrf = xsrfOverride ?? Xsrf;
        if (sendXsrf && xsrf is not null)
        {
            request.Headers.TryAddWithoutValidation(AuthCookieNames.XsrfHeader, xsrf);
        }

        string cookies = string.Join("; ", jar.Where(c => path.StartsWith(c.Value.Path, StringComparison.Ordinal)).Select(c => c.Key + "=" + c.Value.Value));
        if (cookies.Length > 0)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookies);
        }

        configure?.Invoke(request);
        HttpResponseMessage response = await client.SendAsync(request);
        foreach (SetCookie cookie in SetCookie.From(response))
        {
            if (cookie.IsExpired || cookie.Value.Length == 0)
            {
                jar.Remove(cookie.Name);
            }
            else
            {
                jar[cookie.Name] = (cookie.Value, cookie["path"] ?? "/");
            }
        }

        History.Add((response, await response.Content.ReadAsStringAsync()));
        return response;
    }

    /// <summary>GET to obtain the antiforgery pair, then the state-changing session call (the T13 login stand-in).</summary>
    public async Task<HttpResponseMessage> SignInAsync()
    {
        await GetAsync(TestEndpoints.Prefix + "/ping");
        HttpResponseMessage session = await SendAsync(HttpMethod.Post, TestEndpoints.Prefix + "/session");
        await GetAsync(TestEndpoints.Prefix + "/ping");
        return session;
    }

    public void Dispose() => client.Dispose();
}
