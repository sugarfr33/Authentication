using System.Text.RegularExpressions;
using Auth.Contracts.Requests;

namespace Auth.Services.ClientApplications;

/// <summary>A request that passed validation, in canonical form (trimmed, origins normalized, lists distinct).</summary>
internal sealed record ValidClientApplication(
    string ClientId,
    string Name,
    string Audience,
    IReadOnlyList<string> AllowedOrigins,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris);

/// <summary>
/// Strict rules for client application settings. Errors name the field only, never echo the value.
/// <list type="bullet">
/// <item>Origins: absolute <c>scheme://host[:port]</c> only (no path, query, fragment, user info or wildcard), stored
/// normalized. Outside Development https only; in Development plain http only for loopback hosts.</item>
/// <item>Redirect and post-logout URIs: absolute, same scheme rule, no fragment, user info or wildcard; matched exactly
/// later (so no open redirect).</item>
/// <item>Audience: an absolute URI (for example <c>api://orders</c>), never the API's own default audience, so a token
/// for an application can never be used against this API (app-scoped roles cannot satisfy role:Admin).</item>
/// <item>Caps: 10 entries per list, 512 characters per URI, 256 per origin and audience.</item>
/// </list>
/// </summary>
internal sealed partial class ClientApplicationValidator(bool requireHttps, string defaultAudience)
{
    public const int MaxEntries = 10;
    public const int MaxUriLength = 512;
    public const int MaxOriginLength = 256;
    public const int MaxAudienceLength = 256;
    public const int MaxNameLength = 128;

    public (ValidClientApplication? Valid, IReadOnlyDictionary<string, string[]> Errors) Validate(ClientApplicationRequest? request)
    {
        Dictionary<string, string[]> errors = new(StringComparer.Ordinal);
        if (request is null)
        {
            errors["request"] = ["A request body is required."];
            return (null, errors);
        }

        string clientId = (request.ClientId ?? string.Empty).Trim();
        if (!ClientIdPattern().IsMatch(clientId))
        {
            errors["clientId"] = ["Client id must be 3 to 100 characters: lower-case letters, digits, '.', '_' or '-', starting with a letter or digit."];
        }

        string name = (request.Name ?? string.Empty).Trim();
        if (name.Length is 0 or > MaxNameLength || name.Any(char.IsControl))
        {
            errors["name"] = ["Name is required, at most 128 characters, without control characters."];
        }

        string audience = (request.Audience ?? string.Empty).Trim();
        if (!IsValidAudience(audience))
        {
            errors["audience"] = ["Audience must be an absolute URI of at most 256 characters, without fragment, wildcard or spaces, and must differ from this API's audience."];
        }

        List<string> origins = ValidateList(request.AllowedOrigins, "allowedOrigins", errors, NormalizeOrigin);
        List<string> redirects = ValidateList(request.RedirectUris, "redirectUris", errors, NormalizeRedirect);
        List<string> postLogout = ValidateList(request.PostLogoutRedirectUris, "postLogoutRedirectUris", errors, NormalizeRedirect);

        return errors.Count > 0
            ? (null, errors)
            : (new ValidClientApplication(clientId, name, audience, origins, redirects, postLogout), errors);
    }

    private static List<string> ValidateList(IReadOnlyList<string>? values, string field, Dictionary<string, string[]> errors, Func<string, string?> normalize)
    {
        List<string> result = [];
        if (values is null)
        {
            return result;
        }

        if (values.Count > MaxEntries)
        {
            errors[field] = ["At most 10 entries."];
            return result;
        }

        foreach (string value in values)
        {
            string? normalized = value is null ? null : normalize(value.Trim());
            if (normalized is null)
            {
                errors[field] = ["Every entry must be an exact https URL (http only for localhost in Development) without wildcard, fragment or user info."];
                return result;
            }

            if (!result.Contains(normalized, StringComparer.Ordinal))
            {
                result.Add(normalized);
            }
        }

        return result;
    }

    private string? NormalizeOrigin(string value) =>
        value.Length <= MaxOriginLength && !HasForbiddenCharacters(value)
        && OriginNormalizer.TryNormalize(value, out string origin) && IsAllowedScheme(origin)
            ? origin
            : null;

    private string? NormalizeRedirect(string value)
    {
        if (value.Length > MaxUriLength || HasForbiddenCharacters(value) || !Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
        {
            return null;
        }

        if ((uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            || uri.UserInfo.Length > 0
            || uri.Fragment.Length > 0
            || value.Contains('#', StringComparison.Ordinal)
            || !IsAllowedScheme(uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant()))
        {
            return null;
        }

        // Exact match later: keep the value as written (host lower-cased by Uri), never a prefix or pattern.
        return uri.AbsoluteUri;
    }

    private bool IsValidAudience(string audience) =>
        audience.Length is > 0 and <= MaxAudienceLength
        && !HasForbiddenCharacters(audience)
        && !audience.Contains('#', StringComparison.Ordinal)
        && Uri.TryCreate(audience, UriKind.Absolute, out _)
        && !string.Equals(audience.TrimEnd('/'), defaultAudience.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

    /// <summary>https always; plain http only for loopback, and only when https is not required (Development).</summary>
    private bool IsAllowedScheme(string normalizedOrigin) =>
        normalizedOrigin.StartsWith("https://", StringComparison.Ordinal)
        || (!requireHttps && OriginNormalizer.IsHttpsOrLoopback(normalizedOrigin));

    private static bool HasForbiddenCharacters(string value) =>
        value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c is '*' or '\\');

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{2,99}$", RegexOptions.CultureInvariant)]
    private static partial Regex ClientIdPattern();
}
