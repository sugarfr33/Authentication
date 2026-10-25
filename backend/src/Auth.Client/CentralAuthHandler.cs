using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Auth.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

namespace Auth.Client;

/// <summary>
/// Optional live-session check (docs/t22-client-extension.md section 7). When the host registers an implementation, it
/// is called after a token validated; false, or an exception (its own timeout included), means 401 (fail closed).
/// Without one, a token stays valid until it expires.
/// </summary>
public interface ICentralAuthSessionValidator
{
    /// <param name="userId">The token's <c>sub</c>.</param>
    /// <param name="sessionId">The token's <c>sid</c> (refresh family), when it has one.</param>
    /// <param name="principal">The validated principal.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    Task<bool> IsLiveAsync(Guid userId, Guid? sessionId, ClaimsPrincipal principal, CancellationToken cancellationToken);
}

/// <summary>
/// Validates a central-auth access token (Bearer header, or the access cookie in cookie mode) against the cached JWKS
/// with the server's rules: signature by kid with exactly that key's algorithm (ES256 or RS256), <c>typ</c>
/// <see cref="AuthTokenTypes.AccessToken"/>, issuer, audience, lifetime, then the <c>client_id</c> rule. Every failure is
/// a bare 401 with <c>WWW-Authenticate: Bearer error="invalid_token"</c>; the reason is logged at Debug, never the token.
/// Every setting comes from the scheme's options snapshot held by its JWKS cache (a change needs a restart).
/// </summary>
internal sealed partial class CentralAuthHandler(
    IOptionsMonitor<CentralAuthOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    JwksCacheRegistry caches,
    TimeProvider time) : AuthenticationHandler<CentralAuthOptions>(options, logger, encoder)
{
    /// <summary>A real access token is a few hundred bytes; refuse to parse anything absurdly large.</summary>
    public const int MaxTokenLength = 8192;

    private const string Invalid = "Invalid access token.";

    private static readonly JsonWebTokenHandler TokenHandler = new() { MapInboundClaims = false };

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        JwksCache cache = caches.For(Scheme.Name, Options);
        CentralAuthOptions settings = cache.Options;
        (string? token, bool fromCookie, string? refusal) = ReadToken(settings);
        if (refusal is not null)
        {
            return Refuse(refusal);
        }

        if (token is null)
        {
            return AuthenticateResult.NoResult();
        }

        if (fromCookie && CookieRequestRefusal(settings) is string csrf)
        {
            return Refuse(csrf);
        }

        if (token.Length > MaxTokenLength)
        {
            return Refuse("too_long");
        }

        JsonWebToken unverified;
        try
        {
            unverified = new JsonWebToken(token);
        }
        catch (ArgumentException)
        {
            return Refuse("malformed");
        }

        if (unverified.IsEncrypted)
        {
            return Refuse("encrypted");
        }

        // No critical header extension is understood here, so any "crit" makes the token unacceptable (RFC 7515 4.1.11).
        if (unverified.TryGetHeaderValue("crit", out object? _))
        {
            return Refuse("crit");
        }

        JwksKeys keys;
        try
        {
            keys = await cache.GetKeysAsync(unverified.Kid, Context.RequestAborted).ConfigureAwait(false);
        }
        catch (JwksUnavailableException)
        {
            // Fail closed: without published keys nothing can be trusted.
            LogKeysUnavailable(Logger);
            return AuthenticateResult.Fail(Invalid);
        }

        TokenValidationResult result = await TokenHandler.ValidateTokenAsync(token, Parameters(settings, keys)).ConfigureAwait(false);
        if (!result.IsValid || result.ClaimsIdentity is not ClaimsIdentity identity)
        {
            return Refuse(result.Exception?.GetType().Name ?? "invalid");
        }

        List<Claim> clientIds = [.. identity.FindAll(AuthClaimTypes.ClientId)];
        if (clientIds.Count > 1 || !string.Equals(clientIds.SingleOrDefault()?.Value, settings.ClientId, StringComparison.Ordinal))
        {
            return Refuse(settings.ClientId is null ? "client_token_at_browser_api" : "client_id_mismatch");
        }

        if (!Guid.TryParse(identity.FindFirst(AuthClaimTypes.Subject)?.Value, out Guid userId))
        {
            return Refuse("no_subject");
        }

        ClaimsPrincipal principal = new(identity);
        if (Context.RequestServices.GetService<ICentralAuthSessionValidator>() is ICentralAuthSessionValidator sessions)
        {
            Guid? sessionId = Guid.TryParse(identity.FindFirst(AuthClaimTypes.SessionId)?.Value, out Guid sid) ? sid : null;
            try
            {
                if (!await sessions.IsLiveAsync(userId, sessionId, principal, Context.RequestAborted).ConfigureAwait(false))
                {
                    return Refuse("session_ended");
                }
            }
            catch (Exception ex) when (!(ex is OperationCanceledException && Context.RequestAborted.IsCancellationRequested))
            {
                // Includes the hook's own timeout (OperationCanceledException while the request is still alive).
                LogSessionCheckFailed(Logger, ex.GetType().Name);
                return AuthenticateResult.Fail(Invalid);
            }
        }

        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    /// <summary>401 with RFC 6750's <c>invalid_token</c> after a failed attempt (plain <c>Bearer</c> when no token came); no body.</summary>
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        AuthenticateResult result = await HandleAuthenticateOnceSafeAsync().ConfigureAwait(false);
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.Append(
            HeaderNames.WWWAuthenticate,
            result.Failure is null ? "Bearer" : "Bearer error=\"" + OAuthErrorCodes.InvalidToken + "\"");
    }

    private (string? Token, bool FromCookie, string? Refusal) ReadToken(CentralAuthOptions settings)
    {
        if (settings.AcceptBearer && Request.Headers.Authorization is { Count: > 0 } authorization)
        {
            if (authorization.Count > 1)
            {
                return (null, false, "several_authorization_headers");
            }

            string value = authorization.ToString();
            if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                string token = value["Bearer ".Length..].Trim();
                return token.Length > 0 ? (token, false, null) : (null, false, "empty_bearer");
            }

            // Another scheme (Basic, ...) is not ours; the cookie is not consulted either.
            return (null, false, null);
        }

        return settings.AcceptCookie && Request.Cookies.TryGetValue(settings.CookieName, out string? cookie) && !string.IsNullOrEmpty(cookie)
            ? (cookie, true, null)
            : (null, false, null);
    }

    /// <summary>
    /// CSRF rules for cookie-authenticated unsafe requests (docs section 6); null when the request passes. Sec-Fetch-Site
    /// must not be cross-site, Origin must be present and in AllowedOrigins, and the X-XSRF-TOKEN header must equal the
    /// XSRF-TOKEN cookie. Safe methods pass.
    /// </summary>
    private string? CookieRequestRefusal(CentralAuthOptions settings)
    {
        if (HttpMethods.IsGet(Request.Method) || HttpMethods.IsHead(Request.Method) || HttpMethods.IsOptions(Request.Method) || HttpMethods.IsTrace(Request.Method))
        {
            return null;
        }

        if (string.Equals(Request.Headers["Sec-Fetch-Site"].ToString(), "cross-site", StringComparison.OrdinalIgnoreCase))
        {
            return "cross_site";
        }

        string? origin = OriginRules.Normalize(Request.Headers.Origin.ToString(), settings.RequireHttpsMetadata);
        if (origin is null || !settings.AllowedOrigins.Any(o => string.Equals(OriginRules.Normalize(o, settings.RequireHttpsMetadata), origin, StringComparison.Ordinal)))
        {
            return "origin";
        }

        string header = Request.Headers[AuthCookieNames.XsrfHeader].ToString();
        return header.Length > 0
            && Request.Cookies.TryGetValue(AuthCookieNames.Xsrf, out string? cookie)
            && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(header), Encoding.UTF8.GetBytes(cookie ?? string.Empty))
            ? null
            : "xsrf";
    }

    private TokenValidationParameters Parameters(CentralAuthOptions settings, JwksKeys keys) => new()
    {
        ValidateIssuer = true,
        ValidIssuer = settings.Issuer,
        ValidateAudience = true,
        ValidAudience = settings.Audience,
        ValidateLifetime = true,
        RequireExpirationTime = true,
        ClockSkew = settings.ClockSkew,
        LifetimeValidator = (notBefore, expires, _, _) => LifetimeIsValid(settings.ClockSkew, notBefore, expires),
        RequireSignedTokens = true,
        ValidateIssuerSigningKey = true,
        ValidTypes = [AuthTokenTypes.AccessToken],

        // Central auth signs with ES256 by default and can publish RS256 keys (SigningKeyAlgorithm); nothing else.
        ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.RsaSha256],

        // The key must match the token's kid AND the token's alg must be that key's own algorithm.
        TryAllIssuerSigningKeys = false,
        IssuerSigningKeyResolver = (_, securityToken, kid, _) => keys.Resolve(kid, (securityToken as JsonWebToken)?.Alg),
        NameClaimType = AuthClaimTypes.Name,
        RoleClaimType = AuthClaimTypes.Role,
        AuthenticationType = Scheme.Name,
    };

    /// <summary>exp is required; both bounds against the injected clock (the JWKS cache uses the same one), with the skew.</summary>
    private bool LifetimeIsValid(TimeSpan skew, DateTime? notBefore, DateTime? expires)
    {
        DateTime now = time.GetUtcNow().UtcDateTime;
        return expires is DateTime exp
            && now - skew < exp.ToUniversalTime()
            && (notBefore is not DateTime nbf || (nbf.ToUniversalTime() <= exp.ToUniversalTime() && nbf.ToUniversalTime() <= now + skew));
    }

    private AuthenticateResult Refuse(string reason)
    {
        LogRefused(Logger, reason);
        return AuthenticateResult.Fail(Invalid);
    }

    [LoggerMessage(EventId = 7211, Level = LogLevel.Debug, Message = "Central-auth token refused ({Reason})")]
    private static partial void LogRefused(ILogger logger, string reason);

    [LoggerMessage(EventId = 7212, Level = LogLevel.Error, Message = "Central-auth signing keys are unavailable; refusing every token until the JWKS can be loaded")]
    private static partial void LogKeysUnavailable(ILogger logger);

    [LoggerMessage(EventId = 7213, Level = LogLevel.Warning, Message = "The central-auth session check failed ({ExceptionType}); refusing the token")]
    private static partial void LogSessionCheckFailed(ILogger logger, string exceptionType);
}
