using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Accounts;
using Auth.Services.Audit;
using Auth.Services.ClientApplications;
using Auth.Services.Common;
using Auth.Services.Security;
using Auth.Services.Tokens;

namespace Auth.Services.OAuth;

/// <summary>How /authorize answers.</summary>
public enum AuthorizeOutcomeKind
{
    /// <summary>Client or redirect URI not trusted (or the request malformed before that check): render an error on our
    /// own domain, NEVER redirect.</summary>
    ErrorPage,

    /// <summary>The redirect URI is trusted: redirect to <see cref="AuthorizeOutcome.Location"/> carrying an OAuth error.</summary>
    ErrorRedirect,

    /// <summary>No browser session: send the user to the login UI, then back to /authorize.</summary>
    LoginRequired,

    /// <summary>A code was issued: redirect to <see cref="AuthorizeOutcome.Location"/> (code and state in the query).</summary>
    CodeRedirect,
}

/// <param name="Error">The OAuth error code (ErrorPage, ErrorRedirect).</param>
/// <param name="Location">The full redirect target (ErrorRedirect, CodeRedirect). Contains the code: never log it.</param>
public sealed record AuthorizeOutcome(AuthorizeOutcomeKind Kind, string? Error = null, string? Location = null);

/// <summary>The /token answer: tokens, or an RFC 6749 error code (invalid_request, invalid_client, invalid_grant).</summary>
public sealed record TokenGrantResult(SignedIn? Session, string? Error)
{
    public bool IsSuccess => Session is not null;

    internal static TokenGrantResult Fail(string error) => new(null, error);
}

/// <summary>
/// Authorization Code with PKCE for registered public clients (T19, docs/authorization-code-pkce.md). First-party
/// applications only: a signed-in user is auto-approved. Codes are 256-bit, stored as SHA-256 hashes, valid 60 seconds,
/// redeemed at most once, and bound to the user, the client, the exact redirect URI and the S256 challenge.
/// </summary>
public interface IOAuthService
{
    /// <summary>Validates an authorization request in the safe order and issues a code for a signed-in user.</summary>
    Task<AuthorizeOutcome> AuthorizeAsync(AuthorizeRequest request, Guid? signedInUserId, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// grant_type=authorization_code. Any problem with the code, its bindings or the verifier gives invalid_grant, and
    /// the code is burned (never accepted again). A replay of a used code revokes the session it started.
    /// </summary>
    Task<TokenGrantResult> ExchangeAsync(TokenExchangeRequest request, RefreshContext context, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>grant_type=refresh_token for an application family.</summary>
    Task<TokenGrantResult> RefreshAsync(string? refreshToken, string? clientId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>True when <paramref name="origin"/> is one of the active <paramref name="clientId"/>'s own registered origins.</summary>
    Task<bool> IsClientOriginAsync(string? clientId, string? origin, CancellationToken cancellationToken);
}

internal sealed partial class OAuthService(
    IClientApplicationRepository applications,
    IUserRepository users,
    IAuthorizationCodeRepository codes,
    IRefreshTokenRepository refreshRows,
    IClientSessionService sessions,
    ITokenGenerator generator,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    ISessionLiveness liveness,
    IClock clock) : IOAuthService
{
    public static readonly TimeSpan CodeLifetime = TimeSpan.FromSeconds(60);

    public const string InvalidRequest = "invalid_request";
    public const string InvalidClient = "invalid_client";
    public const string InvalidGrant = "invalid_grant";
    public const string UnsupportedResponseType = "unsupported_response_type";
    public const string UnsupportedGrantType = "unsupported_grant_type";
    public const string AccessDenied = "access_denied";
    public const string InvalidRedirectUri = "invalid_redirect_uri";

    private const int MaxStateLength = 512;
    private const int MaxScopeLength = 256;

    public async Task<AuthorizeOutcome> AuthorizeAsync(AuthorizeRequest request, Guid? signedInUserId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(audit);

        // 1-2. Until the client and the redirect URI are trusted, nothing may redirect (no open redirect).
        ClientApplication? application = string.IsNullOrWhiteSpace(request.ClientId) || request.ClientId.Length > 100
            ? null
            : await applications.GetByClientIdAsync(request.ClientId, cancellationToken);
        if (application is not { IsActive: true })
        {
            return new AuthorizeOutcome(AuthorizeOutcomeKind.ErrorPage, InvalidClient);
        }

        string? redirectUri = request.RedirectUri;
        if (string.IsNullOrEmpty(redirectUri) || !RegisteredRedirects(application).Contains(redirectUri, StringComparer.Ordinal))
        {
            return new AuthorizeOutcome(AuthorizeOutcomeKind.ErrorPage, InvalidRedirectUri);
        }

        // 3. The redirect URI is trusted from here on: errors go back to it, with the state when it is acceptable.
        string? state = IsValidState(request.State) ? request.State : null;
        if (!string.Equals(request.ResponseType, "code", StringComparison.Ordinal))
        {
            return ErrorRedirect(redirectUri, UnsupportedResponseType, state);
        }

        if (state is null
            || !string.Equals(request.CodeChallengeMethod, "S256", StringComparison.Ordinal)
            || request.CodeChallenge is null || !PkceValue().IsMatch(request.CodeChallenge)
            || (request.Scope is not null && (request.Scope.Length > MaxScopeLength || !ScopeValue().IsMatch(request.Scope))))
        {
            return ErrorRedirect(redirectUri, InvalidRequest, state);
        }

        // 4. A browser session on our domain is required.
        if (signedInUserId is not Guid userId)
        {
            return new AuthorizeOutcome(AuthorizeOutcomeKind.LoginRequired);
        }

        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true })
        {
            return ErrorRedirect(redirectUri, AccessDenied, state);
        }

        // 5. First-party application: auto-approved. Issue the code.
        GeneratedToken code = generator.Generate();
        DateTime now = clock.UtcNow;
        await codes.AddAsync(
            new AuthorizationCode
            {
                CodeHash = code.Hash,
                UserId = user.Id,
                ClientApplicationId = application.Id,
                RedirectUri = redirectUri,
                CodeChallenge = request.CodeChallenge,
                CreatedUtc = now,
                ExpiresUtc = now + CodeLifetime,
            },
            cancellationToken);
        await audits.StageAsync(AuditEvents.AuthorizationCodeIssued(user.Id, application.Id), audit, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return new AuthorizeOutcome(AuthorizeOutcomeKind.CodeRedirect, null, AppendQuery(redirectUri, ("code", code.Value), ("state", state)));
    }

    public async Task<TokenGrantResult> ExchangeAsync(TokenExchangeRequest request, RefreshContext context, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(audit);
        if (string.IsNullOrEmpty(request.Code) || request.Code.Length > 256 || string.IsNullOrEmpty(request.ClientId)
            || string.IsNullOrEmpty(request.RedirectUri) || string.IsNullOrEmpty(request.CodeVerifier))
        {
            return TokenGrantResult.Fail(InvalidRequest);
        }

        AuthorizationCode? code = await codes.FindByHashAsync(generator.Hash(request.Code), cancellationToken);
        DateTime now = clock.UtcNow;
        if (code is null)
        {
            return await RejectAsync(null, null, "unknown_or_expired", InvalidGrant, audit, cancellationToken);
        }

        // Burn first: whatever happens next, this code is never accepted again.
        if (!await codes.TryMarkUsedAsync(code.Id, now, cancellationToken))
        {
            await RevokeReplayedAsync(code, cancellationToken);
            return await RejectAsync(code.UserId, code.ClientApplicationId, "replayed", InvalidGrant, audit, cancellationToken);
        }

        if (code.ExpiresUtc <= now)
        {
            return await RejectAsync(code.UserId, code.ClientApplicationId, "unknown_or_expired", InvalidGrant, audit, cancellationToken);
        }

        ClientApplication? application = await applications.GetByClientIdAsync(request.ClientId, cancellationToken);
        if (application is null || application.Id != code.ClientApplicationId)
        {
            return await RejectAsync(code.UserId, code.ClientApplicationId, "client_mismatch", InvalidGrant, audit, cancellationToken);
        }

        if (!application.IsActive)
        {
            return await RejectAsync(code.UserId, application.Id, "inactive_client", InvalidClient, audit, cancellationToken);
        }

        if (!string.Equals(code.RedirectUri, request.RedirectUri, StringComparison.Ordinal))
        {
            return await RejectAsync(code.UserId, application.Id, "redirect_mismatch", InvalidGrant, audit, cancellationToken);
        }

        if (!VerifierMatches(request.CodeVerifier, code.CodeChallenge))
        {
            return await RejectAsync(code.UserId, application.Id, "pkce_mismatch", InvalidGrant, audit, cancellationToken);
        }

        // Verified exchange for this user and this client: the only call site of StartAsync (T18 criterion).
        Result<SignedIn> started = await sessions.StartAsync(code.UserId, application.ClientId, context, cancellationToken);
        if (started.Value is not SignedIn session)
        {
            return started.Error == AuthError.InvalidClient
                ? await RejectAsync(code.UserId, application.Id, "inactive_client", InvalidClient, audit, cancellationToken)
                : await RejectAsync(code.UserId, application.Id, "inactive_user", InvalidGrant, audit, cancellationToken);
        }

        await codes.SetFamilyAsync(code.Id, session.RefreshToken.FamilyId, cancellationToken);
        await audits.TryWriteAsync(AuditEvents.AuthorizationCodeRedeemed(code.UserId, application.Id, session.RefreshToken.FamilyId), audit, cancellationToken);
        return new TokenGrantResult(session, null);
    }

    public async Task<TokenGrantResult> RefreshAsync(string? refreshToken, string? clientId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(clientId))
        {
            return TokenGrantResult.Fail(InvalidRequest);
        }

        Result<SignedIn> refreshed = await sessions.RefreshAsync(refreshToken, clientId, context, audit, cancellationToken);
        return refreshed.Value is SignedIn session
            ? new TokenGrantResult(session, null)
            : TokenGrantResult.Fail(refreshed.Error == AuthError.InvalidClient ? InvalidClient : InvalidGrant);
    }

    public async Task<bool> IsClientOriginAsync(string? clientId, string? origin, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(clientId) || !OriginNormalizer.TryNormalize(origin, out string normalized))
        {
            return false;
        }

        ClientApplication? application = await applications.GetByClientIdAsync(clientId, cancellationToken);
        return application is { IsActive: true } && ReadList(application.AllowedOrigin).Contains(normalized, StringComparer.Ordinal);
    }

    /// <summary>BASE64URL(SHA-256(ASCII(verifier))) compared to the stored challenge in constant time.</summary>
    internal static bool VerifierMatches(string verifier, string challenge)
    {
        if (!PkceValue().IsMatch(verifier))
        {
            return false;
        }

        string computed = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(computed), Encoding.ASCII.GetBytes(challenge));
    }

    internal static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>RFC 6819 4.4.1.1: a used code presented again revokes the session it started.</summary>
    private async Task RevokeReplayedAsync(AuthorizationCode code, CancellationToken cancellationToken)
    {
        AuthorizationCode? current = await codes.FindByHashAsync(code.CodeHash, cancellationToken);
        if (current?.FamilyId is Guid family)
        {
            await refreshRows.RevokeFamilyAsync(family, RefreshTokenRevokedReason.Reuse, clock.UtcNow, cancellationToken);
            liveness.Invalidate(family);
        }
    }

    private async Task<TokenGrantResult> RejectAsync(Guid? userId, Guid? applicationId, string reason, string error, AuditContext audit, CancellationToken cancellationToken)
    {
        await audits.TryWriteAsync(AuditEvents.AuthorizationCodeRejected(userId, applicationId, reason), audit, cancellationToken);
        return TokenGrantResult.Fail(error);
    }

    private static AuthorizeOutcome ErrorRedirect(string redirectUri, string error, string? state) =>
        new(AuthorizeOutcomeKind.ErrorRedirect, error, state is null ? AppendQuery(redirectUri, ("error", error)) : AppendQuery(redirectUri, ("error", error), ("state", state)));

    private static string AppendQuery(string uri, params (string Name, string Value)[] parameters)
    {
        StringBuilder target = new(uri);
        char separator = uri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        foreach ((string name, string value) in parameters)
        {
            target.Append(separator).Append(name).Append('=').Append(Uri.EscapeDataString(value));
            separator = '&';
        }

        return target.ToString();
    }

    private static bool IsValidState(string? state) =>
        state is { Length: > 0 and <= MaxStateLength } && state.All(c => c is >= ' ' and <= '~');

    private static string[] RegisteredRedirects(ClientApplication application) => ReadList(application.RedirectUri);

    private static string[] ReadList(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<string[]>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>RFC 7636: 43 to 128 unreserved characters (code_challenge and code_verifier).</summary>
    [GeneratedRegex("^[A-Za-z0-9._~-]{43,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex PkceValue();

    [GeneratedRegex("^[a-z0-9_.:]+( [a-z0-9_.:]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex ScopeValue();
}
