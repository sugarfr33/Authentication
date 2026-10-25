using System.Data;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
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
/// applications only: a signed-in user is auto-approved. Codes are 256-bit, stored as SHA-256 hashes, valid
/// OAuth:CodeLifetime (60 s), redeemed at most once, and bound to the user, the client, the exact redirect URI and the
/// S256 challenge. HTTP concerns (the caller's Origin, rate limits) stay in the endpoint.
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
}

/// <summary>
/// Client authentication at the token endpoint. Seam for confidential clients (a later task); registered public clients
/// have no secret: PKCE plus the client's own Origin is their proof.
/// </summary>
internal interface IClientAuthenticator
{
    Task<bool> AuthenticateAsync(ClientApplication application, TokenExchangeRequest request, CancellationToken cancellationToken);
}

internal sealed class PublicClientAuthenticator : IClientAuthenticator
{
    public Task<bool> AuthenticateAsync(ClientApplication application, TokenExchangeRequest request, CancellationToken cancellationToken) => Task.FromResult(true);
}

/// <summary>Whether the user agreed to sign in to the application. Seam for a consent screen (third-party clients, later).</summary>
internal interface IConsentDecision
{
    Task<bool> IsApprovedAsync(Guid userId, ClientApplicationView application, string? scope, CancellationToken cancellationToken);
}

/// <summary>Every registered application is first-party today: a signed-in user is approved without asking.</summary>
internal sealed class FirstPartyAutoApproval : IConsentDecision
{
    public Task<bool> IsApprovedAsync(Guid userId, ClientApplicationView application, string? scope, CancellationToken cancellationToken) => Task.FromResult(true);
}

internal sealed partial class OAuthService(
    IClientApplicationOriginProvider clients,
    IClientApplicationRepository applications,
    IUserRepository users,
    IAuthorizationCodeRepository codes,
    IRefreshTokenRepository refreshRows,
    IClientSessionService sessions,
    IClientAuthenticator clientAuthenticator,
    IConsentDecision consent,
    ITokenGenerator generator,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    ISessionLiveness liveness,
    OAuthOptions options,
    IClock clock) : IOAuthService
{
    private const int MaxStateLength = 512;
    private const int MaxScopeLength = 256;

    private static readonly Meter OAuthMeter = new("Auth.OAuth");

    /// <summary>
    /// Codes that match no row (garbage or long purged) are counted here, not audited: they carry no user or client and
    /// cost the caller nothing, so an audit row each would let anyone grow the audit log (T19 audit L2).
    /// </summary>
    private static readonly Counter<long> UnknownCodes = OAuthMeter.CreateCounter<long>("auth.oauth.unknown_codes");

    public async Task<AuthorizeOutcome> AuthorizeAsync(AuthorizeRequest request, Guid? signedInUserId, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(audit);

        // 1-2. Until the client and the redirect URI are trusted, nothing may redirect (no open redirect).
        ClientApplicationView? application = await clients.FindActiveAsync(request.ClientId, cancellationToken);
        if (application is null)
        {
            return new AuthorizeOutcome(AuthorizeOutcomeKind.ErrorPage, OAuthErrorCodes.InvalidClient);
        }

        string? redirectUri = request.RedirectUri;
        if (string.IsNullOrEmpty(redirectUri) || !application.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            return new AuthorizeOutcome(AuthorizeOutcomeKind.ErrorPage, OAuthErrorCodes.InvalidRedirectUri);
        }

        // 3. The redirect URI is trusted from here on: errors go back to it, with the state when it is acceptable.
        string? state = IsValidState(request.State) ? request.State : null;
        if (!string.Equals(request.ResponseType, "code", StringComparison.Ordinal))
        {
            return ErrorRedirect(redirectUri, OAuthErrorCodes.UnsupportedResponseType, state);
        }

        if (state is null
            || !string.Equals(request.CodeChallengeMethod, "S256", StringComparison.Ordinal)
            || request.CodeChallenge is null || !PkceValue().IsMatch(request.CodeChallenge)
            || (request.Scope is not null && (request.Scope.Length > MaxScopeLength || !ScopeValue().IsMatch(request.Scope))))
        {
            return ErrorRedirect(redirectUri, OAuthErrorCodes.InvalidRequest, state);
        }

        // 4. A browser session on our domain is required.
        if (signedInUserId is not Guid userId)
        {
            return new AuthorizeOutcome(AuthorizeOutcomeKind.LoginRequired);
        }

        User? user = await users.GetByIdAsync(userId, cancellationToken);
        if (user is not { IsActive: true, EmailVerified: true })
        {
            return ErrorRedirect(redirectUri, OAuthErrorCodes.AccessDenied, state);
        }

        // 5. Consent (first-party applications: auto-approved), then issue the code.
        if (!await consent.IsApprovedAsync(user.Id, application, request.Scope, cancellationToken))
        {
            return ErrorRedirect(redirectUri, OAuthErrorCodes.AccessDenied, state);
        }

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
                ExpiresUtc = now + options.CodeLifetime,
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
            return TokenGrantResult.Fail(OAuthErrorCodes.InvalidRequest);
        }

        AuthorizationCode? code = await codes.FindByHashAsync(generator.Hash(request.Code), cancellationToken);
        if (code is null)
        {
            UnknownCodes.Add(1);
            return TokenGrantResult.Fail(OAuthErrorCodes.InvalidGrant);
        }

        // One transaction: the conditional UPDATE that burns the code also records the family the redemption will start
        // (chosen here), and that family is created before the commit. A concurrent replay blocks on the code row until
        // the commit, then finds the code used AND its family existing, and revokes it: no window. A failed check commits
        // the burn alone; an unexpected exception rolls everything back (the code stays redeemable until it expires).
        Guid familyId = Guid.NewGuid();
        DateTime now = clock.UtcNow;
        Rejection? rejection;
        SignedIn? session = null;
        await using (IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken))
        {
            if (!await codes.TryRedeemAsync(code.Id, now, familyId, cancellationToken))
            {
                rejection = new Rejection("replayed", OAuthErrorCodes.InvalidGrant, code.ClientApplicationId);
            }
            else
            {
                (rejection, ClientApplication? application) = await VerifyAsync(code, request, now, cancellationToken);
                if (rejection is null)
                {
                    // Verified exchange for this user and this client: the only call site of StartAsync (T18 criterion,
                    // checked by an architecture test).
                    Result<SignedIn> started = await sessions.StartAsync(code.UserId, application!.ClientId, familyId, context, audit, cancellationToken);
                    session = started.Value;
                    rejection = session is not null ? null
                        : started.Error == AuthError.InvalidClient ? new Rejection("inactive_client", OAuthErrorCodes.InvalidClient, application.Id)
                        : new Rejection("inactive_user", OAuthErrorCodes.InvalidGrant, application.Id);
                }

                await transaction.CommitAsync(cancellationToken);
            }
        }

        if (rejection is not null)
        {
            if (rejection.Reason == "replayed")
            {
                await RevokeReplayedAsync(code, cancellationToken);
            }

            await audits.TryWriteAsync(AuditEvents.AuthorizationCodeRejected(code.UserId, rejection.ApplicationId, rejection.Reason), audit, cancellationToken);
            return TokenGrantResult.Fail(rejection.Error);
        }

        await audits.TryWriteAsync(AuditEvents.AuthorizationCodeRedeemed(code.UserId, code.ClientApplicationId, familyId), audit, cancellationToken);
        return new TokenGrantResult(session, null);
    }

    public async Task<TokenGrantResult> RefreshAsync(string? refreshToken, string? clientId, RefreshContext context, AuditContext audit, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(clientId))
        {
            return TokenGrantResult.Fail(OAuthErrorCodes.InvalidRequest);
        }

        Result<SignedIn> refreshed = await sessions.RefreshAsync(refreshToken, clientId, context, audit, cancellationToken);
        return refreshed.Value is SignedIn session
            ? new TokenGrantResult(session, null)
            : TokenGrantResult.Fail(refreshed.Error == AuthError.InvalidClient ? OAuthErrorCodes.InvalidClient : OAuthErrorCodes.InvalidGrant);
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

    /// <summary>The checks after the burn, in order; the first failure wins. Every answer except an inactive client is invalid_grant.</summary>
    private async Task<(Rejection? Rejection, ClientApplication? Application)> VerifyAsync(AuthorizationCode code, TokenExchangeRequest request, DateTime now, CancellationToken cancellationToken)
    {
        if (code.ExpiresUtc <= now)
        {
            return (new Rejection("unknown_or_expired", OAuthErrorCodes.InvalidGrant, code.ClientApplicationId), null);
        }

        ClientApplication? application = await applications.GetByClientIdAsync(request.ClientId, cancellationToken);
        if (application is null || application.Id != code.ClientApplicationId)
        {
            return (new Rejection("client_mismatch", OAuthErrorCodes.InvalidGrant, code.ClientApplicationId), null);
        }

        if (!application.IsActive)
        {
            return (new Rejection("inactive_client", OAuthErrorCodes.InvalidClient, application.Id), null);
        }

        if (!await clientAuthenticator.AuthenticateAsync(application, request, cancellationToken))
        {
            return (new Rejection("client_mismatch", OAuthErrorCodes.InvalidClient, application.Id), null);
        }

        // The redirect URI must match the one on the code AND still be registered: /authorize reads a cache that can be
        // up to 30 s old on other instances, so a URI removed meanwhile is refused here (T19 recheck L-A).
        if (!string.Equals(code.RedirectUri, request.RedirectUri, StringComparison.Ordinal)
            || !ClientApplicationLists.Read(application.RedirectUri).Contains(code.RedirectUri, StringComparer.Ordinal))
        {
            return (new Rejection("redirect_mismatch", OAuthErrorCodes.InvalidGrant, application.Id), null);
        }

        return VerifierMatches(request.CodeVerifier, code.CodeChallenge)
            ? (null, application)
            : (new Rejection("pkce_mismatch", OAuthErrorCodes.InvalidGrant, application.Id), null);
    }

    /// <summary>
    /// RFC 6819 4.4.1.1: a used code presented again revokes the session it started. The family id is read fresh (the
    /// code read before the burn may predate the redemption). A code redeemed before family ids were recorded with the
    /// burn (null) falls back to the user's families at that application started since the code was issued.
    /// </summary>
    private async Task RevokeReplayedAsync(AuthorizationCode code, CancellationToken cancellationToken)
    {
        DateTime now = clock.UtcNow;
        if (await codes.GetFamilyAsync(code.Id, cancellationToken) is Guid family)
        {
            await refreshRows.RevokeFamilyAsync(family, RefreshTokenRevokedReason.Reuse, now, cancellationToken);
            liveness.Invalidate(family);
            return;
        }

        if (await refreshRows.RevokeFamiliesStartedSinceAsync(code.UserId, code.ClientApplicationId, code.CreatedUtc, RefreshTokenRevokedReason.Reuse, now, cancellationToken) > 0)
        {
            liveness.InvalidateUser(code.UserId);
        }
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

    /// <summary>RFC 7636: 43 to 128 unreserved characters (code_challenge and code_verifier). \z, not $: $ also matches before a final newline.</summary>
    [GeneratedRegex(@"^[A-Za-z0-9._~-]{43,128}\z", RegexOptions.CultureInvariant)]
    private static partial Regex PkceValue();

    [GeneratedRegex(@"^[a-z0-9_.:]+( [a-z0-9_.:]+)*\z", RegexOptions.CultureInvariant)]
    private static partial Regex ScopeValue();

    private sealed record Rejection(string Reason, string Error, Guid? ApplicationId);
}
