using System.Data;
using System.Text.Json;
using Auth.Contracts;
using Auth.Contracts.Requests;
using Auth.Contracts.Responses;
using Auth.DAL;
using Auth.DAL.Repositories;
using Auth.Entities;
using Auth.Services.Audit;
using Auth.Services.Common;
using Auth.Services.Security;

namespace Auth.Services.ClientApplications;

/// <summary>
/// Outcome of a registry write: <see cref="Application"/> on success, <see cref="Errors"/> (field names to messages,
/// never echoing the input) when validation failed, or <see cref="Error"/> (NotFound, or ValidationFailed for a client id
/// or audience already in use).
/// </summary>
public sealed record ClientApplicationResult(ClientApplicationResponse? Application, IReadOnlyDictionary<string, string[]> Errors, AuthError? Error = null)
{
    public bool IsSuccess => Application is not null;
}

/// <summary>Configuration section <c>ClientApplications:Bootstrap</c>: the first application (usually the SPA itself).</summary>
public sealed class ClientApplicationBootstrapOptions
{
    public const string SectionName = "ClientApplications:Bootstrap";

    public string? ClientId { get; set; }

    public string? Name { get; set; }

    public string? Audience { get; set; }

    public List<string> AllowedOrigins { get; set; } = [];

    public List<string> RedirectUris { get; set; } = [];

    public List<string> PostLogoutRedirectUris { get; set; } = [];

    public bool IsConfigured => !string.IsNullOrWhiteSpace(ClientId);

    public ClientApplicationRequest ToRequest() =>
        new(ClientId ?? string.Empty, Name ?? string.Empty, Audience ?? string.Empty, AllowedOrigins, RedirectUris, PostLogoutRedirectUris);
}

/// <summary>What the bootstrap step did.</summary>
public enum ClientApplicationBootstrapOutcome
{
    NotConfigured,
    Created,

    /// <summary>At least one application is already registered: the setting was ignored (remove it).</summary>
    ApplicationsExist,

    /// <summary>The configured values failed validation; nothing was created.</summary>
    Invalid,
}

/// <summary>
/// The client application registry (T18). Every write is validated by the strict rules of ClientApplicationValidator,
/// audited (AppCreated, AppUpdated, AppDeactivated, ids and flags only) and drops the CORS origin cache on this instance.
/// There are no HTTP endpoints yet: an admin endpoint must require the apps.manage policy and call this service.
/// </summary>
public interface IClientApplicationRegistry
{
    Task<IReadOnlyList<ClientApplicationResponse>> ListAsync(CancellationToken cancellationToken);

    Task<ClientApplicationResponse?> GetAsync(Guid id, CancellationToken cancellationToken);

    /// <summary>Registers an application, inactive or active as asked. Client id and audience must be unused.</summary>
    Task<ClientApplicationResult> CreateAsync(ClientApplicationRequest request, bool active, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Replaces name, audience, origins and redirect URIs. The client id cannot change.</summary>
    Task<ClientApplicationResult> UpdateAsync(Guid id, ClientApplicationRequest request, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Activates the application again. False when it does not exist.</summary>
    Task<bool> ActivateAsync(Guid id, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>
    /// Deactivates the application and, in the same transaction, revokes every refresh family issued to it (set-based,
    /// reason Admin). The live-session check then rejects its tokens at once on this instance and within
    /// SessionLiveness:CacheDuration elsewhere; CORS drops its origins at once here and within 30 s elsewhere. False when
    /// it does not exist.
    /// </summary>
    Task<bool> DeactivateAsync(Guid id, AuditContext audit, CancellationToken cancellationToken);

    /// <summary>Creates the configured bootstrap application, only while no application exists at all.</summary>
    Task<ClientApplicationBootstrapOutcome> BootstrapAsync(ClientApplicationBootstrapOptions options, CancellationToken cancellationToken);
}

internal sealed class ClientApplicationRegistry(
    IClientApplicationRepository applications,
    IRefreshTokenRepository refreshTokens,
    IAuditService audits,
    IUnitOfWork unitOfWork,
    IClientApplicationOriginProvider origins,
    ISessionLiveness liveness,
    ISessionEndedPublisher sessionsEnded,
    ClientApplicationValidator validator,
    IClock clock) : IClientApplicationRegistry
{
    public async Task<IReadOnlyList<ClientApplicationResponse>> ListAsync(CancellationToken cancellationToken) =>
        [.. (await applications.GetAllAsync(cancellationToken)).Select(ToResponse)];

    public async Task<ClientApplicationResponse?> GetAsync(Guid id, CancellationToken cancellationToken) =>
        await applications.GetByIdAsync(id, cancellationToken) is ClientApplication application ? ToResponse(application) : null;

    public Task<ClientApplicationResult> CreateAsync(ClientApplicationRequest request, bool active, AuditContext audit, CancellationToken cancellationToken) =>
        CreateCoreAsync(request, active, "registry", audit, cancellationToken);

    public async Task<ClientApplicationResult> UpdateAsync(Guid id, ClientApplicationRequest request, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        (ValidClientApplication? valid, IReadOnlyDictionary<string, string[]> errors) = validator.Validate(request);
        if (valid is null)
        {
            return new ClientApplicationResult(null, errors, AuthError.ValidationFailed);
        }

        ClientApplication? application = await applications.GetByIdAsync(id, cancellationToken);
        if (application is null)
        {
            return new ClientApplicationResult(null, Empty, AuthError.NotFound);
        }

        if (!string.Equals(application.ClientId, valid.ClientId, StringComparison.Ordinal))
        {
            return Conflict("clientId", "The client id cannot change.");
        }

        if (await applications.IsAudienceInUseAsync(valid.Audience, application.Id, cancellationToken))
        {
            return Conflict("audience", "Another application already uses this audience.");
        }

        // A new audience ends the application's sessions: tokens minted for the old audience must not stay usable
        // (T18 audit L5). Origins and redirect URIs only refresh the caches.
        bool audienceChanged = !string.Equals(application.Audience, valid.Audience, StringComparison.OrdinalIgnoreCase);
        DateTime now = clock.UtcNow;
        try
        {
            await using IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
            Apply(application, valid);
            application.UpdatedUtc = now;
            int? revoked = audienceChanged
                ? await refreshTokens.RevokeAllForClientApplicationAsync(application.Id, RefreshTokenRevokedReason.Admin, now, cancellationToken)
                : null;
            await audits.StageAsync(AuditEvents.AppUpdated(application.Id, application.IsActive, revoked), audit, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (UniqueConstraintViolationException ex)
        {
            unitOfWork.ClearChanges();
            return ConflictFor(ex);
        }

        origins.Invalidate();
        if (audienceChanged)
        {
            liveness.InvalidateAll();
            await sessionsEnded.PublishAsync(
                new SessionEnded(SessionEndScope.Application, SessionEndCause.ApplicationDeactivated, null, ClientApplicationId: application.Id), audit, cancellationToken);
        }

        return new ClientApplicationResult(ToResponse(application), Empty);
    }

    public async Task<bool> ActivateAsync(Guid id, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        ClientApplication? application = await applications.GetByIdAsync(id, cancellationToken);
        if (application is null)
        {
            return false;
        }

        if (!application.IsActive)
        {
            application.IsActive = true;
            application.UpdatedUtc = clock.UtcNow;
            await audits.StageAsync(AuditEvents.AppUpdated(application.Id, true), audit, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            origins.Invalidate();
        }

        return true;
    }

    public async Task<bool> DeactivateAsync(Guid id, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        await using (IUnitOfWorkTransaction transaction = await unitOfWork.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken))
        {
            ClientApplication? application = await applications.GetByIdAsync(id, cancellationToken);
            if (application is null)
            {
                return false;
            }

            DateTime now = clock.UtcNow;
            application.IsActive = false;
            application.UpdatedUtc = now;
            int revoked = await refreshTokens.RevokeAllForClientApplicationAsync(application.Id, RefreshTokenRevokedReason.Admin, now, cancellationToken);
            await audits.StageAsync(AuditEvents.AppDeactivated(application.Id, revoked), audit, cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        // A rotation that passed its active-app check just before the commit may have inserted a successor after the
        // revoke (T18 audit L1). Such a row is inert (liveness and rotation require an active app) but is revoked too.
        try
        {
            await refreshTokens.RevokeAllForClientApplicationAsync(id, RefreshTokenRevokedReason.Admin, clock.UtcNow, cancellationToken);
        }
        catch (DataAccessException)
        {
            // Best effort: the application is already inactive and such a row cannot be used.
        }

        origins.Invalidate();
        liveness.InvalidateAll();
        await sessionsEnded.PublishAsync(new SessionEnded(SessionEndScope.Application, SessionEndCause.ApplicationDeactivated, null, ClientApplicationId: id), audit, cancellationToken);
        return true;
    }

    public async Task<ClientApplicationBootstrapOutcome> BootstrapAsync(ClientApplicationBootstrapOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.IsConfigured)
        {
            return ClientApplicationBootstrapOutcome.NotConfigured;
        }

        if (await applications.AnyAsync(cancellationToken))
        {
            return ClientApplicationBootstrapOutcome.ApplicationsExist;
        }

        try
        {
            ClientApplicationResult result = await CreateCoreAsync(options.ToRequest(), true, "bootstrap", AuditContext.None, cancellationToken);
            if (result.IsSuccess)
            {
                return ClientApplicationBootstrapOutcome.Created;
            }

            // A conflict means another instance registered it meanwhile, not that the configuration is wrong.
            return await applications.AnyAsync(cancellationToken) ? ClientApplicationBootstrapOutcome.ApplicationsExist : ClientApplicationBootstrapOutcome.Invalid;
        }
        catch (UniqueConstraintViolationException)
        {
            // Another instance seeded the same client id at the same moment.
            unitOfWork.ClearChanges();
            return ClientApplicationBootstrapOutcome.ApplicationsExist;
        }
    }

    private async Task<ClientApplicationResult> CreateCoreAsync(ClientApplicationRequest request, bool active, string source, AuditContext audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(audit);
        (ValidClientApplication? valid, IReadOnlyDictionary<string, string[]> errors) = validator.Validate(request);
        if (valid is null)
        {
            return new ClientApplicationResult(null, errors, AuthError.ValidationFailed);
        }

        if (await applications.GetByClientIdAsync(valid.ClientId, cancellationToken) is not null)
        {
            return Conflict("clientId", "This client id is already registered.");
        }

        if (await applications.IsAudienceInUseAsync(valid.Audience, null, cancellationToken))
        {
            return Conflict("audience", "Another application already uses this audience.");
        }

        DateTime now = clock.UtcNow;
        ClientApplication application = new() { ClientId = valid.ClientId, RequirePkce = true, IsActive = active, CreatedUtc = now };
        Apply(application, valid);
        application.UpdatedUtc = now;
        await applications.AddAsync(application, cancellationToken);
        await audits.StageAsync(AuditEvents.AppCreated(application.Id, source), audit, cancellationToken);
        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (UniqueConstraintViolationException ex)
        {
            // Lost a race with a concurrent create: the unique indexes on client id and audience decide.
            unitOfWork.ClearChanges();
            return ConflictFor(ex);
        }

        origins.Invalidate();
        return new ClientApplicationResult(ToResponse(application), Empty);
    }

    private static readonly IReadOnlyDictionary<string, string[]> Empty = new Dictionary<string, string[]>();

    private static ClientApplicationResult ConflictFor(UniqueConstraintViolationException ex) =>
        ex.ConstraintName == "UQ_ClientApplication_Audience"
            ? Conflict("audience", "Another application already uses this audience.")
            : Conflict("clientId", "This client id is already registered.");

    private static ClientApplicationResult Conflict(string field, string message) =>
        new(null, new Dictionary<string, string[]> { [field] = [message] }, AuthError.ValidationFailed);

    private static void Apply(ClientApplication application, ValidClientApplication valid)
    {
        application.Name = valid.Name;
        application.Audience = valid.Audience;
        application.AllowedOrigin = JsonSerializer.Serialize(valid.AllowedOrigins);
        application.RedirectUri = JsonSerializer.Serialize(valid.RedirectUris);
        application.PostLogoutRedirectUri = JsonSerializer.Serialize(valid.PostLogoutRedirectUris);
    }

    private static ClientApplicationResponse ToResponse(ClientApplication application) => new(
        application.Id,
        application.ClientId,
        application.Name,
        application.Audience,
        ClientApplicationLists.Read(application.AllowedOrigin),
        ClientApplicationLists.Read(application.RedirectUri),
        ClientApplicationLists.Read(application.PostLogoutRedirectUri),
        application.RequirePkce,
        application.IsActive);
}
