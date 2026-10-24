namespace Auth.Services.Accounts;

/// <summary>A plain-text email. The body may hold a one-time link: implementations must never log it.</summary>
public sealed record EmailMessage(string To, string Subject, string Body);

/// <summary>
/// Sends account emails (verification, notices). The host provides the implementation: a development sender that
/// writes messages to a local pickup folder, or a real provider in production.
/// </summary>
public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken);
}
