using System.Text;
using System.Text.RegularExpressions;
using Auth.Services.Accounts;
using Auth.Services.Common;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;
using MimeKit.Utils;

namespace Auth.Api.Email;

/// <summary>
/// Configuration section <c>Smtp</c>: the real sender outside Development. Empty <see cref="Host"/> means off (the
/// refusing sender stays). The password is never a setting: it is the secret named <see cref="PasswordSecret"/>
/// (<c>Secrets:SmtpPassword</c> or <c>SecretFiles:SmtpPassword</c>, see setup.md "Naming rule for secrets").
/// </summary>
public sealed partial class SmtpEmailOptions
{
    public const string SectionName = "Smtp";

    public string? Host { get; set; }

    /// <summary>587 with STARTTLS (default) or 465 with TLS from the first byte. There is no plaintext mode.</summary>
    public int Port { get; set; } = 587;

    /// <summary>True: STARTTLS (port 587). False: TLS on connect (port 465).</summary>
    public bool UseStartTls { get; set; } = true;

    public string? UserName { get; set; }

    public string? FromAddress { get; set; }

    public string FromName { get; set; } = "Central Auth";

    public string PasswordSecret { get; set; } = "SmtpPassword";

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    public bool IsEnabled => !string.IsNullOrWhiteSpace(Host);

    /// <summary>
    /// Refuses a bad configuration at startup. Messages name the setting only, never its value.
    /// A disabled section (no Host) is not checked.
    /// </summary>
    public SmtpEmailOptions Validated()
    {
        if (!IsEnabled)
        {
            return this;
        }

        if (Host!.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)))
        {
            throw Invalid("Host");
        }

        if (Port is < 1 or > 65535)
        {
            throw Invalid("Port");
        }

        // The two standard ports each have one TLS mode; the other one hangs or fails at the first command.
        if ((Port == 587 && !UseStartTls) || (Port == 465 && UseStartTls))
        {
            throw Invalid("UseStartTls", "587 needs true (STARTTLS), 465 needs false (TLS on connect)");
        }

        // Usually the sender's address (Gmail, Microsoft 365), but some providers use a fixed word such as "apikey".
        if (string.IsNullOrWhiteSpace(UserName) || UserName.Length > 254 || UserName.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)))
        {
            throw Invalid("UserName", "1 to 254 characters, no spaces or control characters");
        }

        if (!SmtpEmailSender.TryParseSingleMailbox(FromAddress, out _))
        {
            throw Invalid("FromAddress", "an email address");
        }

        if (string.IsNullOrWhiteSpace(FromName) || FromName.Length > 100 || FromName.Any(char.IsControl))
        {
            throw Invalid("FromName", "1 to 100 characters, no control characters");
        }

        if (!SecretName().IsMatch(PasswordSecret ?? string.Empty))
        {
            throw Invalid("PasswordSecret", "letters, digits and underscores");
        }

        if (Timeout < TimeSpan.FromSeconds(1) || Timeout > TimeSpan.FromMinutes(5))
        {
            throw Invalid("Timeout", "between 1 second and 5 minutes");
        }

        return this;
    }

    private static InvalidOperationException Invalid(string setting, string? rule = null) =>
        new("Smtp:" + setting + " is invalid" + (rule is null ? "." : ": " + rule + "."));

    [GeneratedRegex("^[A-Za-z0-9_]{1,64}$")]
    private static partial Regex SecretName();
}

/// <summary>The network part, behind a seam so the sender is tested without sockets or real mail.</summary>
internal interface ISmtpTransport
{
    Task SendAsync(SmtpEmailOptions options, string password, MimeMessage message, CancellationToken cancellationToken);
}

/// <summary>MailKit: TLS is required (STARTTLS or TLS on connect), the server certificate is checked as usual.</summary>
internal sealed class MailKitSmtpTransport : ISmtpTransport
{
    public async Task SendAsync(SmtpEmailOptions options, string password, MimeMessage message, CancellationToken cancellationToken)
    {
        using SmtpClient client = new() { Timeout = (int)options.Timeout.TotalMilliseconds };
        SecureSocketOptions security = options.UseStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.SslOnConnect;
        // Validated() at startup guarantees both when the sender is registered.
        await client.ConnectAsync(options.Host!, options.Port, security, cancellationToken);
        await client.AuthenticateAsync(options.UserName!, password, cancellationToken);
        await client.SendAsync(message, cancellationToken);
        await client.DisconnectAsync(quit: true, cancellationToken);
    }
}

/// <summary>
/// Sends account emails over SMTP (outside Development, when <c>Smtp:Host</c> is set). One connection per message.
/// The log never holds the recipient, the body (it carries one-time links) or the password; a failure is logged with
/// the exception type and SMTP status code only, and surfaces as the same generic error as the refusing sender.
/// </summary>
internal sealed partial class SmtpEmailSender(SmtpEmailOptions options, ISecretStore secrets, ISmtpTransport transport, ILogger<SmtpEmailSender> logger) : IEmailSender
{
    internal const string FailureMessage = "An account email could not be sent.";

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (!TryBuildMessage(options, message, out MimeMessage mime))
        {
            LogRefused(logger);
            throw new InvalidOperationException(FailureMessage);
        }

        string? password = await secrets.GetSecretAsync(options.PasswordSecret, cancellationToken);
        if (string.IsNullOrWhiteSpace(password))
        {
            LogNoPassword(logger, options.PasswordSecret);
            throw new InvalidOperationException(FailureMessage);
        }

        // MailKit's Timeout bounds each read and write; this bounds the whole send, which runs inside the HTTP request
        // (Phyllis LOW-1). Only the caller's own cancellation propagates as cancellation.
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.Timeout * 2);
        try
        {
            await transport.SendAsync(options, NormalizePassword(password), mime, deadline.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // The server's reply text and MailKit's messages can name the recipient: neither is logged nor chained.
            LogFailed(logger, ex.GetType().Name, ex is SmtpCommandException command ? (int)command.StatusCode : 0);
            throw new InvalidOperationException(FailureMessage);
        }

        LogSent(logger, message.Subject);
    }

    internal static bool TryBuildMessage(SmtpEmailOptions options, EmailMessage message, out MimeMessage mime)
    {
        mime = new MimeMessage();
        if (HasLineBreak(message.Subject) || !TryParseSingleMailbox(message.To, out MailboxAddress? to)
            || !TryParseSingleMailbox(options.FromAddress, out MailboxAddress? from))
        {
            return false;
        }

        from.Name = options.FromName;
        mime.From.Add(from);
        mime.To.Add(to);
        mime.Subject = message.Subject;
        // MimeKit would otherwise put this machine's host name into the Message-Id that every recipient sees.
        mime.MessageId = MimeUtils.GenerateMessageId(from.Domain);
        TextPart body = new(TextFormat.Plain);
        body.SetText(Encoding.UTF8, message.Body ?? string.Empty);
        mime.Body = body;
        return true;
    }

    /// <summary>Exactly one bare address (no display name, list or group), with no line break anywhere.</summary>
    internal static bool TryParseSingleMailbox(string? text, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out MailboxAddress? mailbox)
    {
        mailbox = null;
        if (string.IsNullOrWhiteSpace(text) || HasLineBreak(text) || text.Length > 254)
        {
            return false;
        }

        string trimmed = text.Trim();
        if (!MailboxAddress.TryParse(trimmed, out MailboxAddress? parsed)
            || !string.Equals(parsed.Address, trimmed, StringComparison.OrdinalIgnoreCase)
            || !parsed.Address.Contains('@', StringComparison.Ordinal))
        {
            return false;
        }

        mailbox = new MailboxAddress(string.Empty, parsed.Address);
        return true;
    }

    /// <summary>
    /// A secret file usually ends with a line break, so the value is trimmed. Inner spaces are removed only for the
    /// Gmail app-password shape (four groups of four letters); any other password is kept as written.
    /// </summary>
    internal static string NormalizePassword(string password)
    {
        string trimmed = password.Trim();
        return GmailAppPassword().IsMatch(trimmed) ? trimmed.Replace(" ", string.Empty, StringComparison.Ordinal) : trimmed;
    }

    [GeneratedRegex("^[A-Za-z]{4}( [A-Za-z]{4}){3}$")]
    private static partial Regex GmailAppPassword();

    private static bool HasLineBreak(string? value) => value is not null && value.AsSpan().IndexOfAny('\r', '\n') >= 0;

    [LoggerMessage(EventId = 5202, Level = LogLevel.Information, Message = "Account email \"{Subject}\" sent over SMTP")]
    private static partial void LogSent(ILogger logger, string subject);

    [LoggerMessage(EventId = 5203, Level = LogLevel.Error, Message = "An account email could not be sent over SMTP: {ErrorType}, SMTP status {StatusCode}")]
    private static partial void LogFailed(ILogger logger, string errorType, int statusCode);

    [LoggerMessage(EventId = 5204, Level = LogLevel.Error, Message = "An account email was refused before sending: an address or the subject is not valid")]
    private static partial void LogRefused(ILogger logger);

    [LoggerMessage(EventId = 5205, Level = LogLevel.Error, Message = "An account email could not be sent: the SMTP password secret '{SecretName}' is not set")]
    private static partial void LogNoPassword(ILogger logger, string secretName);
}

/// <summary>Chooses the account email sender (Program.cs). Development is unchanged: the pickup folder.</summary>
internal static class AccountEmailRegistration
{
    public static IServiceCollection AddAccountEmailSender(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        if (environment.IsDevelopment())
        {
            services.AddSingleton(configuration.GetSection(DevelopmentEmailOptions.SectionName).Get<DevelopmentEmailOptions>() ?? new DevelopmentEmailOptions());
            services.AddSingleton<IEmailSender, PickupDirectoryEmailSender>();
            return services;
        }

        SmtpEmailOptions smtp = (configuration.GetSection(SmtpEmailOptions.SectionName).Get<SmtpEmailOptions>() ?? new SmtpEmailOptions()).Validated();
        if (smtp.IsEnabled)
        {
            services.AddSingleton(smtp);
            services.AddSingleton<ISmtpTransport, MailKitSmtpTransport>();
            services.AddSingleton<IEmailSender, SmtpEmailSender>();
        }
        else
        {
            services.AddSingleton<IEmailSender, UnconfiguredEmailSender>();
        }

        return services;
    }
}
