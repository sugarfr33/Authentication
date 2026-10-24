using System.Globalization;
using System.Text;
using Auth.Services.Accounts;

namespace Auth.Api.Email;

/// <summary>Configuration section <c>DevelopmentEmail</c>.</summary>
public sealed class DevelopmentEmailOptions
{
    public const string SectionName = "DevelopmentEmail";

    /// <summary>Folder that receives one .eml file per message. Default: centralauth-mail in the temp folder.</summary>
    public string? PickupDirectory { get; set; }
}

/// <summary>
/// Development only: writes each message to a file in a local pickup folder, where the developer opens the link.
/// The log line names the subject and file only; the body (which holds the one-time link) and the recipient never
/// reach the log.
/// </summary>
internal sealed partial class PickupDirectoryEmailSender(DevelopmentEmailOptions options, ILogger<PickupDirectoryEmailSender> logger) : IEmailSender
{
    private readonly string directory = string.IsNullOrWhiteSpace(options.PickupDirectory)
        ? Path.Combine(Path.GetTempPath(), "centralauth-mail")
        : options.PickupDirectory;

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        Directory.CreateDirectory(directory);
        string file = Path.Combine(directory, DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N")[..8] + ".eml");
        string content = "To: " + message.To + "\r\nSubject: " + message.Subject + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + message.Body + "\r\n";
        await File.WriteAllTextAsync(file, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken);
        LogWritten(logger, message.Subject, file);
    }

    [LoggerMessage(EventId = 5200, Level = LogLevel.Information, Message = "Development email \"{Subject}\" written to {PickupFile}")]
    private static partial void LogWritten(ILogger logger, string subject, string pickupFile);
}

/// <summary>
/// Outside Development until a real provider is registered: refuses to send, loudly. Every sign-up path sends exactly
/// one email, so this fails new and duplicate registrations alike and reveals nothing about which emails exist.
/// </summary>
internal sealed partial class UnconfiguredEmailSender(ILogger<UnconfiguredEmailSender> logger) : IEmailSender
{
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken)
    {
        LogNotConfigured(logger);
        throw new InvalidOperationException("No email sender is configured: register an IEmailSender for this environment.");
    }

    [LoggerMessage(EventId = 5201, Level = LogLevel.Error, Message = "An account email could not be sent: no email sender is configured for this environment")]
    private static partial void LogNotConfigured(ILogger logger);
}
