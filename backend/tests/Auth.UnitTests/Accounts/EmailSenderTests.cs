using Auth.Api.Email;
using Auth.Services.Accounts;
using Auth.UnitTests.Security;
using Microsoft.Extensions.Logging;

namespace Auth.UnitTests.Accounts;

/// <summary>T12: the development sender writes the message to a file and keeps recipient, body and token out of the log.</summary>
public sealed class EmailSenderTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "centralauth-mail-test-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Pickup_sender_writes_the_message_and_logs_only_subject_and_file()
    {
        AuditLowFixTests.ListLogger<PickupDirectoryEmailSender> logger = new();
        PickupDirectoryEmailSender sender = new(new DevelopmentEmailOptions { PickupDirectory = directory }, logger);
        EmailMessage message = new("ada@example.test", "Confirm your email address", "Open https://app.example.test/verify-email#token=SECRET-TOKEN-123");

        await sender.SendAsync(message, CancellationToken.None);

        string file = Assert.Single(Directory.GetFiles(directory, "*.eml"));
        string content = await File.ReadAllTextAsync(file);
        Assert.Contains("To: ada@example.test", content, StringComparison.Ordinal);
        Assert.Contains("#token=SECRET-TOKEN-123", content, StringComparison.Ordinal);
        (LogLevel level, string text) = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, level);
        Assert.Contains("Confirm your email address", text, StringComparison.Ordinal);
        Assert.DoesNotContain("SECRET-TOKEN-123", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ada@example.test", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unconfigured_sender_refuses_and_logs_an_error_without_the_message()
    {
        AuditLowFixTests.ListLogger<UnconfiguredEmailSender> logger = new();
        UnconfiguredEmailSender sender = new(logger);

        await Assert.ThrowsAsync<InvalidOperationException>(() => sender.SendAsync(new EmailMessage("ada@example.test", "s", "#token=SECRET"), CancellationToken.None));

        (LogLevel level, string text) = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, level);
        Assert.DoesNotContain("SECRET", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ada@example.test", text, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
