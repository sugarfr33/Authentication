using Auth.Api.Email;
using Auth.Services.Accounts;
using Auth.Services.Common;
using Auth.UnitTests.Security;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace Auth.UnitTests.Accounts;

/// <summary>
/// The SMTP sender (outside Development, Smtp:Host set): options refused at startup, TLS always, the password from the
/// secret store, no header injection, and nothing of the recipient, body or password in the log. No sockets, no mail.
/// </summary>
public sealed class SmtpEmailSenderTests
{
    private const string Token = "SECRET-TOKEN-123";
    private const string Password = "abcd efgh ijkl mnop";

    private static SmtpEmailOptions Options(Action<SmtpEmailOptions>? change = null)
    {
        SmtpEmailOptions options = new()
        {
            Host = "smtp.example.test",
            Port = 587,
            UseStartTls = true,
            UserName = "sender@example.test",
            FromAddress = "sender@example.test",
            FromName = "Suki Rewards",
        };
        change?.Invoke(options);
        return options;
    }

    private static EmailMessage Message(string to = "ada@example.test", string subject = "Confirm your email address") =>
        new(to, subject, "Open https://app.example.test/verify-email#token=" + Token);

    [Fact]
    public async Task Sends_one_plain_text_message_with_the_secret_store_password()
    {
        FakeTransport transport = new();
        AuditLowFixTests.ListLogger<SmtpEmailSender> logger = new();
        SmtpEmailSender sender = new(Options(), new FakeSecrets(Password + "\r\n"), transport, logger);

        await sender.SendAsync(Message(), CancellationToken.None);

        MimeMessage sent = Assert.Single(transport.Sent);
        Assert.Equal("abcdefghijklmnop", transport.Password);
        Assert.Equal("ada@example.test", Assert.Single(sent.To.Mailboxes).Address);
        MailboxAddress from = Assert.Single(sent.From.Mailboxes);
        Assert.Equal("sender@example.test", from.Address);
        Assert.Equal("Suki Rewards", from.Name);
        Assert.Empty(sent.Cc);
        Assert.Empty(sent.Bcc);
        Assert.Equal("Confirm your email address", sent.Subject);
        TextPart body = Assert.IsType<TextPart>(sent.Body);
        Assert.True(body.IsPlain);
        Assert.Contains("#token=" + Token, body.Text, StringComparison.Ordinal);

        (LogLevel level, string text) = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, level);
        Assert.DoesNotContain(Token, text, StringComparison.Ordinal);
        Assert.DoesNotContain("ada@example.test", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ada@example.test\r\nBcc: eve@example.test", "s")]
    [InlineData("ada@example.test", "Hello\r\nBcc: eve@example.test")]
    [InlineData("ada@example.test, eve@example.test", "s")]
    [InlineData("Ada <ada@example.test>", "s")]
    [InlineData("not-an-address", "s")]
    public async Task Refuses_header_injection_lists_and_bad_addresses_before_sending(string to, string subject)
    {
        FakeTransport transport = new();
        AuditLowFixTests.ListLogger<SmtpEmailSender> logger = new();
        SmtpEmailSender sender = new(Options(), new FakeSecrets(Password), transport, logger);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() => sender.SendAsync(Message(to, subject), CancellationToken.None));

        Assert.Equal(SmtpEmailSender.FailureMessage, error.Message);
        Assert.Empty(transport.Sent);
        (LogLevel level, string text) = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, level);
        Assert.DoesNotContain("eve@example.test", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_missing_password_fails_closed_without_connecting()
    {
        FakeTransport transport = new();
        AuditLowFixTests.ListLogger<SmtpEmailSender> logger = new();
        SmtpEmailSender sender = new(Options(), new FakeSecrets(null), transport, logger);

        await Assert.ThrowsAsync<InvalidOperationException>(() => sender.SendAsync(Message(), CancellationToken.None));

        Assert.Equal(0, transport.Calls);
        (LogLevel level, string text) = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, level);
        Assert.Contains("SmtpPassword", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_server_error_is_logged_by_type_and_status_only_and_not_chained()
    {
        // MailKit puts the server's reply (which can name the recipient) in the exception message.
        SmtpCommandException server = new(SmtpErrorCode.RecipientNotAccepted, SmtpStatusCode.MailboxUnavailable, "5.1.1 <ada@example.test> " + Token);
        FakeTransport transport = new() { Failure = server };
        AuditLowFixTests.ListLogger<SmtpEmailSender> logger = new();
        SmtpEmailSender sender = new(Options(), new FakeSecrets(Password), transport, logger);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() => sender.SendAsync(Message(), CancellationToken.None));

        Assert.Equal(SmtpEmailSender.FailureMessage, error.Message);
        Assert.Null(error.InnerException);
        (LogLevel level, string text) = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, level);
        Assert.Contains("SmtpCommandException", text, StringComparison.Ordinal);
        Assert.Contains("550", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ada@example.test", text, StringComparison.Ordinal);
        Assert.DoesNotContain(Token, text, StringComparison.Ordinal);
        Assert.DoesNotContain("abcd", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_hanging_server_is_cut_off_by_the_total_deadline_with_the_generic_error()
    {
        FakeTransport transport = new() { Hang = true };
        SmtpEmailSender sender = new(Options(o => o.Timeout = TimeSpan.FromSeconds(1)), new FakeSecrets(Password), transport, new AuditLowFixTests.ListLogger<SmtpEmailSender>());

        Task send = sender.SendAsync(Message(), CancellationToken.None);
        Task first = await Task.WhenAny(send, Task.Delay(TimeSpan.FromSeconds(20)));

        Assert.Same(send, first);
        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() => send);
        Assert.Equal(SmtpEmailSender.FailureMessage, error.Message);
    }

    [Fact]
    public async Task The_message_id_uses_the_sender_domain_not_this_machine()
    {
        FakeTransport transport = new();
        SmtpEmailSender sender = new(Options(), new FakeSecrets(Password), transport, new AuditLowFixTests.ListLogger<SmtpEmailSender>());

        await sender.SendAsync(Message(), CancellationToken.None);

        string? id = Assert.Single(transport.Sent).MessageId;
        Assert.NotNull(id);
        Assert.EndsWith("@example.test", id, StringComparison.Ordinal);
        Assert.DoesNotContain(Environment.MachineName, id, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("abcd efgh ijkl mnop\r\n", "abcdefghijklmnop")]
    [InlineData("  pass word with spaces \n", "pass word with spaces")]
    [InlineData("abcd efgh ijkl", "abcd efgh ijkl")]
    public void Only_the_gmail_app_password_shape_loses_its_inner_spaces(string stored, string used) =>
        Assert.Equal(used, SmtpEmailSender.NormalizePassword(stored));

    [Fact]
    public void A_user_name_that_is_not_an_address_is_accepted()
    {
        Options(o => o.UserName = "apikey").Validated();
    }

    [Fact]
    public async Task Cancellation_is_passed_through()
    {
        using CancellationTokenSource cancel = new();
        await cancel.CancelAsync();
        FakeTransport transport = new() { Failure = new OperationCanceledException(cancel.Token) };
        SmtpEmailSender sender = new(Options(), new FakeSecrets(Password), transport, new AuditLowFixTests.ListLogger<SmtpEmailSender>());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sender.SendAsync(Message(), cancel.Token));
    }

    [Theory]
    [InlineData("Host")]
    [InlineData("Port")]
    [InlineData("UseStartTls")]
    [InlineData("UserName")]
    [InlineData("FromAddress")]
    [InlineData("FromName")]
    [InlineData("PasswordSecret")]
    [InlineData("Timeout")]
    public void Options_refuse_a_bad_value_and_name_only_the_setting(string setting)
    {
        SmtpEmailOptions options = Options(o =>
        {
            switch (setting)
            {
                case "Host": o.Host = "smtp.example.test\r\nX"; break;
                case "Port": o.Port = 70000; break;
                case "UseStartTls": o.Port = 465; o.UseStartTls = true; break;
                case "UserName": o.UserName = "user name@example.test"; break;
                case "FromAddress": o.FromAddress = "Eve <eve@example.test>"; break;
                case "FromName": o.FromName = "Suki\r\nBcc: eve@example.test"; break;
                case "PasswordSecret": o.PasswordSecret = "smtp-password"; break;
                case "Timeout": o.Timeout = TimeSpan.Zero; break;
            }
        });

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => options.Validated());

        Assert.StartsWith("Smtp:" + setting + " is invalid", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("eve@example.test", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_accept_587_with_starttls_and_465_with_tls_on_connect_and_skip_a_disabled_section()
    {
        Options().Validated();
        Options(o => { o.Port = 465; o.UseStartTls = false; }).Validated();
        new SmtpEmailOptions { Host = "", Port = -1 }.Validated();
    }

    [Theory]
    [InlineData("Development", null, typeof(PickupDirectoryEmailSender))]
    [InlineData("Development", "smtp.example.test", typeof(PickupDirectoryEmailSender))]
    [InlineData("Production", null, typeof(UnconfiguredEmailSender))]
    [InlineData("Production", "smtp.example.test", typeof(SmtpEmailSender))]
    public void Registration_picks_the_sender_by_environment_and_host(string environment, string? host, Type expected)
    {
        Dictionary<string, string?> settings = new()
        {
            ["Smtp:Host"] = host,
            ["Smtp:UserName"] = "sender@example.test",
            ["Smtp:FromAddress"] = "sender@example.test",
        };
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<ISecretStore>(new FakeSecrets(Password));

        services.AddAccountEmailSender(configuration, new HostingEnvironment { EnvironmentName = environment });

        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.IsType(expected, provider.GetRequiredService<IEmailSender>());
    }

    [Fact]
    public void Registration_refuses_an_invalid_section_at_startup()
    {
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Smtp:Host"] = "smtp.example.test",
            ["Smtp:Port"] = "465",
            ["Smtp:UserName"] = "sender@example.test",
            ["Smtp:FromAddress"] = "sender@example.test",
        }).Build();

        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection().AddAccountEmailSender(configuration, new HostingEnvironment { EnvironmentName = Environments.Production }));
    }

    private sealed class FakeSecrets(string? password) : ISecretStore
    {
        public Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(name == "SmtpPassword" ? password : null);
    }

    private sealed class FakeTransport : ISmtpTransport
    {
        public List<MimeMessage> Sent { get; } = [];

        public string? Password { get; private set; }

        public int Calls { get; private set; }

        public Exception? Failure { get; init; }

        public bool Hang { get; init; }

        public async Task SendAsync(SmtpEmailOptions options, string password, MimeMessage message, CancellationToken cancellationToken)
        {
            Calls++;
            if (Hang)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            if (Failure is not null)
            {
                throw Failure;
            }

            Password = password;
            Sent.Add(message);
        }
    }
}
