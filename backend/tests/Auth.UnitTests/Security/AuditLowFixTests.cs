using System.Reflection;
using System.Text;
using System.Text.Json.Serialization;
using Auth.Api.Hosting;
using Auth.Api.RateLimiting;
using Auth.Contracts.Requests;
using Auth.Services.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.UnitTests.Security;

/// <summary>T11 security audit LOW fixes (A, C, D), fixed with T12.</summary>
public class AuditLowFixTests
{
    private const string LoginPath = "/api/v1/auth/login";

    [Theory]
    [InlineData(StatusCodes.Status408RequestTimeout)]
    [InlineData(StatusCodes.Status400BadRequest)]
    public async Task A_body_the_server_cannot_read_keeps_its_own_status_and_is_logged_as_a_warning(int status)
    {
        (HttpContext context, bool reachedEndpoint, ListLogger<AccountKeyMiddleware> logger) = await RunAccountKeyAsync(
            new ThrowingStream(new BadHttpRequestException("Reading the request body timed out due to data arriving too slowly.", status)));

        Assert.Equal(status, context.Response.StatusCode);
        Assert.False(reachedEndpoint);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains(status.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_413_is_answered_only_for_a_real_overflow()
    {
        (HttpContext context, bool reachedEndpoint, ListLogger<AccountKeyMiddleware> logger) = await RunAccountKeyAsync(
            new ThrowingStream(new BadHttpRequestException("Request body too large.", StatusCodes.Status413PayloadTooLarge)));

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.False(reachedEndpoint);
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public async Task A_readable_body_reaches_the_endpoint_rewound_with_its_account_key()
    {
        byte[] json = Encoding.UTF8.GetBytes("""{"email":" Ada@Example.test "}""");

        (HttpContext context, bool reachedEndpoint, _) = await RunAccountKeyAsync(new MemoryStream(json));

        Assert.True(reachedEndpoint);
        Assert.Equal("ADA@EXAMPLE.TEST", context.Items[AccountKeyMiddleware.ItemKey]);
        Assert.Equal(0, context.Request.Body.Position);
    }

    [Fact]
    public async Task C_a_failing_warm_up_logs_a_warning_and_never_stops_the_host()
    {
        ListLogger<TimingGuardWarmUp> logger = new();
        using TimingGuardWarmUp warmUp = new(new FailingGuard(), logger);

        await warmUp.StartAsync(CancellationToken.None);
        await warmUp.ExecuteTask!;

        Assert.True(warmUp.ExecuteTask.IsCompletedSuccessfully);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning);
    }

    [Theory]
    [InlineData("  Ada@Example.Test ", "ADA@EXAMPLE.TEST")]
    [InlineData("ada@example.test", "ADA@EXAMPLE.TEST")]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    public void D_one_email_normalizer_trims_and_upper_cases(string? raw, string? expected)
    {
        Assert.Equal(expected, EmailNormalizer.Normalize(raw));
    }

    [Fact]
    public void D_rate_limit_key_and_normalizer_agree()
    {
        string raw = " Grace.Hopper@Example.TEST ";

        Assert.Equal(EmailNormalizer.Normalize(raw), AccountKeyMiddleware.FindEmail(Encoding.UTF8.GetBytes("{\"email\":\"" + raw + "\"}")));
        Assert.Null(EmailNormalizer.Normalize(new string('a', EmailNormalizer.MaxLength - 10) + "@example.te"));
        Assert.NotNull(EmailNormalizer.Normalize(new string('a', EmailNormalizer.MaxLength - 11) + "@example.te"));
    }

    [Fact]
    public void D_every_request_DTO_email_property_binds_from_the_shared_field_name()
    {
        List<PropertyInfo> emailProperties = typeof(AuthRequestFields).Assembly.GetTypes()
            .Where(t => t.Namespace == typeof(AuthRequestFields).Namespace && t.Name.EndsWith("Request", StringComparison.Ordinal))
            .SelectMany(t => t.GetProperties())
            .Where(p => p.Name.Contains("email", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(emailProperties);
        Assert.All(emailProperties, p => Assert.Equal(AuthRequestFields.Email, p.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name));
    }

    private static async Task<(HttpContext Context, bool ReachedEndpoint, ListLogger<AccountKeyMiddleware> Logger)> RunAccountKeyAsync(Stream body)
    {
        DefaultHttpContext context = new();
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = LoginPath;
        context.Request.ContentType = "application/json";
        context.Request.Body = body;
        context.Response.Body = new MemoryStream();
        bool reached = false;
        ListLogger<AccountKeyMiddleware> logger = new();
        AccountKeyMiddleware middleware = new(
            _ =>
            {
                reached = true;
                return Task.CompletedTask;
            },
            Options.Create(new AuthRateLimitOptions()),
            new StatusOnlyProblemDetails(),
            logger);

        await middleware.InvokeAsync(context);
        return (context, reached, logger);
    }

    private sealed class ThrowingStream(Exception exception) : MemoryStream
    {
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => throw exception;

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => throw exception;

        public override int Read(byte[] buffer, int offset, int count) => throw exception;
    }

    private sealed class StatusOnlyProblemDetails : IProblemDetailsService
    {
        public ValueTask WriteAsync(ProblemDetailsContext context) => ValueTask.CompletedTask;
    }

    private sealed class FailingGuard : IAuthTimingGuard
    {
        public Task<CredentialCheck> CheckPasswordAsync(string password, string? storedHash, bool accountUsable, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task WarmUpAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("hasher misconfigured");
    }

    internal sealed class ListLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
