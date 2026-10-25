using Auth.Api.Hosting;
using Auth.Api.Logging;
using Microsoft.Extensions.Configuration;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace Auth.UnitTests.Logging;

/// <summary>T17 (T09 review): exceptions reach a sink only as redacted copies; configured sinks are refused.</summary>
public class ExceptionScrubbingTests
{
    private const string Password = "hunter2-Violet-7319";
    private const string RefreshToken = "q2V7nYx0Rk3sJ9bT4uLmW8cZ1aP6dE5fG0hI2jK7lMn";
    private const string Jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl";
    private const string Hash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo";

    [Fact]
    public void Secrets_in_messages_inner_exceptions_and_data_never_reach_the_sink()
    {
        InvalidOperationException inner = new("Login for password=" + Password + " with hash " + Hash);
        Exception root = new AggregateException(
            "Refresh failed for token " + RefreshToken + " and Authorization: Bearer " + Jwt,
            inner,
            new ArgumentException("connection string Server=db;Password=" + Password + ";"));
        root.Data["apiKey"] = Password;
        root.Data["note"] = RefreshToken;

        LogEvent emitted = Emit(root);

        string rendered = emitted.Exception!.ToString();
        foreach (string secret in new[] { Password, RefreshToken, Jwt, Hash, "c2lnbmF0dXJlLXZhbHVl" })
        {
            Assert.DoesNotContain(secret, rendered, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, emitted.Exception.Message, StringComparison.Ordinal);
        }

        Assert.Empty(emitted.Exception.Data);
        Assert.Contains("System.AggregateException", rendered, StringComparison.Ordinal);
        Assert.Contains("System.InvalidOperationException", rendered, StringComparison.Ordinal);
        Assert.Contains("System.ArgumentException", rendered, StringComparison.Ordinal);
        Assert.Contains(LogRedaction.Mask, rendered, StringComparison.Ordinal);
    }

    [Fact]
    public void The_stack_trace_is_kept_and_redacted()
    {
        Exception thrown;
        try
        {
            throw new InvalidOperationException("token=" + RefreshToken);
        }
        catch (InvalidOperationException ex)
        {
            thrown = ex;
        }

        Exception scrubbed = Emit(thrown).Exception!;

        Assert.Contains(nameof(The_stack_trace_is_kept_and_redacted), scrubbed.StackTrace, StringComparison.Ordinal);
        Assert.DoesNotContain(RefreshToken, scrubbed.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Events_without_an_exception_pass_unchanged()
    {
        LogEvent plain = Event(null);
        CapturingSink inner = new();

        new ExceptionScrubbingSink(inner).Emit(plain);

        Assert.Same(plain, Assert.Single(inner.Events));
    }

    [Theory]
    [InlineData("3f2504e0-4f89-11d3-9a0c-0305e82c3301")]
    [InlineData("4bf92f3577b34da6a3ce929d0e0e4736")]
    [InlineData("Microsoft.AspNetCore.Hosting.Diagnostics")]
    public void Identifiers_stay_readable(string value) => Assert.Equal(value, LogRedaction.Redact(value));

    [Fact]
    public void The_original_exception_type_is_kept_as_a_property_for_structured_sinks()
    {
        LogEvent emitted = Emit(new TimeoutException("slow"));

        Assert.Equal("\"System.TimeoutException\"", emitted.Properties[ExceptionScrubbingSink.ExceptionTypeProperty].ToString());
    }

    [Theory]
    [InlineData("StatusCode=500", "StatusCode=500")]
    [InlineData("SessionId=3f2504e0-4f89-11d3-9a0c-0305e82c3301", "SessionId=3f2504e0-4f89-11d3-9a0c-0305e82c3301")]
    [InlineData("TokenType=Bearer", "TokenType=Bearer")]
    [InlineData("newPassword=hunter2", "newPassword=[REDACTED]")]
    [InlineData("refresh_token=abc&state=1", "refresh_token=[REDACTED]&state=1")]
    [InlineData("?code=xyz&state=1", "?code=[REDACTED]&state=1")]
    [InlineData("Cookie: __Host-access=abc", "Cookie=[REDACTED]")]
    public void Pairs_are_masked_by_their_exact_key_role_only(string input, string expected) =>
        Assert.Equal(expected, LogRedaction.Redact(input));

    [Fact]
    public void Opaque_runs_are_masked_from_43_characters()
    {
        string run42 = new('a', 42);
        string run43 = new('b', 43);

        Assert.Equal(run42, LogRedaction.Redact(run42));
        Assert.Equal(LogRedaction.Mask, LogRedaction.Redact(run43));
    }

    [Fact]
    public void A_pathological_text_is_handled_within_the_match_timeout()
    {
        string hostile = string.Concat(Enumerable.Repeat("a-", 200_000)) + "!";
        System.Diagnostics.Stopwatch watch = System.Diagnostics.Stopwatch.StartNew();

        string result = LogRedaction.Redact(hostile);

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), "took " + watch.Elapsed);
        Assert.False(string.IsNullOrEmpty(result));
    }

    [Fact]
    public void Non_string_scalars_are_rendered_and_scrubbed()
    {
        LogEvent logEvent = new(
            DateTimeOffset.UtcNow,
            LogEventLevel.Information,
            null,
            new MessageTemplateParser().Parse("Calling {Target} with {Count}"),
            [
                new LogEventProperty("Target", new ScalarValue(new Uri("https://idp.example.test/cb?token=SecretValue1&state=1"))),
                new LogEventProperty("Count", new ScalarValue(3)),
            ]);

        new RedactionEnricher().Enrich(logEvent, null!);

        string target = logEvent.Properties["Target"].ToString();
        Assert.DoesNotContain("SecretValue1", target, StringComparison.Ordinal);
        Assert.Contains("state=1", target, StringComparison.Ordinal);
        Assert.Equal("3", logEvent.Properties["Count"].ToString());
    }

    [Fact]
    public void Log_sinks_declared_in_configuration_stop_the_app()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Serilog:WriteTo:0:Name"] = "File" })
            .Build();

        Assert.Throws<InvalidOperationException>(() => HostingGuards.EnsureNoConfiguredLogSinks(configuration));
        HostingGuards.EnsureNoConfiguredLogSinks(new ConfigurationBuilder().Build());
    }

    private static LogEvent Emit(Exception exception)
    {
        CapturingSink inner = new();
        new ExceptionScrubbingSink(inner).Emit(Event(exception));
        LogEvent emitted = Assert.Single(inner.Events);
        Assert.IsType<ScrubbedException>(emitted.Exception);
        return emitted;
    }

    private static LogEvent Event(Exception? exception) => new(
        DateTimeOffset.UtcNow,
        LogEventLevel.Error,
        exception,
        new MessageTemplateParser().Parse("Something failed"),
        [new LogEventProperty("Path", new ScalarValue("/api/v1/auth/login"))]);

    private sealed class CapturingSink : ILogEventSink
    {
        public List<LogEvent> Events { get; } = [];

        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }
}
