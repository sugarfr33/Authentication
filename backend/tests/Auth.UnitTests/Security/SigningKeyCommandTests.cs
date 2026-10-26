using Auth.Api.Hosting;
using Auth.Services.Common;
using Auth.Services.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.UnitTests.Security;

/// <summary>T29: the signing-key maintenance command parses its arguments, calls the rotation service and maps errors.</summary>
public sealed class SigningKeyCommandTests
{
    private static readonly DateTime Now = new(2026, 10, 26, 10, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void The_command_is_recognised_only_as_the_first_argument_and_its_options_never_reach_the_host()
    {
        string[] args = ["signing-key", "add", "signingkey2", "--environment", "Production", "--reference", "signingkey2", "--algorithm", "RS256", "--urls=http://x"];

        Assert.True(SigningKeyCommand.IsCommand(args));
        Assert.False(SigningKeyCommand.IsCommand(["--environment", "Production", "signing-key"]));
        Assert.Equal(["--environment", "Production", "--urls=http://x"], SigningKeyCommand.HostArgs(args));
        Assert.Equal(["--urls", "x"], SigningKeyCommand.HostArgs(["--urls", "x"]));
    }

    [Fact]
    public async Task Add_calls_the_rotation_with_the_kid_reference_and_algorithm_and_activates_now_by_default()
    {
        FakeRotation rotation = new();

        (int code, string output, string error) = await RunAsync(rotation, "signing-key", "add", "signingkey1", "--reference", "signingkey1");

        Assert.Equal(0, code);
        Assert.Empty(error);
        Assert.Equal(("signingkey1", "ES256", "signingkey1", Now), rotation.Call);
        Assert.Contains("'signingkey1' (ES256) is published and signs from 2026-10-26T10:00:00Z", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_explicit_activation_time_is_read_as_UTC()
    {
        FakeRotation rotation = new();

        (int code, _, _) = await RunAsync(rotation, "signing-key", "add", "k2", "--reference", "k2", "--activate-at", "2026-10-27T08:30:00Z");

        Assert.Equal(0, code);
        Assert.Equal(new DateTime(2026, 10, 27, 8, 30, 0, DateTimeKind.Utc), rotation.Call!.Value.ActivateAt);
        Assert.Equal(DateTimeKind.Utc, rotation.Call.Value.ActivateAt.Kind);
    }

    [Theory]
    [InlineData("signing-key")]
    [InlineData("signing-key", "remove", "k1", "--reference", "k1")]
    [InlineData("signing-key", "add")]
    [InlineData("signing-key", "add", "--reference", "k1")]
    [InlineData("signing-key", "add", "k1")]
    [InlineData("signing-key", "add", "k1", "--reference")]
    [InlineData("signing-key", "add", "k1", "--reference", "k1", "--algorithm", "HS256")]
    [InlineData("signing-key", "add", "k1", "--reference", "k1", "--activate-at", "tomorrow-ish")]
    public async Task Usage_errors_exit_with_2_and_never_touch_the_keys(params string[] args)
    {
        FakeRotation rotation = new();

        (int code, string output, string error) = await RunAsync(rotation, args);

        Assert.Equal(2, code);
        Assert.Empty(output);
        Assert.Contains("Usage: Auth.Api signing-key add", error, StringComparison.Ordinal);
        Assert.Null(rotation.Call);
    }

    [Fact]
    public async Task A_second_key_without_an_activation_time_is_refused_with_the_earliest_allowed_time()
    {
        FakeRotation rotation = new() { Failure = new ArgumentOutOfRangeException("activateAtUtc", "too soon") };

        (int code, string output, string error) = await RunAsync(rotation, "signing-key", "add", "k2", "--reference", "k2");

        Assert.Equal(1, code);
        Assert.Empty(output);
        Assert.Contains("Pass --activate-at", error, StringComparison.Ordinal);
        Assert.Contains("15.5 minutes", error, StringComparison.Ordinal);
        Assert.Contains("2026-10-26T10:16:30Z", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_missing_secret_or_duplicate_kid_is_reported_and_exits_with_1()
    {
        FakeRotation rotation = new() { Failure = new InvalidOperationException("The private key of signing key 'k3' was not found in the secret store.") };

        (int code, _, string error) = await RunAsync(rotation, "signing-key", "add", "k3", "--reference", "k3");

        Assert.Equal(1, code);
        Assert.Contains("The signing key was not added: The private key of signing key 'k3' was not found", error, StringComparison.Ordinal);
    }

    private static async Task<(int Code, string Output, string Error)> RunAsync(FakeRotation rotation, params string[] args)
    {
        ServiceCollection services = new();
        services.AddSingleton<ISigningKeyRotation>(rotation);
        services.AddSingleton<IClock>(new FixedClock());
        services.AddSingleton(new TokenOptions { Issuer = "https://auth.example.test" });
        await using ServiceProvider provider = services.BuildServiceProvider();
        using StringWriter output = new();
        using StringWriter error = new();

        int code = await SigningKeyCommand.RunAsync(provider, args, output, error, CancellationToken.None);
        return (code, output.ToString(), error.ToString());
    }

    private sealed class FixedClock : IClock
    {
        public DateTime UtcNow => Now;
    }

    private sealed class FakeRotation : ISigningKeyRotation
    {
        public (string Kid, string Algorithm, string Reference, DateTime ActivateAt)? Call { get; private set; }

        public Exception? Failure { get; init; }

        public Task AddKeyAsync(string kid, string algorithm, string privateKeyReference, DateTime activateAtUtc, CancellationToken cancellationToken)
        {
            if (Failure is not null)
            {
                return Task.FromException(Failure);
            }

            Call = (kid, algorithm, privateKeyReference, activateAtUtc);
            return Task.CompletedTask;
        }

        public Task<int> RetireSupersededAsync(CancellationToken cancellationToken) => Task.FromResult(0);
    }
}
