using Auth.Services;
using Auth.Services.Passwords;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Auth.UnitTests.Passwords;

/// <summary>
/// The password must never appear in logs, exception messages or anything the services return.
/// The services are resolved from DI with an in-memory log sink capturing every level, then every operation, including
/// failing ones, runs with a recognizable probe password.
/// </summary>
public sealed class PasswordSecrecyTests : IDisposable
{
    private const string Probe = "Probe-Secret-7f3a9c!Zq";

    private readonly InMemoryLoggerProvider sink = new();
    private readonly ServiceProvider provider;

    public PasswordSecrecyTests()
    {
        ServiceCollection services = new();
        services.AddLogging(logging => logging.AddProvider(sink).SetMinimumLevel(LogLevel.Trace));
        services.AddSingleton(Argon2PasswordHasherTests.FastOptions);
        services.AddPasswordServices();
        provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });
    }

    [Fact]
    public void Probe_password_never_reaches_logs_exceptions_or_outputs()
    {
        IPasswordHasher hasher = provider.GetRequiredService<IPasswordHasher>();
        IPasswordPolicy policy = provider.GetRequiredService<IPasswordPolicy>();
        List<string> outputs = [];
        List<Exception> exceptions = [];

        string stored = hasher.Hash(Probe);
        outputs.Add(stored);
        outputs.Add(hasher.Verify(Probe, stored).ToString());
        outputs.Add(hasher.Verify(Probe + "x", stored).ToString());
        outputs.Add(hasher.Verify(Probe, Probe).ToString());
        outputs.Add(hasher.Verify(Probe, "$argon2id$v=19$m=1024,t=1,p=1$" + Probe + "$" + Probe).ToString());
        outputs.AddRange(policy.Validate(Probe, Probe + "@example.test").Select(v => v.ToString()));
        outputs.AddRange(policy.Validate(Probe[..5], null).Select(v => v.ToString()));

        Capture(exceptions, () => hasher.Hash(null!));
        Capture(exceptions, () => hasher.Verify(null!, stored));
        Capture(exceptions, () => policy.Validate(null!, Probe));

        Assert.Equal(3, exceptions.Count);
        Assert.All(exceptions, ex => Assert.DoesNotContain(Probe, ex.ToString(), StringComparison.Ordinal));
        Assert.All(outputs, output => Assert.DoesNotContain(Probe, output, StringComparison.OrdinalIgnoreCase));
        Assert.All(sink.Messages, message => Assert.DoesNotContain(Probe, message, StringComparison.Ordinal));
    }

    [Fact]
    public void Registered_services_are_singletons_and_keep_test_options()
    {
        Assert.Same(provider.GetRequiredService<IPasswordHasher>(), provider.GetRequiredService<IPasswordHasher>());
        Assert.StartsWith("$argon2id$v=19$m=1024,t=1,p=1$", provider.GetRequiredService<IPasswordHasher>().Hash("violet-canyon-7319"), StringComparison.Ordinal);
    }

    public void Dispose()
    {
        provider.Dispose();
        sink.Dispose();
    }

    private static void Capture(List<Exception> exceptions, Action action)
    {
        try
        {
            action();
        }
        catch (ArgumentException ex)
        {
            exceptions.Add(ex);
        }
    }

    /// <summary>Records every formatted message and exception text written by any logger.</summary>
    private sealed class InMemoryLoggerProvider : ILoggerProvider
    {
        private readonly List<string> messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (messages)
                {
                    return [.. messages];
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => new Logger(this);

        public void Dispose()
        {
        }

        private void Add(string message)
        {
            lock (messages)
            {
                messages.Add(message);
            }
        }

        private sealed class Logger(InMemoryLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                owner.Add(formatter(state, exception) + " " + exception);
        }
    }
}
