using System.Globalization;
using Auth.Services.Common;
using Auth.Services.Tokens;

namespace Auth.Api.Hosting;

/// <summary>
/// T29: the opt-in maintenance command <c>signing-key add &lt;kid&gt; [--algorithm ES256|RS256] --reference &lt;secret&gt;
/// [--activate-at &lt;UTC time&gt;]</c>. It registers a signing key through <see cref="ISigningKeyRotation.AddKeyAsync"/>
/// (so the overlap rule applies) with the host's normal configuration, database and secret store, then exits. The web
/// host is built for its services but never started: no listener, no hosted service. Any other arguments (for example
/// <c>--environment Production</c>) still configure the host.
/// </summary>
internal static class SigningKeyCommand
{
    public const string Name = "signing-key";

    private const string Usage =
        "Usage: Auth.Api signing-key add <kid> --reference <secret name> [--algorithm ES256|RS256] [--activate-at <UTC time, ISO 8601>]";

    private static readonly string[] Algorithms = ["ES256", "RS256"];

    /// <summary>True when the process was started to run this command instead of the web host.</summary>
    public static bool IsCommand(string[] args) => args.Length > 0 && string.Equals(args[0], Name, StringComparison.Ordinal);

    /// <summary>The arguments for the host: the command and its own options removed.</summary>
    public static string[] HostArgs(string[] args) => IsCommand(args) ? Parse(args).HostArgs : args;

    /// <summary>Runs the command. Exit code 0 on success, 1 when the key was refused, 2 for a usage error.</summary>
    public static async Task<int> RunAsync(IServiceProvider services, string[] args, TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        ParsedCommand command = Parse(args);
        if (command.Problem is not null)
        {
            await error.WriteLineAsync(command.Problem);
            await error.WriteLineAsync(Usage);
            return 2;
        }

        await using AsyncServiceScope scope = services.CreateAsyncScope();
        DateTime now = scope.ServiceProvider.GetRequiredService<IClock>().UtcNow;
        DateTime activateAt = command.ActivateAtUtc ?? now;
        try
        {
            await scope.ServiceProvider.GetRequiredService<ISigningKeyRotation>()
                .AddKeyAsync(command.Kid, command.Algorithm, command.Reference, activateAt, cancellationToken);
        }
        catch (ArgumentOutOfRangeException ex) when (ex.ParamName == "activateAtUtc")
        {
            TimeSpan overlap = scope.ServiceProvider.GetRequiredService<TokenOptions>().KeyOverlap;
            DateTime earliest = now + overlap;
            await error.WriteLineAsync(
                "A signing key is already published, so a new key must be published before it signs. Pass --activate-at with a UTC time at least "
                + overlap.TotalMinutes.ToString(CultureInfo.InvariantCulture) + " minutes from now, for example "
                + earliest.AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + ".");
            return 1;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            // These messages name the kid or the secret reference only, never key material.
            await error.WriteLineAsync("The signing key was not added: " + ex.Message);
            return 1;
        }

        DateTime signsFrom = activateAt < now ? now : activateAt;
        await output.WriteLineAsync(
            "Signing key '" + command.Kid + "' (" + command.Algorithm + ") is published and signs from "
            + signsFrom.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + " (UTC).");
        return 0;
    }

    internal static ParsedCommand Parse(string[] args)
    {
        List<string> hostArgs = [];
        string? kid = null;
        string? reference = null;
        string algorithm = "ES256";
        DateTime? activateAt = null;
        string? problem = null;

        if (args.Length < 2 || !string.Equals(args[1], "add", StringComparison.Ordinal))
        {
            problem = "Unknown or missing signing-key action; the only action is 'add'.";
        }
        else if (args.Length < 3 || args[2].StartsWith('-'))
        {
            problem = "Missing <kid>.";
        }
        else
        {
            kid = args[2];
        }

        for (int i = 3; i < args.Length; i++)
        {
            string token = args[i];
            string? value = i + 1 < args.Length ? args[i + 1] : null;
            switch (token)
            {
                case "--algorithm":
                case "--reference":
                case "--activate-at":
                    if (value is null || value.StartsWith("--", StringComparison.Ordinal))
                    {
                        problem ??= token + " needs a value.";
                        break;
                    }

                    i++;
                    if (token == "--algorithm")
                    {
                        algorithm = value;
                    }
                    else if (token == "--reference")
                    {
                        reference = value;
                    }
                    else if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime parsed))
                    {
                        activateAt = DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
                    }
                    else
                    {
                        problem ??= "--activate-at is not a date and time: " + value;
                    }

                    break;

                default:
                    // Not ours: a host option such as --environment Production, with its value when it has one.
                    hostArgs.Add(token);
                    if (token.StartsWith("--", StringComparison.Ordinal) && !token.Contains('=', StringComparison.Ordinal)
                        && value is not null && !value.StartsWith("--", StringComparison.Ordinal))
                    {
                        hostArgs.Add(value);
                        i++;
                    }

                    break;
            }
        }

        if (problem is null && string.IsNullOrWhiteSpace(reference))
        {
            problem = "Missing --reference <secret name>: the secret store entry that holds the private key PEM.";
        }

        if (problem is null && !Algorithms.Contains(algorithm, StringComparer.Ordinal))
        {
            problem = "--algorithm must be ES256 or RS256.";
        }

        return new ParsedCommand(kid ?? string.Empty, algorithm, reference ?? string.Empty, activateAt, problem, [.. hostArgs]);
    }

    internal sealed record ParsedCommand(string Kid, string Algorithm, string Reference, DateTime? ActivateAtUtc, string? Problem, string[] HostArgs);
}
