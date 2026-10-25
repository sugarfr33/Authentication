using System.Reflection;
using System.Reflection.Emit;
using Auth.Services.ClientApplications;

namespace Auth.ArchitectureTests;

/// <summary>
/// T18 criterion, enforced (T19 arch review): IClientSessionService.StartAsync trusts the user id it is given, so the only
/// code that may call it is the OAuth service, after a verified authorization-code exchange. The IL of every method in
/// Auth.Services and Auth.Api (compiler-generated async state machines included) is scanned for call sites.
/// </summary>
public class SessionStartCallSiteTests
{
    private static readonly Dictionary<short, OpCode> OpCodesByValue = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(o => o.Value);

    [Fact]
    public void Only_the_OAuth_service_starts_client_application_sessions()
    {
        MethodInfo start = typeof(IClientSessionService).GetMethod(nameof(IClientSessionService.StartAsync))!;

        Assert.Equal(["Auth.Services.OAuth.OAuthService"], CallersOf(start));
    }

    /// <summary>
    /// T19 fix review: the IssueAsync overload with a chosen family id could add a token to a live family if misused, so
    /// only the application-session start (which passes the id the exchange recorded on the code) may call it.
    /// </summary>
    [Fact]
    public void Only_the_client_session_start_issues_a_family_with_a_chosen_id()
    {
        MethodInfo issueWithFamily = typeof(Auth.Services.Tokens.IRefreshTokenService).GetMethods()
            .Single(m => m.Name == nameof(Auth.Services.Tokens.IRefreshTokenService.IssueAsync) && m.GetParameters().Any(p => p.ParameterType == typeof(Guid) && p.Name == "familyId"));

        Assert.Equal(["Auth.Services.ClientApplications.ClientSessionService"], CallersOf(issueWithFamily));
    }

    private static string[] CallersOf(MethodInfo target)
    {
        Assembly[] scanned = [typeof(Auth.Services.AssemblyMarker).Assembly, typeof(Auth.Api.AssemblyMarker).Assembly];
        return [.. scanned
            .SelectMany(a => a.GetTypes())
            .SelectMany(t => t.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
                .Where(m => Calls(m, target))
                .Select(_ => OuterMost(t).FullName!))
            .Distinct()
            .Order(StringComparer.Ordinal)];
    }

    [Fact]
    public void The_scanner_finds_a_known_call_site()
    {
        // Guards the scanner itself: the registry calls the origin provider's Invalidate.
        MethodInfo invalidate = typeof(IClientApplicationOriginProvider).GetMethod(nameof(IClientApplicationOriginProvider.Invalidate))!;

        Assert.Contains(
            typeof(IClientSessionService).Assembly.GetTypes(),
            t => t.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly).Any(m => Calls(m, invalidate)));
    }

    /// <summary>
    /// T20 review (arch M4): every Auth.Services type that revokes refresh families (IRefreshTokenService.Revoke* or
    /// IRefreshTokenRepository.Revoke*) also publishes SessionEnded, so listeners (single logout, a future back-channel)
    /// never miss an ending. The exceptions are explicit, each with its reason.
    /// </summary>
    [Fact]
    public void Every_type_that_revokes_sessions_publishes_SessionEnded_or_is_an_explicit_exception()
    {
        Dictionary<string, string> silentByDesign = new(StringComparer.Ordinal)
        {
            ["Auth.Services.Tokens.RefreshTokenService"] = "the revocation primitive; its reuse revocation is published by SessionRefresher",
            ["Auth.Services.Tokens.SessionCap"] = "cap eviction is a consequence of starting a new session, not an ending the user asked for",
            ["Auth.Services.Security.SingleLogoutListener"] = "it is the listener reacting to SessionEnded",
        };
        Assembly services = typeof(Auth.Services.AssemblyMarker).Assembly;
        Type refreshService = typeof(Auth.Services.Tokens.IRefreshTokenService);
        Type refreshRepository = typeof(Auth.DAL.Repositories.IRefreshTokenRepository);
        MethodInfo publish = typeof(Auth.Services.Security.ISessionEndedPublisher).GetMethod(nameof(Auth.Services.Security.ISessionEndedPublisher.PublishAsync))!;

        string[] revokers = [.. services.GetTypes()
            .Where(t => AllMethods(t).Any(m => CallsAny(m, called => (called.DeclaringType == refreshService || called.DeclaringType == refreshRepository)
                && called.Name.StartsWith("Revoke", StringComparison.Ordinal))))
            .Select(t => OuterMost(t).FullName!)
            .Distinct()
            .Order(StringComparer.Ordinal)];
        string[] publishers = [.. services.GetTypes()
            .Where(t => AllMethods(t).Any(m => Calls(m, publish)))
            .Select(t => OuterMost(t).FullName!)
            .Distinct()];

        Assert.Contains("Auth.Services.Accounts.SignInService", revokers);
        string[] unpublished = [.. revokers.Where(r => !publishers.Contains(r) && !silentByDesign.ContainsKey(r))];
        Assert.True(unpublished.Length == 0, "Revoke without SessionEnded: " + string.Join(", ", unpublished));
        Assert.All(silentByDesign.Keys, k => Assert.Contains(k, revokers));
    }

    private static MethodInfo[] AllMethods(Type type) =>
        type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);

    private static Type OuterMost(Type type)
    {
        while (type.DeclaringType is Type outer)
        {
            type = outer;
        }

        return type;
    }

    private static bool Calls(MethodInfo method, MethodInfo target) =>
        CallsAny(method, called => called.Name == target.Name && called.DeclaringType == target.DeclaringType
            && called.GetParameters().Select(p => p.ParameterType).SequenceEqual(target.GetParameters().Select(p => p.ParameterType)));

    private static bool CallsAny(MethodInfo method, Func<MethodBase, bool> match)
    {
        byte[]? il = method.GetMethodBody()?.GetILAsByteArray();
        if (il is null)
        {
            return false;
        }

        int position = 0;
        while (position < il.Length)
        {
            short value = il[position] == 0xFE ? (short)(0xFE00 | il[position + 1]) : il[position];
            OpCode opCode = OpCodesByValue[value];
            position += opCode.Size;
            if ((opCode == OpCodes.Call || opCode == OpCodes.Callvirt) && Resolves(method.Module, BitConverter.ToInt32(il, position), match))
            {
                return true;
            }

            position += OperandSize(opCode, il, position);
        }

        return false;
    }

    private static bool Resolves(Module module, int token, Func<MethodBase, bool> match)
    {
        try
        {
            return module.ResolveMethod(token) is MethodInfo called && match(called);
        }
        catch (ArgumentException)
        {
            // Generic context needed to resolve: not a call to the (non-generic) target.
            return false;
        }
    }

    private static int OperandSize(OpCode opCode, byte[] il, int position) => opCode.OperandType switch
    {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        OperandType.InlineSwitch => 4 + (4 * BitConverter.ToInt32(il, position)),
        _ => 4,
    };
}
