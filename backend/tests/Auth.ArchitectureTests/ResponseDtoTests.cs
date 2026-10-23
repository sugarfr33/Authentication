using System.Reflection;

namespace Auth.ArchitectureTests;

/// <summary>No response DTO may expose a token, hash, secret or password, not even through a nested contract type.</summary>
public class ResponseDtoTests
{
    private const string ResponsesNamespace = "Auth.Contracts.Responses";

    private static readonly string[] ForbiddenNameParts = ["Token", "Hash", "Secret", "Password"];

    private static readonly Assembly Contracts = typeof(Auth.Contracts.AssemblyMarker).Assembly;

    [Fact]
    public void Response_types_are_found()
    {
        IEnumerable<string> names = ResponseTypes().Select(t => t.Name);

        Assert.Contains("UserProfileResponse", names);
        Assert.Contains("SessionResponse", names);
        Assert.Contains("MfaEnrollResponse", names);
        Assert.Contains("ClientApplicationResponse", names);
    }

    [Fact]
    public void Response_types_have_no_token_hash_secret_or_password_properties()
    {
        IEnumerable<string> offenders = ResponseTypes().SelectMany(t => FindForbiddenProperties(t, []));

        Assert.Empty(offenders);
    }

    [Fact]
    public void Scan_detects_forbidden_property_names()
    {
        IEnumerable<string> offenders = FindForbiddenProperties(typeof(LeakyResponse), []);

        Assert.Equal(["LeakyResponse.RefreshToken", "LeakyResponse.PasswordHash", "LeakyResponse.ClientSecret"], offenders);
    }

    private static IEnumerable<Type> ResponseTypes() =>
        Contracts.GetExportedTypes().Where(t => t.Namespace == ResponsesNamespace);

    /// <summary>Checks the type's property names, then recurses into property types (and their generic arguments) declared in Auth.Contracts.</summary>
    private static IEnumerable<string> FindForbiddenProperties(Type type, HashSet<Type> visited)
    {
        if (!visited.Add(type))
        {
            yield break;
        }

        foreach (PropertyInfo property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (ForbiddenNameParts.Any(part => property.Name.Contains(part, StringComparison.OrdinalIgnoreCase)))
            {
                yield return type.Name + "." + property.Name;
            }

            foreach (Type nested in ContractTypesIn(property.PropertyType))
            {
                foreach (string offender in FindForbiddenProperties(nested, visited))
                {
                    yield return offender;
                }
            }
        }
    }

    private static IEnumerable<Type> ContractTypesIn(Type type)
    {
        IEnumerable<Type> candidates = type.IsGenericType ? type.GetGenericArguments().Prepend(type) : [type];

        return candidates.Where(t => t.Assembly == Contracts);
    }

    private sealed record LeakyResponse(string RefreshToken, string PasswordHash, string ClientSecret, Guid Id);
}
