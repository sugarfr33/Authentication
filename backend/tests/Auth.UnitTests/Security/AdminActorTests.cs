using System.Security.Claims;
using Auth.Api.Endpoints;
using Auth.Contracts;

namespace Auth.UnitTests.Security;

/// <summary>
/// T21b FIX: the admin group filter refuses (403) any principal without a usable sub, because every guard rail
/// (self-lockout, privilege ceiling) treats a null actor as a trusted host caller.
/// </summary>
public sealed class AdminActorTests
{
    public static TheoryData<string?> Unusable() => [null, "", "not-a-guid", Guid.Empty.ToString()];

    [Theory]
    [MemberData(nameof(Unusable))]
    public void A_missing_or_unusable_sub_gives_no_actor(string? sub)
    {
        List<Claim> claims = [new Claim(AuthClaimTypes.Permission, AuthPermissions.UsersWrite)];
        if (sub is not null)
        {
            claims.Add(new Claim(AuthClaimTypes.Subject, sub));
        }

        ClaimsPrincipal user = new(new ClaimsIdentity(claims, "test"));

        Assert.Null(AdminEndpoints.ActorId(user));
    }

    [Fact]
    public void An_anonymous_principal_gives_no_actor() => Assert.Null(AdminEndpoints.ActorId(new ClaimsPrincipal()));

    [Fact]
    public void The_sub_claim_is_the_actor()
    {
        Guid id = Guid.NewGuid();
        ClaimsPrincipal user = new(new ClaimsIdentity([new Claim(AuthClaimTypes.Subject, id.ToString())], "test"));

        Assert.Equal(id, AdminEndpoints.ActorId(user));
    }
}
