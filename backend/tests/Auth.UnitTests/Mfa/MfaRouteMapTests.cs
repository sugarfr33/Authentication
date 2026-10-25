using Auth.Api.Endpoints;
using Auth.Api.RateLimiting;
using Auth.Api.Security;
using Auth.Services.Mfa;
using Auth.Services.Tokens;
using Auth.UnitTests.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.UnitTests.Mfa;

/// <summary>T21: every MFA route declares its access, has a rate-limit kind, and none opts out of antiforgery.</summary>
public class MfaRouteMapTests
{
    [Fact]
    public async Task Every_MFA_route_is_rate_limited_declares_its_access_and_keeps_antiforgery()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Services.AddSingleton(Stubs.Create<IMfaService>().Instance);
        builder.Services.AddSingleton(Stubs.Create<ITokenService>().Instance);
        builder.Services.AddSingleton(Stubs.Create<ICookieWriter>().Instance);
        builder.Services.AddAntiforgery();
        await using WebApplication app = builder.Build();
        new MfaEndpoints().Map(app.MapGroup("/api/v1"));
        RouteEndpoint[] endpoints = [.. ((IEndpointRouteBuilder)app).DataSources.SelectMany(d => d.Endpoints).OfType<RouteEndpoint>()];
        AuthRateLimitOptions limits = new();

        Assert.Equal(5, endpoints.Length);
        Assert.All(endpoints, e => Assert.NotNull(limits.Resolve(new PathString("/" + e.RoutePattern.RawText!.TrimStart('/')))));
        Assert.All(endpoints, e => Assert.True(e.Metadata.GetMetadata<IAllowAnonymous>() is not null || e.Metadata.GetOrderedMetadata<IAuthorizeData>().Count > 0));
        Assert.Equal(["/api/v1/auth/mfa/verify"], endpoints.Where(e => e.Metadata.GetMetadata<IAllowAnonymous>() is not null).Select(e => "/" + e.RoutePattern.RawText!.TrimStart('/')));
        Assert.DoesNotContain(endpoints, e => e.Metadata.GetMetadata<Microsoft.AspNetCore.Antiforgery.IAntiforgeryMetadata>() is { RequiresValidation: false });
    }
}
