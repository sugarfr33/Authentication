using Auth.Api.Endpoints;
using Auth.Api.RateLimiting;
using Auth.Services.ClientApplications;
using Auth.Services.OAuth;
using Auth.Services.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.UnitTests.OAuth;

/// <summary>
/// T19 arch review: every anonymous OAuth endpoint, as actually mapped, is covered by a rate-limit kind, so a new one
/// cannot ship unlimited. Also pins that /token is the endpoint that opts out of antiforgery (by metadata, not by path).
/// </summary>
public class OAuthRateLimitMapTests
{
    [Fact]
    public async Task Every_anonymous_OAuth_endpoint_has_a_rate_limit_kind()
    {
        IReadOnlyList<RouteEndpoint> endpoints = await MappedAsync();
        AuthRateLimitOptions limits = new();

        Assert.NotEmpty(endpoints);
        Assert.All(endpoints, e => Assert.NotNull(e.Metadata.GetMetadata<IAllowAnonymous>()));
        Assert.All(endpoints, e => Assert.True(limits.Resolve(new PathString("/" + e.RoutePattern.RawText!.TrimStart('/'))) is not null, e.RoutePattern.RawText));
    }

    [Fact]
    public async Task Only_the_token_endpoint_opts_out_of_antiforgery()
    {
        IReadOnlyList<RouteEndpoint> endpoints = await MappedAsync();

        string[] exempt = [.. endpoints
            .Where(e => e.Metadata.GetMetadata<Microsoft.AspNetCore.Antiforgery.IAntiforgeryMetadata>() is { RequiresValidation: false })
            .Select(e => "/" + e.RoutePattern.RawText!.TrimStart('/'))];

        Assert.Equal([OAuthEndpoints.TokenPath], exempt);
    }

    private static async Task<IReadOnlyList<RouteEndpoint>> MappedAsync()
    {
        // The handlers' services only need to be known for parameter binding; the endpoints are never invoked.
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Services.AddSingleton(Stubs.Create<IOAuthService>().Instance);
        builder.Services.AddSingleton(Stubs.Create<IClientApplicationOriginProvider>().Instance);
        builder.Services.AddSingleton<AccountRateLimiter>();
        builder.Services.AddSingleton<TokenOptions>();
        await using WebApplication app = builder.Build();
        new OAuthEndpoints(new OAuthOptions()).Map(app.MapGroup("/api/v1"));
        return [.. ((IEndpointRouteBuilder)app).DataSources.SelectMany(d => d.Endpoints).OfType<RouteEndpoint>()];
    }
}
