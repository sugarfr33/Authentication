using Auth.Api.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Auth.IntegrationTests.Api;

/// <summary>
/// T11 audit LOW-D: the per-account key is read from a JSON body only, so no rate-limited endpoint may bind a form
/// body (a form-encoded email would bypass the account limit).
/// </summary>
[Collection(ApiTestGroup.Name)]
public sealed class RateLimitedEndpointTests(ApiFixture api)
{
    [Fact]
    public void Rate_limited_endpoints_accept_JSON_bodies_only_and_never_bind_forms()
    {
        AuthRateLimitOptions limits = api.Factory.Services.GetRequiredService<IOptions<AuthRateLimitOptions>>().Value;
        List<RouteEndpoint> limited = api.Factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(e => limits.Paths.ContainsKey("/" + e.RoutePattern.RawText?.Trim('/')))
            .ToList();

        Assert.Contains(limited, e => e.RoutePattern.RawText == "/api/v1/auth/register");
        Assert.Contains(limited, e => e.RoutePattern.RawText == "/api/v1/auth/verify-email");
        Assert.All(limited, endpoint =>
        {
            Assert.Empty(endpoint.Metadata.OfType<IFromFormMetadata>());
            foreach (IAcceptsMetadata accepts in endpoint.Metadata.OfType<IAcceptsMetadata>())
            {
                Assert.All(accepts.ContentTypes, type => Assert.Equal("application/json", type));
            }
        });
    }
}
