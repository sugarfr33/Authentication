using Auth.Contracts.Responses;
using Auth.Services.Tokens;
using Microsoft.Net.Http.Headers;

namespace Auth.Api.Endpoints;

internal static class WellKnownEndpoints
{
    public const string JwksPath = "/.well-known/jwks.json";

    /// <summary>Clients may cache the key set briefly; new keys are published well before they sign (plan A6).</summary>
    public const string JwksCacheControl = "public, max-age=300";

    /// <summary>Unversioned on purpose: the JWKS location is a protocol convention, not part of /api/v1.</summary>
    public static IEndpointRouteBuilder MapWellKnownEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(JwksPath, async (ISigningKeyProvider keys, HttpContext http, CancellationToken cancellationToken) =>
        {
            JwksDocument jwks = await keys.GetJwksAsync(cancellationToken);
            http.Response.Headers[HeaderNames.CacheControl] = JwksCacheControl;
            return Results.Json(jwks, contentType: "application/jwk-set+json");
        });

        return endpoints;
    }
}
