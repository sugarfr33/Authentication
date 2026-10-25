using Auth.Api.Security;
using Auth.Services.ClientApplications;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Auth.UnitTests.Security;

/// <summary>T10 review (c): the CORS policy carries the normalized origin, never the raw header.</summary>
public class CorsPolicyProviderTests
{
    [Theory]
    [InlineData("https://APP.Example.TEST")]
    [InlineData("https://app.example.test/")]
    [InlineData(" https://app.example.test ")]
    public async Task Policy_lists_the_normalized_origin(string rawOrigin)
    {
        ClientApplicationCorsPolicyProvider provider = new(
            new FixedOrigins("https://app.example.test"),
            Options.Create(new BrowserProtectionOptions()),
            new ProductionEnvironment());
        DefaultHttpContext context = new();
        context.Request.Headers.Origin = rawOrigin;

        CorsPolicy? policy = await provider.GetPolicyAsync(context, null);

        Assert.NotNull(policy);
        Assert.Equal(["https://app.example.test"], policy.Origins);
        Assert.True(policy.SupportsCredentials);
        Assert.False(policy.AllowAnyOrigin);
    }

    [Theory]
    [InlineData("https://evil.example.test")]
    [InlineData("*")]
    [InlineData("null")]
    public async Task Unknown_or_invalid_origin_gets_no_policy(string rawOrigin)
    {
        ClientApplicationCorsPolicyProvider provider = new(
            new FixedOrigins("https://app.example.test"),
            Options.Create(new BrowserProtectionOptions()),
            new ProductionEnvironment());
        DefaultHttpContext context = new();
        context.Request.Headers.Origin = rawOrigin;

        Assert.Null(await provider.GetPolicyAsync(context, null));
    }

    private sealed class FixedOrigins(params string[] origins) : IClientApplicationOriginProvider
    {
        private readonly HashSet<string> set = new(origins, StringComparer.Ordinal);

        public Task<IReadOnlySet<string>> GetAllowedOriginsAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlySet<string>>(set);

        public Task<bool> IsAllowedAsync(string origin, CancellationToken cancellationToken) => Task.FromResult(set.Contains(origin));

        public Task<ClientApplicationView?> FindActiveAsync(string? clientId, CancellationToken cancellationToken) => Task.FromResult<ClientApplicationView?>(null);

        public Task<ClientApplicationView?> MatchOriginAsync(string? clientId, string? origin, CancellationToken cancellationToken) => Task.FromResult<ClientApplicationView?>(null);

        public void Invalidate()
        {
        }
    }

    private sealed class ProductionEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;

        public string ApplicationName { get; set; } = "Auth.Api";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
