namespace Auth.Services.OAuth;

/// <summary>Configuration section <c>OAuth</c> (T19). T20 adds the shared-domain settings here.</summary>
public sealed class OAuthOptions
{
    public const string SectionName = "OAuth";

    /// <summary>
    /// Absolute URL of our login UI (on our domain). /authorize sends users without a session there with
    /// <c>returnTo</c> = the relative /api/v1/oauth/authorize path and query to come back to. Unset: /authorize answers
    /// login_required on our domain instead.
    /// </summary>
    public Uri? LoginUrl { get; set; }

    /// <summary>How long an authorization code can be redeemed (default 60 s, 10 s to 10 min; RFC 6749 recommends at most 10 min).</summary>
    public TimeSpan CodeLifetime { get; set; } = TimeSpan.FromSeconds(60);

    public OAuthOptions Validated(bool requireHttps)
    {
        if (LoginUrl is not null
            && (!LoginUrl.IsAbsoluteUri
                || !(LoginUrl.Scheme == Uri.UriSchemeHttps || (!requireHttps && LoginUrl.Scheme == Uri.UriSchemeHttp && LoginUrl.IsLoopback))
                || LoginUrl.UserInfo.Length > 0
                || LoginUrl.Fragment.Length > 0))
        {
            throw new InvalidOperationException("OAuth:LoginUrl must be an absolute https URL without user info or fragment (http only for localhost in Development).");
        }

        if (CodeLifetime < TimeSpan.FromSeconds(10) || CodeLifetime > TimeSpan.FromMinutes(10))
        {
            throw new InvalidOperationException("OAuth:CodeLifetime must be between 00:00:10 and 00:10:00.");
        }

        return this;
    }
}
