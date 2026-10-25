namespace Auth.Api.Endpoints;

/// <summary>Configuration section <c>OAuth</c> (T19).</summary>
internal sealed class OAuthOptions
{
    public const string SectionName = "OAuth";

    /// <summary>
    /// Absolute URL of our login UI (on our domain). /authorize sends users without a session there with
    /// <c>returnTo</c> = the relative /api/v1/oauth/authorize path and query to come back to. Unset: /authorize answers
    /// login_required on our domain instead.
    /// </summary>
    public Uri? LoginUrl { get; set; }

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

        return this;
    }
}
