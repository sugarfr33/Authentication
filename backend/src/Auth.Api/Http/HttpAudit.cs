using System.Diagnostics;
using Auth.Services.Common;

namespace Auth.Api.Http;

/// <summary>Who is asking, as the audit log records it: client IP, user agent and the trace id for correlation.</summary>
internal static class HttpAudit
{
    public static AuditContext From(HttpContext http) => new(
        http.Connection.RemoteIpAddress?.ToString(),
        http.Request.Headers.UserAgent.ToString(),
        Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier);
}
