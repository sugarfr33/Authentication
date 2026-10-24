namespace Auth.Api.Endpoints;

/// <summary>
/// A group of /api/v1 endpoints. Program.cs maps every registered module under the versioned group, so endpoints go
/// through routing, CORS, authentication, CSRF protection and authorization. The real modules arrive with T13.
/// </summary>
public interface IEndpointModule
{
    void Map(IEndpointRouteBuilder api);
}
