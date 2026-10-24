using System.Text.Json.Serialization;

namespace Auth.Contracts.Responses;

/// <summary>The JSON Web Key Set served at <c>/.well-known/jwks.json</c> (RFC 7517). Public keys only.</summary>
public sealed record JwksDocument([property: JsonPropertyName("keys")] IReadOnlyList<JsonWebKeyDto> Keys);

/// <summary>
/// One public signing key (RFC 7517/7518). EC keys set <see cref="Crv"/>, <see cref="X"/> and <see cref="Y"/>;
/// RSA keys set <see cref="N"/> and <see cref="E"/>. This type has no private-key members by design.
/// </summary>
public sealed record JsonWebKeyDto(
    [property: JsonPropertyName("kty")] string Kty,
    [property: JsonPropertyName("use")] string Use,
    [property: JsonPropertyName("kid")] string Kid,
    [property: JsonPropertyName("alg")] string Alg,
    [property: JsonPropertyName("crv"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Crv,
    [property: JsonPropertyName("x"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? X,
    [property: JsonPropertyName("y"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Y,
    [property: JsonPropertyName("n"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? N,
    [property: JsonPropertyName("e"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? E);
