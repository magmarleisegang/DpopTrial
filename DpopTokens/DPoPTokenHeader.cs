using System.Text.Json.Serialization;

namespace DpopTokens;

public class DPoPTokenHeader(string alg, DPoPJwk jwk)
{
    public string typ = "dpop+jwt";

    [JsonConstructor]
    public DPoPTokenHeader()
        : this(string.Empty, null)
    {
    }

    [JsonPropertyName("alg")]
    public string KeyAlgorithm { get; set; } = alg;

    [JsonPropertyName("jwk")]
    public DPoPJwk JsonWebKey { get; set; } = jwk;
}
