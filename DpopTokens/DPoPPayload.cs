using System.Text.Json.Serialization;

namespace DpopTokens;

public class DPoPPayload(Guid tokenIdentifier, string httpMethod, string intendedUri, DateTimeOffset tokenCreationDate)
{
    [JsonConstructor]
    public DPoPPayload()
        : this(Guid.Empty, string.Empty, string.Empty, DateTimeOffset.MinValue)
    {

    }

    [JsonPropertyName("jti")]
    public Guid TokenIdentifier { get; set; } = tokenIdentifier;

    [JsonPropertyName("htm")]
    public string HttpMethod { get; set; } = httpMethod;

    [JsonPropertyName("htu")]
    public string IntendedUri { get; set; } = intendedUri;

    [JsonPropertyName("iat")]
    public DateTimeOffset TokenCreationDate { get; set; } = tokenCreationDate;
}
