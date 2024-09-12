using System.Text.Json;
using System.Text.Json.Serialization;

namespace DpopTokens;

public class DPoPJwk
{
    public DPoPJwk(string kty, string modulus, string exponent)
    {
        this.Kty = kty;
        this.Modulus = modulus;
        this.Exponent = exponent;
    }

    [JsonConstructor]
    public DPoPJwk()
    {

    }

    [JsonPropertyName("kty")]
    public string Kty { get; set; }


    [JsonPropertyName("n")]
    public string Modulus { get; set; }

    [JsonPropertyName("e")]
    public string Exponent { get; set; }

    [JsonPropertyName("crv")]
    public string Curve { get; set; }
}


public class DPoPJwkSerializer : JsonConverter<DPoPJwk>
{
    public override DPoPJwk? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }

    public override void Write(Utf8JsonWriter writer, DPoPJwk value, JsonSerializerOptions options)
    {
        var serialized = JsonSerializer.Serialize<object>(value, options);
        writer.WriteRawValue(serialized);
    }
}
