using System.Text.Json.Serialization;

namespace DpopTokens;

public class RSAJwk(string kty, string modulus, string exponent) : DPoPJwk(kty, modulus, exponent)
{
    [JsonConstructor]
    public RSAJwk()
        : this(string.Empty, string.Empty, string.Empty)
    {

    }

    public string Modulus => base.modulus;

    public string Exponent => exponent;
}
