using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DpopTokens;

public class DPopTokenGenerator
{
    public DPopTokenGenerator()
    {
        internal_rsa = RSA.Create();
    }

    private readonly RSA internal_rsa;
    private string? _accessToken;
    public string AccessToken => _accessToken ?? throw new InvalidOperationException("No access token available");

    public string GenerateDpopProofToken(string requestPath, string requestMethod)
    {
        var rsaKey = new RsaSecurityKey(internal_rsa);

        var rsaParameters = internal_rsa.ExportParameters(false);

        var jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(rsaKey);

        var jwk = new DPoPJwk(jsonWebKey.Kty, Convert.ToBase64String(rsaParameters.Modulus!), jsonWebKey.E);
        var dpopjwtheader = new DPoPTokenHeader("PS256", jwk);
        var dpopjwtpayload = new DPoPPayload(Guid.NewGuid(), requestMethod, requestPath, DateTimeOffset.Now);

        var h1 = Base64Encode(dpopjwtheader);
        var p1 = Base64Encode(dpopjwtpayload);
        var tokendata = $"{h1}.{p1}";
        var bytesToSign = Encoding.UTF8.GetBytes(tokendata);

        var signature = internal_rsa.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var signatureEncoded = Base64UrlEncoder.Encode(signature);
        return $"{tokendata}.{signatureEncoded}";
    }

    public static string Base64Encode(object thing)
    {
        var plainText = JsonSerializer.Serialize(thing);
        var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        return Base64UrlEncoder.Encode(plainTextBytes);
    }
    public void SetAccessToken(string accesstoken)
    {
        _accessToken = accesstoken;
    }

}

