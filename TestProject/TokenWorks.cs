using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TestProject;

public static class TokenWorks
{
    private const string DpopTokenType = "dpop+jwt";
    public static byte[] SignedData { get; private set; }
    public static byte[] Signature { get; private set; }
    public static string SignatureEncoded { get; private set; }

    public static string GenerateDpopToken(RSA rsa)
    {
        var rsaKey = new RsaSecurityKey(rsa);

        var rsaParameters = rsa.ExportParameters(false);

        var jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(rsaKey);

        var jwk = new RSAJwk(
            kty: jsonWebKey.Kty,
            Modulus: Convert.ToBase64String(rsaParameters.Modulus!),
            Exponent: jsonWebKey.E
        );

        var dpopjwtheader = new DPoPTokenHeader(
            KeyAlgorithm: "PS256",
            jwk
        );

        var dpopjwtpayload = new DPoPPayload(
            Guid.NewGuid(),
            "POST",
            "https://localhost:7292/token",
            DateTimeOffset.Now);

        var h1 = Base64Encode(dpopjwtheader);
        var p1 = Base64Encode(dpopjwtpayload);
        var tokendata = $"{h1}.{p1}";
        var bytesToSign = System.Text.Encoding.UTF8.GetBytes(tokendata);
        SignedData = bytesToSign;

        var signature = rsa.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Signature = signature;

        SignatureEncoded = Base64UrlEncoder.Encode(signature);
        return $"{tokendata}.{SignatureEncoded}";
    }

    public static string Base64Encode(object thing)
    {
        var plainText = JsonSerializer.Serialize(thing);
        var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
        return Base64UrlEncoder.Encode(plainTextBytes);
    }


    public static bool ValidateDpopTokenSignature(string dpopjwt, out string pubKeyPrint)
    {
        pubKeyPrint = string.Empty;
        var bits = dpopjwt.Split('.');
        var header64 = bits[0];
        var payload64 = bits[1];
        var signature64 = bits[2];

        var header = Base64Decode<DPoPTokenHeader>(header64);

        var exponent = Base64UrlEncoder.DecodeBytes(header.jwk.e);
        var modulus = Convert.FromBase64String(header.jwk.n);

        var paramss = new RSAParameters()
        {
            Exponent = exponent,
            Modulus = modulus,
        };

        var publicKey = RSA.Create(paramss);

        var dataBytes = Encoding.UTF8.GetBytes($"{header64}.{payload64}");
        var sigBytes = Base64UrlEncoder.DecodeBytes(signature64);

        var valid = publicKey.VerifyData(dataBytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        if (valid)
        {
            pubKeyPrint = publicKey.ExportRSAPublicKeyPem();
        }
        return valid;
    }

    public static bool ValidateDPoPTokenDetail(string dpopjwt, HttpRequest request)
    {
        var bits = dpopjwt.Split('.');
        var payload64 = bits[1];
        var payload = Base64Decode<DPoPPayload>(payload64);
        return payload.IntendedUri == request.Path && payload.HttpMethod == request.Method;
    }

    public static T Base64Decode<T>(string thing64)
    {
        var decoded = Base64UrlEncoder.Decode(thing64);
        var _daata = JsonSerializer.Deserialize<T>(decoded);
        return _daata;
    }


}

