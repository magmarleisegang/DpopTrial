using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace TestProject;

public class TokenWorker
{
    public TokenWorker()
    {
        internal_rsa = RSA.Create();
    }

    private const string DpopTokenType = "dpop+jwt";
    private readonly RSA internal_rsa;
    private string _accessToken;
    public string AccessToken => _accessToken;

    public string GenerateDpopProofToken()
    {
        var rsaKey = new RsaSecurityKey(internal_rsa);

        var rsaParameters = internal_rsa.ExportParameters(false);

        var jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(rsaKey);

        var jwk = new
        {
            kty = jsonWebKey.Kty,
            n = Convert.ToBase64String(rsaParameters.Modulus!),
            e = jsonWebKey.E
        };

        var dpopjwtheader = new
        {
            typ = DpopTokenType,
            alg = "PS256",
            jwk
        };
        var dpopjwtpayload = new
        {
            jti = Guid.NewGuid().ToString(),
            htm = "POST",
            htu = "https://localhost:7292/token",
            iat = DateTime.Now.Ticks,
        };

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

        var header = Base64Decode<DpopHeader>(header64);

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

    public static T Base64Decode<T>(string thing64)
    {
        var decoded = Base64UrlEncoder.Decode(thing64);
        var _daata = JsonSerializer.Deserialize<T>(decoded);
        return _daata;
    }

    public void SetAccessToken(string accesstoken)
    {
        _accessToken = accesstoken;
    }

    public class DpopHeader
    {
        public string typ { get; set; }
        public string alg { get; set; }
        public Jwk jwk { get; set; }

    }
    public class Jwk
    {
        public string kty { get; set; }
        public string n { get; set; }
        public string e { get; set; }
    }
}

