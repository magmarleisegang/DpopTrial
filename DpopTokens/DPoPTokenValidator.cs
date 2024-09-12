using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DpopTokens;

public class DPoPTokenValidator
{

    public bool ValidateDpopTokenSignature(string dpopjwt, out string pubKeyPrint)
    {
        pubKeyPrint = string.Empty;
        var bits = dpopjwt.Split('.');
        var header64 = bits[0];
        var payload64 = bits[1];
        var signature64 = bits[2];

        var header = Base64Decode<DPoPTokenHeader>(header64);
        var rsaKey = header.JsonWebKey;
        var exponent = Base64UrlEncoder.DecodeBytes(rsaKey.Exponent);
        var modulus = Convert.FromBase64String(rsaKey.Modulus);

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

    public bool ValidateDPoPTokenDetail(string dpopjwt, HttpRequest request)
    {
        var bits = dpopjwt.Split('.');
        var payload64 = bits[1];
        var payload = Base64Decode<DPoPPayload>(payload64);
        var requestUri = request.GetDisplayUrl();
        return payload.IntendedUri == requestUri && payload.HttpMethod == request.Method;
    }

    public bool ValidateDPoPPublicKey(string accessToken, string dpopThumbprint)
    {
        var jwtHandler = new JsonWebTokenHandler();

        if (!jwtHandler.CanReadToken(accessToken))
        { return false; }

        var to = (JsonWebToken)jwtHandler.ReadToken(accessToken);

        if (!to.TryGetClaim("cnf", out Claim claim))
        {
            return false;
        }

        var cnf = JsonSerializer.Deserialize<Jkt>(claim.Value);
        var pubkeyThumbprint = Base64UrlEncoder.Encode(dpopThumbprint);
        return cnf.jkt.Equals(pubkeyThumbprint);
    }

    public static T Base64Decode<T>(string thing64)
    {
        var decoded = Base64UrlEncoder.Decode(thing64);
        var _daata = JsonSerializer.Deserialize<T>(decoded);
        return _daata;
    }

    public void BindPubKeyToAccessToken(SecurityTokenDescriptor token, string pubkey)
    {
        var pubkeyThumbprint = Base64UrlEncoder.Encode(pubkey); //JWK SHA-256 Thumbprint
        token.Claims.Add("cnf", JsonSerializer.Serialize(new Jkt { jkt = pubkeyThumbprint }));
    }
}

