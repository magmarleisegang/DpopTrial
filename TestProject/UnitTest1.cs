using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Unicode;

namespace TestProject
{
    public class Tests
    {

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void GenerateToken()
        {
            RSA rsa = RSA.Create();
            var pkParams = rsa.ExportParameters(false);
            //Save the public key information to an RSAParameters structure.  
            var tokenHandler = new JsonWebTokenHandler();
            var dpopjwt = TokenWorks.GenerateDpopToken(rsa);

            //validate using public key 

            Assert.That(TokenWorks.ValidateDpopTokenSignature(dpopjwt, out var _), Is.True);
        }

        [Test]
        public void GEnerateToken2()
        {
            IdentityModelEventSource.ShowPII = true;
            var edsaKey = new ECDsaSecurityKey(ECDsa.Create());
            var rsaKey = new RsaSecurityKey(RSA.Create(2048));
            var jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(edsaKey);
            //jsonWebKey.Alg = "PS256";
            var jwk = new
            {
                kty = jsonWebKey.Kty,
                alg = jsonWebKey.Alg,
                crv = jsonWebKey.Crv,
                x = jsonWebKey.X,
            };
            string jwkS = JsonSerializer.Serialize(jwk);

            var handler = new JsonWebTokenHandler();
            var now = DateTime.UtcNow;

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = new ClaimsIdentity(new List<Claim> { new Claim("sub", "scott") }),
                SigningCredentials = new SigningCredentials(jsonWebKey, SecurityAlgorithms.RsaSsaPssSha256),
                AdditionalHeaderClaims = new Dictionary<string, object>()
                {
                    {"jwk", jwkS }
                }
            };

            string jwt = handler.CreateToken(descriptor);
        }


        [Test]
        public async Task Generate3()
        {
            var options = new SampleOptions();
            var handler = new JsonWebTokenHandler();

            var generator = new Ed25519KeyPairGenerator();
            var keyPramsn = new Ed25519KeyGenerationParameters(new SecureRandom());
            generator.Init(keyPramsn);
            var keyPair = generator.GenerateKeyPair();

            //return new EdDsa
            //{
            //    Parameters = new EdDsaParameters(curve)
            //    {
            //        D = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded(),
            //        X = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded()
            //    },
            //    PrivateKeyParameter = keyPair.Private,
            //    PublicKeyParameter = keyPair.Public
            //};

            var paramss = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519)
            {
                D = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded(),
                X = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded()
            };

            var secKey = new EdDsaSecurityKey(EdDsa.Create(paramss));

            var jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(secKey);
            //jsonWebKey.Alg = "PS256";
            string jwk = JsonSerializer.Serialize(jsonWebKey);

            var jwk2 = new
            {
                kty = ExtendedSecurityAlgorithms.KeyTypes.Ecdh,
                alg = options.EdDsaPublicKey.EdDsa.SignatureAlgorithm,
                crv = ExtendedSecurityAlgorithms.Curves.Ed25519,
                X = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded()
            };


            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                SigningCredentials = new SigningCredentials(secKey, ExtendedSecurityAlgorithms.EdDsa),

                AdditionalHeaderClaims = new Dictionary<string, object>()
                {
                    {"jwk", jwk }
                }
            };

            var token = handler.CreateToken(descriptor);
            var payloadClaims = handler.ReadJsonWebToken(token).Claims;

            var claimsJson = new JsonObject();
            foreach (var claim in payloadClaims)
            {
                if (claim.ValueType.Contains("integer"))
                {
                    claimsJson.Add(claim.Type, int.Parse(claim.Value));
                }
                else
                {
                    claimsJson.Add(claim.Type, claim.Value);
                }
            }

            var t = new
            {
                Type = "EdDSA JWT",
                Token = token,
                Payload = claimsJson.ToString()
            };
        }
    }

    public class SampleOptions
    {
        private static readonly EdDsa _key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);

        public readonly EdDsaSecurityKey EdDsaPublicKey = new EdDsaSecurityKey(_key);
        public readonly EdDsaSecurityKey EdDsaPrivateKey = new EdDsaSecurityKey(_key);

    }


}
