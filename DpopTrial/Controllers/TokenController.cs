using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using TestProject;

namespace DpopTrial.Controllers;

[ApiController]
[Route("[controller]")]
public class TokenController : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Index()
    {
        /*
         * 1. extract DPoP jwt from token request
         * 2. verify signature with included pub key
         * 3. generate the access token
         * 4. bind pub key to access token -> BindPubKeyToAccessToken
         * 5. respond with access token
         */

        //1,2. Extract and Verify DPoP token 
        if (Request.Headers.TryGetValue("DPOP", out var dpopToken))
        {
            var isValidDpopToken = TokenWorks.ValidateDpopTokenSignature(dpopToken.ToString(), out var thumbprint);
            if (isValidDpopToken)
            {
                var data = await GetRequestText(HttpContext);

                var jwtHandler = new JsonWebTokenHandler();
                var token = new SecurityTokenDescriptor()
                {
                    TokenType = "DPoP",
                    Audience = Request.Host.ToString(),
                    Claims = new Dictionary<string, object>() { { "resource-get", "bob" } }

                };

                BindPubKeyToAccessToken(token, thumbprint);

                return Ok(jwtHandler.CreateToken(token));
            }
        }

        return Unauthorized();
    }
    private async Task<string> GetRequestText(HttpContext context)
    {
        context.Request.EnableBuffering();

        var requestText = await new StreamReader(context.Request.Body).ReadToEndAsync();

        context.Request.Body.Seek(0, SeekOrigin.Begin);
        return requestText;
    }
    private void BindPubKeyToAccessToken(SecurityTokenDescriptor token, string pubkey)
    {
        var pubkeyThumbprint = Base64UrlEncoder.Encode(pubkey); //JWK SHA-256 Thumbprint
        token.Claims.Add("cnf", JsonSerializer.Serialize(new Jkt { jkt = pubkeyThumbprint }));
    }
}
