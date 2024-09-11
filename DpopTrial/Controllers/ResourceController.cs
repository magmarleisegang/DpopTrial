using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Json;
using TestProject;

namespace DpopTrial.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ResourceController : Controller
    {
        public IActionResult Index()
        {
            /*
             * 1. verify dpop jwt signature with dpop included pub key
             * 2. verify pub key matches access token pub key
             * 3. respond if true
             */
            if (Request.Headers.TryGetValue("DPOP", out var dpopToken))
            {
                var isValidDpopToken = TokenWorks.ValidateDpopTokenSignature(dpopToken.ToString(), out var thumbprint);
                if (isValidDpopToken)
                {
                    IdentityModelEventSource.ShowPII = true;
                    var jwtHandler = new JsonWebTokenHandler();
                    var tokenValue = Request.Headers.Authorization.ToString().Replace("dpop ", string.Empty, StringComparison.OrdinalIgnoreCase);
                    if (jwtHandler.CanReadToken(tokenValue))
                    {
                        var to = (JsonWebToken)jwtHandler.ReadToken(tokenValue);
                        if (to.TryGetClaim("cnf", out Claim claim))
                        {
                            var cnf = JsonSerializer.Deserialize<Jkt>(claim.Value);
                            var pubkeyThumbprint = Base64UrlEncoder.Encode(thumbprint);
                            if (cnf.jkt.Equals(pubkeyThumbprint))
                            {
                                return Ok("DPoP proof seems legit");
                            }
                            else
                            {
                                return Unauthorized("Access Token thumbprint invalid");
                            }
                        }
                    }
                }
            }


            return Unauthorized();
        }
    }
}
