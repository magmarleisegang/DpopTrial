using DpopTokens;
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
                var TokenWorks = new DPoPTokenValidator();

                var isValidDpopToken = TokenWorks.ValidateDpopTokenSignature(dpopToken.ToString(), out var thumbprint);
                if (isValidDpopToken)
                {
                    IdentityModelEventSource.ShowPII = true;

                    var tokenValue = Request.Headers.Authorization.ToString().Replace("dpop ", string.Empty, StringComparison.OrdinalIgnoreCase);
                    var validPubKey = TokenWorks.ValidateDPoPPublicKey(tokenValue, thumbprint);

                    if (validPubKey)
                    {
                        return Ok("DPoP proof seems legit");
                    }
                    else
                    {
                        return Unauthorized("Access Token thumbprint invalid");
                    }

                }
            }


            return Unauthorized();
        }
    }
}
