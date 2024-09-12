using DpopTokens;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using TestProject;
using static System.Net.WebRequestMethods;

namespace DpopClient.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController(IHttpClientFactory httpClientFactory, DPopTokenGenerator tokenWorker) : Controller
    {
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            /*
             * 1. Generate pub/pvt key
             * 2. prepare payload incl. pub key
             * 3. sign with pvt key
             * 4. create dpop jwt
             * 5. send to auth server
            */

            //1.
            //Generate a public/private key pair.  
            //var tokenHandler = new JsonWebTokenHandler();


            using var client = httpClientFactory.CreateClient("default");
            var reqPath = $"{client.BaseAddress}token";
            var token = tokenWorker.GenerateDpopProofToken(reqPath, "POST");
            // call other API
            client.DefaultRequestHeaders.Add("DPOP", token);
            var response = await client.PostAsync("token", new StringContent("hallo"));
            var responseData = await response.Content.ReadAsStringAsync();
            tokenWorker.SetAccessToken(responseData);
            return Ok(responseData);
        }
    }
}
