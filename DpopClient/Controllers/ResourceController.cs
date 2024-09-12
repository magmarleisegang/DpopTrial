using DpopTokens;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using TestProject;

namespace DpopClient.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ResourceController(IHttpClientFactory httpClientFactory, DPopTokenGenerator tokenWorker) : Controller
    {
        public async Task<IActionResult> Index()
        {
            /*
             * prepare json with payload and pub key
             * sign payload + pub key with pvt key
             * pack into jwt and send to server along with access token
            
             */

            using var client = httpClientFactory.CreateClient("default");
            var reqPath = $"{client.BaseAddress}resource";
            // call other API
            var token = tokenWorker.GenerateDpopProofToken(reqPath, "POST");
            client.DefaultRequestHeaders.Add("DPOP", token);
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("DPoP", tokenWorker.AccessToken);
            var response = await client.PostAsync("resource", new StringContent("hallo"));

            return Ok(await response.Content.ReadAsStringAsync());
        }

        [Route("invalid")]
        public async Task<IActionResult> Invalid()
        {
            /*
             * prepare json with payload and pub key
             * sign payload + pub key with pvt key
             * pack into jwt and send to server along with access token
            
             */
            var TokenWorks = new DPopTokenGenerator();


            using var client = httpClientFactory.CreateClient("default");
            var reqPath = $"{client.BaseAddress}/resource";

            var token = TokenWorks.GenerateDpopProofToken(reqPath, "POST");
            // call other API
            client.DefaultRequestHeaders.Add("DPOP", token);
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("DPoP", tokenWorker.AccessToken);
            var response = await client.PostAsync("resource", new StringContent("hallo"));

            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
