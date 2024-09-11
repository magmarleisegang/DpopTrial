using Microsoft.AspNetCore.Mvc;
using TestProject;

namespace DpopClient.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ResourceController(IHttpClientFactory httpClientFactory, TokenWorker tokenWorker) : Controller
    {
        public async Task<IActionResult> Index()
        {
            /*
             * prepare json with payload and pub key
             * sign payload + pub key with pvt key
             * pack into jwt and send to server along with access token
            
             */
            var token = tokenWorker.GenerateDpopProofToken();

            using var client = httpClientFactory.CreateClient("default");
            // call other API
            client.DefaultRequestHeaders.Add("DPOP", token);
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("DPoP", tokenWorker.AccessToken);
            var response = await client.PostAsync("resource", new StringContent("hallo"));

            return Ok(await response.Content.ReadAsStringAsync());
        }
    }
}
