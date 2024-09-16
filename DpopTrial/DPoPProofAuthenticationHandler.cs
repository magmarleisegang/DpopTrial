using DpopTokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace DpopTrial
{
    public class DPoPProofAuthenticationHandler
        : AuthenticationHandler<AuthSchemeOptions>
    {
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly DPoPTokenValidator tokenWorks;

        public DPoPProofAuthenticationHandler(IOptionsMonitor<AuthSchemeOptions> options,
              ILoggerFactory logger,
            UrlEncoder encoder,
            IHttpContextAccessor httpContextAccessor, 
            DPoPTokenValidator tokenWorks)
            : base(options, logger, encoder)
        {

            this.httpContextAccessor = httpContextAccessor;
            this.tokenWorks = tokenWorks;
        }
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (httpContextAccessor.HttpContext.Request.Headers.TryGetValue("DPOP", out var dpopToken))
            {
                var isValidDpopToken = tokenWorks.ValidateDpopTokenSignature(dpopToken.ToString(), out var thumbprint);
                var isValidDpopDetails = isValidDpopToken && tokenWorks.ValidateDPoPTokenDetail(dpopToken.ToString(), httpContextAccessor.HttpContext.Request);
                if (isValidDpopToken && isValidDpopDetails)
                {
                    return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new System.Security.Claims.ClaimsPrincipal(), "DPoPProof")));
                }
            }
            return Task.FromResult(AuthenticateResult.Fail("Invalid DPoP proof"));

        }


        public Task ChallengeAsync(AuthenticationProperties? properties)
        {
            throw new NotImplementedException();
        }

        public Task ForbidAsync(AuthenticationProperties? properties)
        {
            throw new NotImplementedException();
        }

        public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
        {
            throw new NotImplementedException();
        }


    }
    public class AuthSchemeOptions : AuthenticationSchemeOptions
    {
    }
}
