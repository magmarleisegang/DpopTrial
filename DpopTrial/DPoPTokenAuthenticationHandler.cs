using DpopTokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Ocsp;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace DpopTrial;

public class DPoPTokenAuthenticationHandler : AuthenticationHandler<AuthSchemeOptions>
{
    private readonly IHttpContextAccessor httpContextAccessor;
    private readonly DPoPTokenValidator tokenWorks;

    public DPoPTokenAuthenticationHandler(IOptionsMonitor<AuthSchemeOptions> options,
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
        string dpopProofThumbprint = string.Empty;
        if (httpContextAccessor.HttpContext.Request.Headers.TryGetValue("DPOP", out var dpopProofToken))
        {
            var isValidDpopProofToken = tokenWorks.ValidateDpopTokenSignature(dpopProofToken.ToString(), out dpopProofThumbprint);
            var isValidDpopDetails = isValidDpopProofToken && tokenWorks.ValidateDPoPTokenDetail(dpopProofToken.ToString(), httpContextAccessor.HttpContext.Request);
            if (!isValidDpopProofToken || !isValidDpopDetails)
            {
                return Task.FromResult(AuthenticateResult.Fail("DPoP proof token invalid"));

            }
        }

        var tokenValue = httpContextAccessor.HttpContext.Request.Headers.Authorization.ToString().Replace("dpop ", string.Empty, StringComparison.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(tokenValue))
        {
            return Task.FromResult(AuthenticateResult.Fail("Authentication token invalid"));

        }

        var validPubKey = tokenWorks.ValidateDPoPPublicKey(tokenValue, dpopProofThumbprint);

        if (validPubKey)
        {
            var token = "[encoded jwt]";
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(tokenValue);

            var claimsPrinciple = new ClaimsPrincipal();
            var id = new ClaimsIdentity("DPoP");
            id.AddClaims(jwtSecurityToken.Claims.Where(c => c.Type != "cnf"));

            claimsPrinciple.AddIdentity(id);
            var authTicket = new AuthenticationTicket(claimsPrinciple, "DPoPProof");
            return Task.FromResult(AuthenticateResult.Success(authTicket));

        }
        else
        {
            return Task.FromResult(AuthenticateResult.Fail("Access Token thumbprint invalid"));
        }
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

public static class DPoPTokenAuthentication
{
    public static IServiceCollection AddDPoPAuth(this IServiceCollection services)
    {
        services.AddSingleton<DPoPTokenValidator>();

        services.AddAuthentication("DPoPProof")
            .AddScheme<AuthSchemeOptions, DPoPTokenAuthenticationHandler>("DPoPProof", null);
        return services;
    }
}
