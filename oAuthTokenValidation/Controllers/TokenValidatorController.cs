using Newtonsoft.Json;
using oAuthTokenValidation.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web.Http;

namespace oAuthTokenValidation.Controllers
{

    [RoutePrefix("api/TokenValidator")]
    public class TokenValidatorController : ApiController
    {
        [Route("ValidateToken")]
        [HttpGet]
        public Token ValidateToken(string provider, string token)
        {
            if (provider == "google")
            {
                var client = new HttpClient();
                client.BaseAddress = new Uri("https://oauth2.googleapis.com");
                var request = new HttpRequestMessage(HttpMethod.Post, "/token");

                var keyValues = new List<KeyValuePair<string, string>>();
                keyValues.Add(new KeyValuePair<string, string>("code", token));
                keyValues.Add(new KeyValuePair<string, string>("redirect_uri", "http://localhost:4200/oauth?provider=google"));

                keyValues.Add(new KeyValuePair<string, string>("client_id", "<Client id>"));
                keyValues.Add(new KeyValuePair<string, string>("client_secret", "<client secret>"));
                keyValues.Add(new KeyValuePair<string, string>("scope", "openid email profile"));
                keyValues.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));

                request.Content = new FormUrlEncodedContent(keyValues);
                var response = client.SendAsync(request).Result;
                var data = JsonConvert.DeserializeObject<Token>(response.Content.ReadAsStringAsync().Result);

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    return data;
                }
                else
                {
                    return null;
                }
            }
            else if (provider == "github")
            {
                var client = new HttpClient();

                UriBuilder builder = new UriBuilder("https://github.com/login/oauth/access_token");
                builder.Query = "redirect_uri=http://localhost:4200/oauth&client_id=<clientid>&client_secret=<clientscret>&state=testing&code=" + token;

                var response = client.GetStringAsync(builder.Uri).Result;
                if (response.Contains("access_token"))
                {
                    Token token1 = new Token();
                    var splittedData = response.Split('&');
                    token1.access_token = splittedData[0].Split('=')[1];
                    token1.scope = splittedData[1].Split('=')[1];
                    token1.token_type = splittedData[2].Split('=')[1];
                    return token1;
                }

                return null;
            }

            return null;
        }

        [Route("ParseIdToken")]
        [HttpGet]
        public string ParseIdToken(string idToken)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(idToken);
            return token.ToString();
        }

        [Route("GithubClaims")]
        [HttpGet]
        public string GithubClaims(string accessToken)
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("token", accessToken);
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("signin-github", "1.0"));

            var response = client.GetStringAsync("https://api.github.com/user").Result;
            return response;
        }
    }
}
