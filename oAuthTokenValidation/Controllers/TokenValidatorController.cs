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

                keyValues.Add(new KeyValuePair<string, string>("client_id", "633622781734-9dtbahaafjtkt3ai50d9i47dgj47kljh.apps.googleusercontent.com"));
                keyValues.Add(new KeyValuePair<string, string>("client_secret", "hYB-CGQR2B0HPhVJyc5PgI2H"));
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
                builder.Query = "redirect_uri=http://localhost:4200/oauth&client_id=10f4d8c6134a1a0419f5&client_secret=37c404c3f47134b43936308a874c3e6655eacd5f&state=testing&code=" + token;

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
