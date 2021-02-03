// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Okta.Helpers;
using Okta.Quickstart.Account;
using RestSharp;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static IdentityServer4.Models.IdentityResources;

namespace IdentityServerHost.Quickstart.UI
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private TestUserStore _users;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private OIDCClientStore oidcClientStore;
        private AuthServerStore authServerStore;

        // Replace with your authorization server URL:
        private string authIssuer;
        private ConfigurationManager<OpenIdConnectConfiguration> configurationManager;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            TestUserStore users = null)
        {
            _users = users ?? new TestUserStore(TestUsers.Users);
            oidcClientStore = new OIDCClientStore();
            authServerStore = new AuthServerStore();
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            authIssuer = "https://uprightsecurity-demo.okta.com/oauth2/default";
        }

        private IntrospectModel introspect(string token)
        {
            var client = new RestClient("https://auth.uprightsecurity.dev/oauth2/aus1vvcb9qY8vyWH64x7/v1/introspect");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Authorization", "Basic MG9hMXc1MWMxaE1RTjJZSUE0eDc6TW1vVTgwR2hjSF9aLWxZQzVrNkJXcm90ZG1BYW1YWTlpMW13WWFOQQ==");
            request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            request.AddHeader("Cookie", "__cfduid=d870aa47cce504d2d63809fe88b8134cb1610974211; DT=DI0DA7HqXbhTASAo_iXE4ryvQ; t=default; JSESSIONID=A09B8AF7ED9124DA011413E027207CDC");
            request.AddParameter("token", token);
            request.AddParameter("token_type_hint", "id_token");
            IRestResponse response = client.Execute(request);
            IntrospectModel model = JsonConvert.DeserializeObject<IntrospectModel>(response.Content);
            //Console.WriteLine(response.Content);
            return model;
        }

        public async Task authenticate(TestUser t)
        {
            var context = await _interaction.GetAuthorizationContextAsync("temp");
            //var user = _users.FindByUsername(username);
            await _events.RaiseAsync(new UserLoginSuccessEvent(t.Username, t.SubjectId, t.Username, clientId: context?.Client.ClientId));

            // only set explicit expiration here if user chooses "remember me". 
            // otherwise we rely upon expiration configured in cookie middleware.
            AuthenticationProperties props = null;
            props = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
            };

            // issue authentication cookie with subject ID and username
            var isuser = new IdentityServerUser(t.SubjectId)
            {
                DisplayName = t.Username
            };

            await HttpContext.SignInAsync(isuser, props);
        }

        private async Task<JwtSecurityToken> ValidateToken(
    string token,
    string issuer,
    string tokenType,
    string audience,
    IConfigurationManager<OpenIdConnectConfiguration> configurationManager,
    CancellationToken ct = default(CancellationToken))
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
            if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));

            var discoveryDocument = await configurationManager.GetConfigurationAsync(ct);
            var signingKeys = discoveryDocument.SigningKeys;
            string validAudience = "not-set";



            if (tokenType == "access_token")
            {
                //This needs to be replaced with env variables, it should be the authorization server of our okta tenant.
                //for now it is hard coded to test.
                validAudience = audience;
            } else if(tokenType == "id_token")
            {
                //string audience = token.Claims.First(claim => claim.Type == "aud").Value;
                //with id token the audience is the clientid, to avoid that any other client id is send we will check it with a whitelist.
                if (oidcClientStore.OIDCClients.SingleOrDefault(x => x.clientid == audience).clientid != null)
                {
                    validAudience = audience;
                } else
                {
                    validAudience = "invalid";
                }
            }

            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireAudience = false,
                RequireSignedTokens = true,
                ValidAudience = validAudience,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateLifetime = true,
                // Allow for some drift in server time
                // (a lower value is better; we recommend two minutes or less)
                ClockSkew = TimeSpan.FromMinutes(2),
                // See additional validation for aud below
            };

            try
            {
                var principal = new JwtSecurityTokenHandler()
                    .ValidateToken(token, validationParameters, out var rawValidatedToken);

                return (JwtSecurityToken)rawValidatedToken;
            }
            catch (SecurityTokenValidationException ex)
            {
                // Logging, etc.

                return null;
            }
        }

        private TestUser createUser(string username)
        {
            Random rnd = new Random();
            int id = rnd.Next(100000, 999999);
            System.Collections.Generic.List<Claim> claims = new System.Collections.Generic.List<Claim>()
            {
                new Claim(JwtClaimTypes.Email, username),
                new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
            };
            TestUser t = _users.AutoProvisionUser("local", id.ToString(), claims);
            return t;
        }

        private JwtSecurityToken decodeToken(string token)
        {
            var stream = token;
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(stream);
            var tokenS = handler.ReadToken(stream) as JwtSecurityToken;
            return tokenS;
        }

        private string GenerateValue(string extra = "")
        {
            string result = "";
            SHA1 sha1 = SHA1.Create();

            Random rand = new Random();

            while (result.Length < 32)
            {
                string[] generatedRandoms = new string[4];

                for (int i = 0; i < 4; i++)
                {
                    generatedRandoms[i] = rand.Next().ToString();
                }

                result += Convert.ToBase64String(sha1.ComputeHash(Encoding.ASCII.GetBytes(string.Join("", generatedRandoms) + "|" + extra))).Replace("=", "").Replace("/", "").Replace("+", "");
            }

            return result.Substring(0, 32);
        }

        [HttpGet]
        public async Task<IActionResult> SwapToken(string token,string tokenType, string redirectapp)
        {
            var accessToken = token;
            JwtSecurityToken decodedToken = decodeToken(token);

           

            //string audience = decodedToken.Claims.First(claim => claim.Type == "aud").Value;
            string issuer = decodedToken.Claims.First(claim => claim.Type == "iss").Value;
            AuthServer authServer = authServerStore.WhiteListedServers.SingleOrDefault(x => x.issuer == issuer);
            
            if(authServer != null)
            {
                configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
    authServer.issuer + "/.well-known/oauth-authorization-server",
    new OpenIdConnectConfigurationRetriever(),
    new HttpDocumentRetriever());
                var validatedToken = new JwtSecurityToken();
                if (tokenType == "access_token")
                {
                    validatedToken = await ValidateToken(accessToken, authServer.issuer, tokenType, authServer.audience, configurationManager);
                } else
                {
                    string audience = decodedToken.Claims.First(claim => claim.Type == "aud").Value;
                    validatedToken = await ValidateToken(accessToken, authServer.issuer, tokenType, audience, configurationManager);
                }

                if (validatedToken == null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Token is either invalid or has expired");
                }
                else
                {
                    // Additional validation...
                    Console.WriteLine("Token is valid!");
                    string username = getUsernameFromToken(validatedToken, tokenType);
                    if (username == null)
                    {
                        return StatusCode(StatusCodes.Status500InternalServerError, "Username is missing from the token, make sure the original token uses the profile scope.");
                    }
                    string oidcid = getClientIdFromToken(validatedToken, tokenType);
                    OIDCClient client = oidcClientStore.OIDCClients.Single(x => x.name == redirectapp);
                    TestUser t = createUser(username);
                    await authenticate(t);

                    //return RedirectToAction("Index", "Home");
                    return Redirect(authServer.issuer + "/v1/authorize?idp=0oa19nu4c9XfCbH5W0x7&client_id="
                        + client.clientid + "&response_type=code&response_mode=query&scope="
                        + client.scopes
                        + "&redirect_uri="
                        + client.redirect_url
                        + "&state=" + GenerateValue()
                        + "&nonce=" + GenerateValue());
                }
            } else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Token comes from an unknown auth server.");
            } 
        }

        private string getClientIdFromToken(JwtSecurityToken token, string tokenType)
        {
            if(tokenType == "access_token")
            {
                return token.Claims.First(claim => claim.Type == "cid").Value;
            } else
            {
                return token.Claims.First(claim => claim.Type == "aud").Value;
            }
        }

        private string getUsernameFromToken(JwtSecurityToken token, string tokenType)
        {
            string username = "";
            if(tokenType == "access_token")
            {
                username = token.Claims.First(claim => claim.Type == "sub").Value;
            } else
            {
                Claim c = token.Claims.FirstOrDefault(claim => claim.Type == "preferred_username");
                if(c != null)
                {
                    username = token.Claims.FirstOrDefault(claim => claim.Type == "preferred_username").Value;
                } else
                {
                    username = null;
                }
            }
            return username;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        /// 
        /*
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl, string username, string token)
        {
            LoginInputModel model = new LoginInputModel()
            {
                Username = username,
                Password = "msmith",
                RememberLogin = false,
                ReturnUrl = "https://auth.uprightsecurity.dev/oauth2/v1/authorize/callback"
            };
            string button = "login";

            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                // validate username/password against in-memory store
                if (_users.ValidateCredentials(model.Username, model.Password))
                {
                    var user = _users.FindByUsername(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.Client.ClientId));

                    // only set explicit expiration here if user chooses "remember me". 
                    // otherwise we rely upon expiration configured in cookie middleware.
                    AuthenticationProperties props = null;
                    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                    {
                        props = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                        };
                    };

                    // issue authentication cookie with subject ID and username
                    var isuser = new IdentityServerUser(user.SubjectId)
                    {
                        DisplayName = user.Username
                    };

                    await HttpContext.SignInAsync(isuser, props);

                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect("~/");
                    }

                    return Redirect(model.ReturnUrl);
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                model.Username = "msmith@samltest.id";
                model.Password = "msmith";
                // validate username/password against in-memory store
                if (_users.ValidateCredentials(model.Username, model.Password))
                {
                    var user = _users.FindByUsername(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.Client.ClientId));

                    // only set explicit expiration here if user chooses "remember me". 
                    // otherwise we rely upon expiration configured in cookie middleware.
                    AuthenticationProperties props = null;
                    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                    {
                        props = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                        };
                    };

                    // issue authentication cookie with subject ID and username
                    var isuser = new IdentityServerUser(user.SubjectId)
                    {
                        DisplayName = user.Username
                    };

                    await HttpContext.SignInAsync(isuser, props);

                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        throw new Exception("invalid return URL");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId:context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }
        */

        
        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await HttpContext.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }


        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}
