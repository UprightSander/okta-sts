using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Okta.Helpers
{
    //This class will store all whitelisted OIDC clients, this is to avoid that anyone can send tokens with their own client id
    public class OIDCClientStore
    {
        public List<OIDCClient> OIDCClients { get; set; } = new List<OIDCClient>();

        public OIDCClientStore()
        {
            OIDCClient democlient = new OIDCClient()
            {
                name = "demoapp",
                clientid = "0oa1y46tflW2xAUZz4x7",
                description = "OIDC Demo client",
                redirect_url = "https://localhost:44362/authorization-code/callback",
                scopes = "openid profile email"
            };
            OIDCClient jwtverifier = new OIDCClient()
            {
                name = "jwtverifier",
                clientid = "0oa1w51c1hMQN2YIA4x7",
                description = "JWT Verifier",
                redirect_url = "https://localhost:5001",
                scopes = "openid profile email"
            };
            OIDCClient rbfaticketing = new OIDCClient()
            {
                name = "ticketing",
                clientid = "0oapdpxvhAlIr8M8K0x6",
                description = "RBFA ticketing app",
                redirect_url = "https://rbfa.staging.tymes4.com/account/sso-login",
                scopes = "openid profile email"
            };
            OIDCClient rbfatokenapp = new OIDCClient()
            {
                name = "tokenapp",
                clientid = "0oa19nuyc8dWPlIA30x7",
                description = "App to get a test access or id token",
                redirect_url = "https://example.org",
                scopes = "openid profile email"
            };

            OIDCClient rbfaMobile = new OIDCClient()
            {
                name = "RBFA mobile",
                clientid = "0oapxtdsf2m45XDsS0x6",
                description = "RBFA mobile app",
                redirect_url = "be.rbfa.mobile.rbfa://authorization-code/callback",
                scopes = "openid profile email"
            };

            OIDCClients.Add(democlient);
            OIDCClients.Add(jwtverifier);
            OIDCClients.Add(rbfaticketing);
            OIDCClients.Add(rbfatokenapp);
            OIDCClients.Add(rbfaMobile);
        }
    }
}
