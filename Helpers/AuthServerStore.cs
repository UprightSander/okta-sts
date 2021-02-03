using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Okta.Helpers
{
    public class AuthServerStore
    {
        public List<AuthServer> WhiteListedServers { get; set; } = new List<AuthServer>();
        public AuthServerStore()
        {
            AuthServer UprdefaultServer = new AuthServer()
            {
                issuer = "https://uprightsecurity-demo.okta.com/oauth2/default",
                audience = "api://default",
                description = "default oauth server"
            };

            AuthServer UprstsServer = new AuthServer()
            {
                issuer = "https://auth.uprightsecurity.dev/oauth2/aus1vvcb9qY8vyWH64x7",
                audience = "api://sts",
                description = "STS oauth server"
            };

            AuthServer RBFAPreviewDefault = new AuthServer()
            {
                issuer = "https://rbfa.oktapreview.com/oauth2/default",
                audience = "api://default",
                description = "RBFA Preview CIAM Auth Server"
            };

            WhiteListedServers.Add(UprdefaultServer);
            WhiteListedServers.Add(UprstsServer);
            WhiteListedServers.Add(RBFAPreviewDefault);
        }
    }
}
