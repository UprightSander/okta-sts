using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Okta.Helpers
{
    public class OIDCClient
    {
        public string name { get; set; }
        public string clientid { get; set; }
        public string description { get; set; }
        public string redirect_url { get; set; }
        public string scopes { get; set; }
    }
}
