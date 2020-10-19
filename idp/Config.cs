using IdentityServer4.Models;
using System.Collections.Generic;
using IdentityServer4;
using IdentityServer4.Saml;
using IdentityServer4.Saml.Models;

namespace idp
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[] {new IdentityResources.OpenId(), new IdentityResources.Profile()};

        public static IEnumerable<Client> Clients =>
            new[]
            {
                new Client
                {
                    ClientId = "https://localhost:5001",
                    AllowedScopes = {"openid", "profile"},
                    RequireConsent = false,
                    ProtocolType = IdentityServerConstants.ProtocolTypes.Saml2p
                }
            };

        public static IEnumerable<ServiceProvider> ServiceProviders =>
            new[]
            {
                new ServiceProvider
                {
                    EntityId = "https://localhost:5001",
                    AssertionConsumerServices = new List<Service>
                    {
                        new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5001/saml/acs")
                    }
                }
            };
    }
}