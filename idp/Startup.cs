using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using IdentityServer4.Models;
using IdentityServerHost.Quickstart.UI;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace idp
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            var builder = services.AddIdentityServer()
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryApiScopes(new List<ApiScope>())
                .AddInMemoryClients(Config.Clients)
                .AddTestUsers(TestUsers.Users)
                .AddSigningCredential(
                    new X509Certificate2("idp_privatekey.pfx", string.Empty, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable));

            builder.AddSamlPlugin(options =>
            {
                options.Licensee = "DEMO"; // TODO: change to "Pluralsight"
                options.LicenseKey = "eyJTb2xkRm9yIjowLjAsIktleVByZXNldCI6NiwiU2F2ZUtleSI6ZmFsc2UsIkxlZ2FjeUtleSI6ZmFsc2UsIlJlbmV3YWxTZW50VGltZSI6IjAwMDEtMDEtMDFUMDA6MDA6MDAiLCJhdXRoIjoiREVNTyIsImV4cCI6IjIwMjAtMTEtMTVUMDE6MDA6MDMuNDY2OTYxNCswMDowMCIsImlhdCI6IjIwMjAtMTAtMTZUMDA6MDA6MDMiLCJvcmciOiJERU1PIiwiYXVkIjoyfQ==.l7B6U9aTiZOi/rTv28txZejeDOcwMzRH/2OcAG5+eDCw0BovV62DGbyS287nnlIPr+W5AM3ESQPUNkUe6LiuzIYdxmOxwtGyYBlD6H/F4n33XR+Trm9JyL+l7rmuAxDJVrD4gU5XxbAL3pfLN/ELduYLZYUuRnVIQwwa+rnt2Ki+EhkMNwJDEgGN1zffWn6XT+1OTZKPLhg5nqgpdOUtc3izOXk5QKjPHrmQAhnf/39AXAEBvlo644KUUPxnMSz9TR1TNOmXdRG5/+6GmlSiCc+rIC8XTnr7kn3XkNahScgPUGT19/UN9h9mCQghb3hYJ5rzghGtYBN5jZX92waQ9J3Vo+0mPMPOHSu/13F25pGPQD8AY9OGwNO8VKxZwJcyAPrD854RKklmOjVU3VwMUthiqQTx7t+CsutjPS9p3JKb5e9f/K1a2vjLjzpYQ4mqqJ3qzn6bAd2KrEhRsWOw1cisdNfihgSXyWmU9S6W9oG9CY/iShxFTWM7RAipmhHo3LhXgbU3NUltyHByqjKTVDZBALz3x2LYk6xEe7efTuenQc8OtpQfmT+v/CllmImhnnIaSQ5NNZBR1U+cz1G4rYh8wb9KVaySXfc+bbc3jg7YN7NAF+jWbRqtuQND9FfYcvQoNdk2FZVJ0geKqfUvopBtUKd11CdQ+5AwVvJwM2k="; // Expires 15 November 2020

                options.WantAuthenticationRequestsSigned = false;
            }).AddInMemoryServiceProviders(Config.ServiceProviders);

        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseHttpsRedirection();
            
            app.UseStaticFiles();
            app.UseRouting();
            
            app.UseIdentityServer()
                .UseIdentityServerSamlPlugin();
            
            app.UseAuthorization();
            
            app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
        }
    }
}