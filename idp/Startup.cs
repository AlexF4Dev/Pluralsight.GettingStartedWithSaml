using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Common;
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
            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();

            var builder = services.AddIdentityServer()
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryApiScopes(new List<ApiScope>())
                .AddInMemoryClients(Config.Clients)
                .AddTestUsers(TestUsers.Users)
                .AddSigningCredential(
                    new X509Certificate2("idp_privatekey.pfx", string.Empty, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable));

            builder.AddSamlPlugin(options =>
            {
                options.Licensee = DemoLicense.Licensee;
                options.LicenseKey = DemoLicense.LicenseKey;

                options.WantAuthenticationRequestsSigned = false;
            }).AddInMemoryServiceProviders(Config.ServiceProviders);

            services.AddScoped<ISamlMessageParser, SamlMessageParser>();
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