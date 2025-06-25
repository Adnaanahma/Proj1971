using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;

namespace Proj.Tests
{
    public class CustomWebApplicationFactory<TStartup> : WebApplicationFactory<TStartup> where TStartup : class
    {
        protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                var dict = new Dictionary<string, string>
                {
                    ["Jwt:Key"] = "supersecretkey1234567890supersecret!",
                    ["Jwt:Issuer"] = "testissuer",
                    ["Jwt:Audience"] = "testaudience",
                    ["Jwt:ExpiresInMinutes"] = "60"
                };
                config.AddInMemoryCollection(dict);
            });
        }
    }
}
