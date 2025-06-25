using System.Net;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Proj.Tests
{
    public class AuthIntegrationTests : IClassFixture<CustomWebApplicationFactory<Program>>
    {
        private readonly HttpClient _client;
        public AuthIntegrationTests(CustomWebApplicationFactory<Program> factory)
        {
            _client = factory.CreateClient();
        }

        [Fact]
        public async Task Register_ReturnsBadRequest_OnDuplicateEmail()
        {
            var payload = new { fullName = "Test", email = "dupe@x.com", password = "123456", confirmPassword = "123456" };
            await _client.PostAsJsonAsync("/api/auth/register", payload); // first registration
            var resp = await _client.PostAsJsonAsync("/api/auth/register", payload); // duplicate
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        }

        [Fact]
        public async Task Login_ReturnsBadRequest_OnInvalidCredentials()
        {
            var payload = new { email = "notfound@x.com", password = "badpass" };
            var resp = await _client.PostAsJsonAsync("/api/auth/login", payload);
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        }

        [Fact]
        public async Task Register_ReturnsBadRequest_OnMissingFields()
        {
            var payload = new { email = "", password = "", confirmPassword = "", fullName = "" };
            var resp = await _client.PostAsJsonAsync("/api/auth/register", payload);
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        }
    }
}
