using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Moq;
using Proj.DTOs;
using Proj.Models;
using Proj.Repositories;
using Proj.Services;
using Xunit;

namespace Proj.Tests
{
    public class UserServiceTests
    {
        private readonly Mock<IUserRepository> _userRepoMock = new();
        private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
        private readonly Mock<IConfiguration> _configMock = new();
        private readonly UserService _service;

        public UserServiceTests()
        {
            var store = new Mock<IUserStore<ApplicationUser>>();
            _userManagerMock = new Mock<UserManager<ApplicationUser>>(store.Object, null, null, null, null, null, null, null, null);
            _service = new UserService(_userRepoMock.Object, _userManagerMock.Object, _configMock.Object);
        }

        [Fact]
        public async Task RegisterAsync_ReturnsError_WhenPasswordsDoNotMatch()
        {
            var dto = new RegisterDto { Email = "a@b.com", Password = "123", ConfirmPassword = "456", FullName = "Test" };
            var (succeeded, errors) = await _service.RegisterAsync(dto);
            Assert.False(succeeded);
            Assert.Contains("Passwords do not match.", errors);
        }

        [Fact]
        public async Task RegisterAsync_ReturnsError_WhenEmailExists()
        {
            _userRepoMock.Setup(r => r.GetByEmailAsync(It.IsAny<string>())).ReturnsAsync(new ApplicationUser());
            var dto = new RegisterDto { Email = "a@b.com", Password = "123456", ConfirmPassword = "123456", FullName = "Test" };
            var (succeeded, errors) = await _service.RegisterAsync(dto);
            Assert.False(succeeded);
            Assert.Contains("Email already registered.", errors);
        }

        [Fact]
        public async Task LoginAsync_ReturnsError_WhenInvalidCredentials()
        {
            _userRepoMock.Setup(r => r.GetByEmailAsync(It.IsAny<string>())).ReturnsAsync((ApplicationUser?)null);
            var dto = new LoginDto { Email = "notfound@x.com", Password = "badpass" };
            var (succeeded, token, error) = await _service.LoginAsync(dto);
            Assert.False(succeeded);
            Assert.Equal("Invalid credentials.", error);
            Assert.Null(token);
        }

        [Fact]
        public async Task RegisterAsync_ReturnsError_WhenMissingFields()
        {
            var dto = new RegisterDto { Email = "", Password = "", ConfirmPassword = "", FullName = "" };
            var (succeeded, errors) = await _service.RegisterAsync(dto);
            Assert.False(succeeded);
            Assert.Contains("Email is required.", errors);
            Assert.Contains("Password is required.", errors);
        }

        [Fact]
        public async Task LoginAsync_ReturnsError_WhenMissingEmail()
        {
            var dto = new LoginDto { Email = "", Password = "123456" };
            var (succeeded, token, error) = await _service.LoginAsync(dto);
            Assert.False(succeeded);
            Assert.Equal("Email is required.", error);
            Assert.Null(token);
        }

        [Fact]
        public async Task LoginAsync_ReturnsError_WhenMissingPassword()
        {
            var dto = new LoginDto { Email = "valid@x.com", Password = "" };
            var (succeeded, token, error) = await _service.LoginAsync(dto);
            Assert.False(succeeded);
            Assert.Equal("Password is required.", error);
            Assert.Null(token);
        }

        [Fact]
        public async Task RegisterAsync_ReturnsSuccess_WhenValid()
        {
            _userRepoMock.Setup(r => r.GetByEmailAsync(It.IsAny<string>())).ReturnsAsync((ApplicationUser?)null);
            _userManagerMock.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);
            var dto = new RegisterDto { Email = "valid@x.com", Password = "123456", ConfirmPassword = "123456", FullName = "Test" };
            var (succeeded, errors) = await _service.RegisterAsync(dto);
            Assert.True(succeeded);
            Assert.Empty(errors);
        }

        [Fact]
        public async Task LoginAsync_ReturnsSuccess_WhenValid()
        {
            var user = new ApplicationUser { Id = Guid.NewGuid(), Email = "valid@x.com", FullName = "Test" };
            _userRepoMock.Setup(r => r.GetByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            _userManagerMock.Setup(m => m.CheckPasswordAsync(user, It.IsAny<string>())).ReturnsAsync(true);
            // Use a JWT key of at least 32 characters to satisfy HS256 requirements
            _configMock.Setup(c => c.GetSection("Jwt")["Key"]).Returns("supersecretkey1234567890supersecret!");
            _configMock.Setup(c => c.GetSection("Jwt")["Issuer"]).Returns("testissuer");
            _configMock.Setup(c => c.GetSection("Jwt")["Audience"]).Returns("testaudience");
            _configMock.Setup(c => c.GetSection("Jwt")["ExpiresInMinutes"]).Returns("60");
            var dto = new LoginDto { Email = "valid@x.com", Password = "123456" };
            var (succeeded, token, error) = await _service.LoginAsync(dto);
            Assert.True(succeeded);
            Assert.NotNull(token);
            Assert.Null(error);
        }

        [Fact]
        public async Task RegisterAsync_ReturnsError_WhenEmailIsNull()
        {
            var dto = new RegisterDto { Email = string.Empty, Password = "123456", ConfirmPassword = "123456", FullName = "Test" };
            var (succeeded, errors) = await _service.RegisterAsync(dto);
            Assert.False(succeeded);
            Assert.Contains("Email is required.", errors);
        }

        [Fact]
        public async Task LoginAsync_ReturnsError_WhenEmailIsNull()
        {
            var dto = new LoginDto { Email = string.Empty, Password = "123456" };
            var (succeeded, token, error) = await _service.LoginAsync(dto);
            Assert.False(succeeded);
            Assert.Equal("Email is required.", error);
            Assert.Null(token);
        }

        
    }
}
