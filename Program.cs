using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Proj.Data;
using Proj.DTOs;
using Proj.Models;
using Proj.Repositories;
using Proj.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
{
    options.User.RequireUniqueEmail = true;
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IUserRepository, UserRepository>();

builder.Services.AddControllers();

var jwtSettings = builder.Configuration.GetSection("Jwt");
var jwtKey = jwtSettings["Key"];
if (string.IsNullOrWhiteSpace(jwtKey))
    throw new InvalidOperationException("JWT Key is missing from configuration.");
var key = Encoding.UTF8.GetBytes(jwtKey);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
    options.AddPolicy("FrontendPolicy", policy =>
    {
        policy.WithOrigins("http://localhost:5173") // Update if your frontend runs on a different port
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

// Global exception handling middleware
app.UseMiddleware<Proj.Middleware.ExceptionMiddleware>();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseCors("FrontendPolicy");

app.MapPost("/api/auth/register", async (
    RegisterDto dto,
    UserManager<ApplicationUser> userManager,
    IConfiguration config
) =>
{
    // Defensive: treat null as empty for all fields
    var email = dto.Email ?? string.Empty;
    var password = dto.Password ?? string.Empty;
    var confirmPassword = dto.ConfirmPassword ?? string.Empty;
    var fullName = dto.FullName ?? string.Empty;
    var errors = new List<string>();
    if (string.IsNullOrWhiteSpace(email)) errors.Add("Email is required.");
    if (string.IsNullOrWhiteSpace(password)) errors.Add("Password is required.");
    if (errors.Count > 0) return Results.BadRequest(new { errors });
    if (password != confirmPassword)
        return Results.BadRequest(new { message = "Passwords do not match." });

    var existingUser = await userManager.FindByEmailAsync(email);
    if (existingUser != null)
        return Results.BadRequest(new { message = "Email already registered." });

    var user = new ApplicationUser
    {
        Id = Guid.NewGuid(),
        FullName = fullName,
        Email = email,
        UserName = email
    };
    var result = await userManager.CreateAsync(user, password);
    if (!result.Succeeded)
        return Results.BadRequest(result.Errors);

    return Results.Ok(new { message = "Registration successful." });
});

app.MapPost("/api/auth/login", async (
    LoginDto dto,
    UserManager<ApplicationUser> userManager,
    IConfiguration config
) =>
{
    var user = await userManager.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
    if (user == null)
        return Results.BadRequest(new { message = "Invalid credentials." });

    var passwordValid = await userManager.CheckPasswordAsync(user, dto.Password);
    if (!passwordValid)
        return Results.BadRequest(new { message = "Invalid credentials." });

    var jwtSettings = config.GetSection("Jwt");
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.Email, user.Email!),
        new Claim("FullName", user.FullName)
    };
    var token = new JwtSecurityToken(
        issuer: jwtSettings["Issuer"],
        audience: jwtSettings["Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(int.Parse(jwtSettings["ExpiresInMinutes"]!)),
        signingCredentials: creds
    );
    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
    return Results.Ok(new { token = tokenString });
});

app.MapControllers();

app.Run();

namespace Proj // Ensure namespace is public for test accessibility
{
    public partial class Program { }
}
