# Dev_5iveApp ASP.NET Core User Account API

A professional, portable RESTful API for user account management, built with ASP.NET Core (.NET 8), Entity Framework Core (SQLite), Identity, and JWT authentication.

## Features
- User registration, login, JWT auth
- Profile management (get/update)
- Change password, deactivate (soft delete)
- Password reset (forgot/reset)
- Layered architecture: Controllers → Services → Repositories → DTOs
- Global exception handling
- CORS enabled for React frontend

## Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
- No database install required (uses SQLite)

## Setup Instructions
1. **Clone the repository**
   ```sh
   git clone <your-repo-url>
   cd Dev_5iveApp/Proj
   ```
2. **Restore dependencies**
   ```sh
   dotnet restore
   ```
3. **Apply migrations and create the SQLite database**
   ```sh
   dotnet ef database update
   ```
4. **Run the API**
   ```sh
   dotnet run
   ```
   The API will be available at `https://localhost:5001` or `http://localhost:5000` by default.

## Sample Request/Response Payloads

### Register
**POST** `/api/auth/register`
```json
{
  "fullName": "Jane Doe",
  "email": "jane@example.com",
  "password": "Password123!",
  "confirmPassword": "Password123!"
}
```
**Response:**
```json
{
  "message": "Registration successful."
}
```

### Login
**POST** `/api/auth/login`
```json
{
  "email": "jane@example.com",
  "password": "Password123!"
}
```
**Response:**
```json
{
  "token": "<jwt-token>"
}
```

### Get Profile
**GET** `/api/user/profile` (Requires Bearer token)
**Response:**
```json
{
  "fullName": "Jane Doe",
  "email": "jane@example.com",
  "profileImageUrl": null
}
```

### Update Profile
**PUT** `/api/user/profile` (Requires Bearer token)
```json
{
  "fullName": "Jane Doe",
  "email": "jane@example.com",
  "profileImageUrl": "https://example.com/avatar.jpg"
}
```
**Response:**
```json
{
  "message": "Profile updated."
}
```

### Change Password
**PUT** `/api/user/change-password` (Requires Bearer token)
```json
{
  "oldPassword": "Password123!",
  "newPassword": "NewPassword456!",
  "confirmPassword": "NewPassword456!"
}
```
**Response:**
```json
{
  "message": "Password changed successfully."
}
```

### Deactivate Account
**POST** `/api/user/deactivate` (Requires Bearer token)
**Response:**
```json
{
  "message": "Account deactivated."
}
```

### Forgot Password
**POST** `/api/auth/forgot-password`
```json
{
  "email": "jane@example.com"
}
```
**Response:**
```json
{
  "message": "Password reset token generated.",
  "token": "<reset-token>"
}
```

### Reset Password
**POST** `/api/auth/reset-password`
```json
{
  "email": "jane@example.com",
  "token": "<reset-token>",
  "newPassword": "NewPassword456!",
  "confirmPassword": "NewPassword456!"
}
```
**Response:**
```json
{
  "message": "Password reset successful."
}
```
## Testing Instructions

To run all unit and integration tests:

```sh
cd Dev_5iveApp/Proj
 dotnet test
```

- This will automatically build the project and run all tests in the `Tests` folder.
- Make sure you have the .NET 8 SDK installed.
- No additional setup is required; the test configuration uses an in-memory or SQLite database and injects test secrets.

## Notes
- All protected endpoints require a valid JWT Bearer token in the `Authorization` header.
- CORS is enabled for `http://localhost:5173` (React frontend default).
- For demo/interview, password reset tokens are returned in the response (in production, send via email).
- The API will not be available until you start the application (e.g., by running dotnet run or starting the project in Visual Studio). Make sure the server is running before trying to access any endpoints.

---
## Local Secrets

- The file `appsettings.Local.json` is gitignored and should be created locally for secrets.
- Example:
  {
    "Jwt": {
      "Key": "your-32-char-real-secret-key-here",
      "Issuer": "ProjApi",
      "Audience": "ProjApiUsers",
      "ExpiresInMinutes": 60
    }
  }
- The default `appsettings.json` only contains placeholders.

For any issues, please open an issue or contact the maintainer.
