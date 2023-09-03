using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using ScrumboardAPI.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;

namespace ScrumboardAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly User _user;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;

            // Initialize a default user for testing purposes
            _user = new User();
            _user.Username = "testuser";
            _user.PasswordHash = BCrypt.Net.BCrypt.HashPassword("testpassword");
        }

        // Endpoint for user registration
        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            // Hash the incoming password using BCrypt
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            // Update the _user object with the new user information
            _user.Username = request.Username;
            _user.PasswordHash = passwordHash;

            // Return the user object (this is typically where you'd save the user to a database)
            return Ok(_user);
        }

        // Endpoint for user login
        [HttpPost("login")]
        public ActionResult<string> Login(UserDto request)
        {
            // Check if the provided username matches the stored user's username
            if (_user.Username != request.Username)
            {
                return BadRequest("User not found");
            }

            // Verify the provided password against the stored password hash using BCrypt
            if (!BCrypt.Net.BCrypt.Verify(request.Password, _user.PasswordHash))
            {
                return BadRequest("Wrong password.");
            }

            // Create a JWT token for the authenticated user
            string token = CreateToken(_user);

            // Return the JWT token to the client
            return Ok(token);
        }

        // Helper method to create a JWT token for a user
        private string CreateToken(User user)
        {
            // Define claims for the JWT token (in this case, the user's name)
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            // Generate a symmetric security key
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            // Create signing credentials using the security key and HMAC-SHA512 signature algorithm
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            // Create a JWT token with the specified claims, expiration, and signing credentials
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),  // Token expiration time 
                signingCredentials: creds
            );

            // Serialize the JWT token into a string
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            // Return the JWT token
            return jwt;
        }
    }
}
