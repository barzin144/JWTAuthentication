using System.Security.Claims;
using System.Text.Json;
using Domain.Entities;
using Domain.Enums;
using Domain.Models;
using Domain.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using WebApi.ViewModels;

namespace WebApi.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly OAuthOptions _oAuthOptions;
		private readonly JwtOptions _jwtOptions;
		private readonly IDataProtector _dataProtector;
		private readonly IUserService _userService;
		private readonly ISecurityService _securityService;
		private readonly IJwtTokenService _jwtTokenService;

		public AuthController(IOptions<OAuthOptions> oAuthOptions, IOptions<JwtOptions> jwtOptions, IDataProtectionProvider dataProtectionProvider, IUserService userService, ISecurityService securityService, IJwtTokenService jwtTokenService)
		{
			_oAuthOptions = oAuthOptions.Value;
			_jwtOptions = jwtOptions.Value;
			_dataProtector = dataProtectionProvider.CreateProtector(_jwtOptions.DataProtectionPurpose);
			_userService = userService;
			_securityService = securityService;
			_jwtTokenService = jwtTokenService;
		}

		[HttpPost("login")]
		public async Task<IActionResult> Login(LoginUserViewModel loginUser)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}

			User user = await _userService.FindUserByLoginAsync(loginUser.Email, Provider.Password, loginUser.Password);

			if (user == null)
			{
				return NotFound("User not found.");
			}
			if (user.IsActive == false)
			{
				return Unauthorized("User account is inactive.");
			}

			JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(user);

			await _jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

			AppendCookie(Response, new AuthCookie
			{
				AccessToken = jwtToken.AccessToken,
				RefreshToken = jwtToken.RefreshToken,
			});

			return Ok(
				new
				{
					user.Email,
					user.Name,
					Provider = user.Provider.ToString()
				}
			);
		}

		[HttpPost("register")]
		public async Task<IActionResult> Register(RegisterUserViewModel registerUser)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}
			if (await _userService.FindUserByEmailAsync(registerUser.Email) == null)
			{
				User newUser = new User
				{
					Name = registerUser.Name,
					Email = registerUser.Email,
					ProviderKey = _securityService.GetSha256Hash(registerUser.Password),
					Provider = Provider.Password,
					IsActive = true,
					Roles = [new Role { Name = "User" }],
					SerialNumber = _securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "")
				};

				await _userService.AddUserAsync(newUser);

				JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(newUser);

				await _jwtTokenService.AddUserTokenAsync(newUser, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

				AppendCookie(Response, new AuthCookie
				{
					AccessToken = jwtToken.AccessToken,
					RefreshToken = jwtToken.RefreshToken,
				});

				return Ok(new
				{
					newUser.Email,
					newUser.Name,
					Provider = newUser.Provider.ToString()
				});
			}
			else
			{
				return BadRequest("A user with this email already exists.");
			}
		}

		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		[HttpPost("change-password")]
		public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}

			User user = await _userService.GetCurrentUserDataAsync();

			if (user.ProviderKey != _securityService.GetSha256Hash(model.OldPassword))
			{
				return BadRequest("Incorrect old password.");
			}

			if (await _userService.ChangePassword(user.Id, model.NewPassword))
			{
				return Ok(new { message = "Password changed successfully." });
			}

			return BadRequest("Failed to change password.");

		}


		[HttpGet("google-login")]
		public IActionResult GoogleLogin()
		{
			var properties = new AuthenticationProperties
			{
				RedirectUri = _oAuthOptions.GoogleCallbackURL
			};
			return Challenge(properties, GoogleDefaults.AuthenticationScheme);
		}

		[HttpGet("google-callback")]
		public async Task<IActionResult> GoogleCallbackAsync()
		{
			var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

			if (!authenticateResult.Succeeded)
			{
				return BadRequest("Google authentication failed.");
			}

			var claims = authenticateResult.Principal.Claims;

			var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
			ArgumentNullException.ThrowIfNull(email, nameof(email));

			var name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
			ArgumentNullException.ThrowIfNull(name, nameof(name));

			var nameIdentifier = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
			ArgumentNullException.ThrowIfNull(nameIdentifier, nameof(nameIdentifier));

			var user = await _userService.FindUserByLoginAsync(email, Provider.Google, nameIdentifier);

			if (user == null)
			{
				user = new User
				{
					Name = name,
					Email = email,
					ProviderKey = _securityService.GetSha256Hash(nameIdentifier),
					Provider = Provider.Google,
					IsActive = true,
					Roles = [new Role { Name = "User" }],
					SerialNumber = _securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "")
				};
				await _userService.AddUserAsync(user);
			}

			if (user.IsActive == false)
			{
				return Unauthorized("User account is inactive.");
			}

			JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(user);

			await _jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

			AppendCookie(Response, new AuthCookie
			{
				AccessToken = jwtToken.AccessToken,
				RefreshToken = jwtToken.RefreshToken,
			});

			return Ok(new
			{
				user.Email,
				user.Name,
				Provider = user.Provider.ToString()
			});
		}

		[HttpGet("refresh-token")]
		public async Task<IActionResult> RefreshToken()
		{
			AuthCookie authResponse = ReadCookie(Request);
			if (authResponse == null)
			{
				return Unauthorized("No authentication cookie found.");
			}
			string refreshToken = authResponse.RefreshToken;
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				return BadRequest("Refresh token is not set.");
			}

			try
			{
				(Token token, User user) = await _jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);
				if (token == null)
				{
					return Unauthorized("Invalid refresh token.");
				}

				var result = _jwtTokenService.CreateJwtTokens(user);
				await _jwtTokenService.AddUserTokenAsync(user, result.RefreshTokenSerial, result.AccessToken, _jwtTokenService.GetRefreshTokenSerial(refreshToken));

				AppendCookie(Response, new AuthCookie
				{
					AccessToken = result.AccessToken,
					RefreshToken = result.RefreshToken,
				});

				return Ok(new { message = "Token refreshed successfully." });
			}
			catch
			{
				return BadRequest("Invalid refresh token.");
			}
		}

		[HttpGet("logout")]
		public async Task<IActionResult> Logout()
		{
			AuthCookie authResponse = ReadCookie(Request);
			if (authResponse == null)
			{
				return Ok(new { message = "You have logged out successfully." });
			}
			string refreshToken = authResponse.RefreshToken;
			(Token token, User user) = await _jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);

			if (token != null)
			{
				await _jwtTokenService.RevokeUserBearerTokensAsync(user.Id, refreshToken);
			}

			Response.Cookies.Delete(_jwtOptions.CookieName);
			return Ok(new { message = "You have logged out successfully." });
		}

		private void AppendCookie(HttpResponse response, AuthCookie authCookie)
		{
			response.Cookies.Append(_jwtOptions.CookieName, _dataProtector.Protect(JsonSerializer.Serialize(authCookie)), new CookieOptions
			{
				HttpOnly = true,
				Secure = true,
				SameSite = SameSiteMode.Strict,
				Expires = DateTimeOffset.Now.AddMinutes(_jwtOptions.RefreshTokenExpirationMinutes)
			});
		}

		private AuthCookie ReadCookie(HttpRequest request)
		{
			if (request.Cookies.TryGetValue(_jwtOptions.CookieName, out string cookieValue))
			{
				return JsonSerializer.Deserialize<AuthCookie>(_dataProtector.Unprotect(cookieValue));
			}
			return null;
		}
	}
}
