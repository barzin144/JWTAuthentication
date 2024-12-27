using System.Security.Claims;
using Domain.Entities;
using Domain.Enums;
using Domain.Models;
using Domain.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
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
		private readonly IUserService _userService;
		private readonly ISecurityService _securityService;
		private readonly IJwtTokenService _jwtTokenService;

		public AuthController(IOptions<OAuthOptions> oAuthOptions, IUserService userService, ISecurityService securityService, IJwtTokenService jwtTokenService)
		{
			_oAuthOptions = oAuthOptions.Value;
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
				return NotFound();
			}
			if (user.IsActive == false)
			{
				return Unauthorized();
			}

			JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(user);

			await _jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

			return Ok(new AuthResponseViewModel
			{
				AccessToken = jwtToken.AccessToken,
				RefreshToken = jwtToken.RefreshToken,
				Email = user.Email,
				Name = user.Name,
				Provider = user.Provider.ToString()
			});
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

				return Ok(new AuthResponseViewModel
				{
					AccessToken = jwtToken.AccessToken,
					RefreshToken = jwtToken.RefreshToken,
					Email = newUser.Email,
					Name = newUser.Name,
					Provider = newUser.Provider.ToString()
				});
			}
			else
			{
				return BadRequest("User with this Email has exist.");
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
				return BadRequest("Old password is wrong.");
			}

			if (await _userService.ChangePassword(user.Id, model.NewPassword))
			{
				return Ok(new { message = "password changed successfully." });
			}

			return BadRequest("change password failed.");

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
				return BadRequest("Authentication failed");
			}

			var claims = authenticateResult.Principal.Claims;

			var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
			ArgumentNullException.ThrowIfNull(email, nameof(email));

			var name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
			ArgumentNullException.ThrowIfNull(name, nameof(name));

			var nameIdentifier = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
			ArgumentNullException.ThrowIfNull(nameIdentifier, nameof(nameIdentifier));

			var user = await _userService.FindUserByLoginAsync(email, Provider.Google, nameIdentifier);

			if (user is null)
			{
				User newUser = new User
				{
					Name = name,
					Email = email,
					ProviderKey = _securityService.GetSha256Hash(nameIdentifier),
					Provider = Provider.Google,
					IsActive = true,
					Roles = [new Role { Name = "User" }],
					SerialNumber = _securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "")
				};

				await _userService.AddUserAsync(newUser);

				JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(newUser);

				await _jwtTokenService.AddUserTokenAsync(newUser, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

				return Ok(new AuthResponseViewModel
				{
					AccessToken = jwtToken.AccessToken,
					RefreshToken = jwtToken.RefreshToken,
					Email = newUser.Email,
					Name = newUser.Name,
					Provider = newUser.Provider.ToString()
				});

			}
			else
			{
				if (user.IsActive == false)
				{
					return Unauthorized();
				}

				JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(user);

				await _jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

				return Ok(new AuthResponseViewModel
				{
					AccessToken = jwtToken.AccessToken,
					RefreshToken = jwtToken.RefreshToken,
					Email = user.Email,
					Name = user.Name,
					Provider = user.Provider.ToString()
				});
			}
		}

		[HttpPost("refresh-token")]
		public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenViewModel model)
		{
			string refreshToken = model.RefreshToken;
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				return BadRequest("refreshToken is not set.");
			}

			(Token token, User user) = await _jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);
			if (token == null)
			{
				return Unauthorized();
			}

			var result = _jwtTokenService.CreateJwtTokens(user);
			await _jwtTokenService.AddUserTokenAsync(user, result.RefreshTokenSerial, result.AccessToken, _jwtTokenService.GetRefreshTokenSerial(refreshToken));

			return Ok(new AuthResponseViewModel
			{
				AccessToken = result.AccessToken,
				RefreshToken = result.RefreshToken,
				Email = user.Email,
				Name = user.Name,
				Provider = user.Provider.ToString()
			});
		}

		[HttpPost("logout")]
		public async Task<IActionResult> Logout([FromBody] RefreshTokenViewModel model)
		{
			string refreshToken = model.RefreshToken;
			(Token token, User user) = await _jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);

			if (token == null)
			{
				return Unauthorized();
			}

			await _jwtTokenService.RevokeUserBearerTokensAsync(user.Id, refreshToken);

			return Ok(new { message = "You logged out successfully." });
		}
	}
}
