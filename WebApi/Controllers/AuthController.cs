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
using WebApi.ViewModels;

namespace WebApi.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly IUserService _userService;
		private readonly ISecurityService _securityService;
		private readonly IJwtTokenService _jwtTokenService;

		public AuthController(IUserService userService, ISecurityService securityService, IJwtTokenService jwtTokenService)
		{
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

			return Ok(new { accessToken = jwtToken.AccessToken, refreshToken = jwtToken.RefreshToken });
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

				return Ok(new { accessToken = jwtToken.AccessToken, refreshToken = jwtToken.RefreshToken });
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
				RedirectUri = Url.Action("GoogleCallback")
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

				return Ok(new { accessToken = jwtToken.AccessToken, refreshToken = jwtToken.RefreshToken });

			}
			else
			{
				if (user.IsActive == false)
				{
					return Unauthorized();
				}

				JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(user);

				await _jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

				return Ok(new { accessToken = jwtToken.AccessToken, refreshToken = jwtToken.RefreshToken });

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

			return Ok(new { access_token = result.AccessToken, refresh_token = result.RefreshToken });
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
