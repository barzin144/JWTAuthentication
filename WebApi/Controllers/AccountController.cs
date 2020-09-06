using System.Collections.Generic;
using System.Threading.Tasks;
using Domain.Entities;
using Domain.Models;
using Domain.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using WebApi.ViewModels;

namespace WebApi.Controllers
{
	[Route("api/[controller]/[action]")]
	[ApiController]
	[EnableCors("CorsPolicy")]
	[AllowAnonymous]
	public class AccountController : ControllerBase
	{
		private readonly IUserService userService;
		private readonly ISecurityService securityService;
		private readonly IJwtTokenService jwtTokenService;

		public AccountController(IUserService userService, ISecurityService securityService, IJwtTokenService jwtTokenService)
		{
			this.userService = userService;
			this.securityService = securityService;
			this.jwtTokenService = jwtTokenService;
		}

		[HttpPost]
		public async Task<IActionResult> Login(LoginUserViewModel loginUser)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}

			User user = await userService.FindUserByUsernameAndPasswordAsync(loginUser.UserName, loginUser.Password);

			if (user == null)
			{
				return NotFound();
			}
			if (user.IsActive == false)
			{
				return Unauthorized();
			}

			JwtTokensData jwtToken = jwtTokenService.CreateJwtTokens(user);

			await jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

			return Ok(new { accessToken = jwtToken.AccessToken, refreshToken = jwtToken.RefreshToken });
		}

		[HttpPost]
		public async Task<IActionResult> Register(RegisteUserViewModel newUser)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}
			if (userService.FindUserByUsernameAsync(newUser.UserName).Result == null)
			{
				User user = new User
				{
					UserName = newUser.UserName,
					Password = securityService.GetSha256Hash(newUser.Password),
					DisplayName = newUser.DisplayName,
					IsActive = true,
					Roles = new List<Role>() { new Role { Name = "User" } },
					SerialNumber = securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "")
				};

				await userService.AddUserAsync(user);

				JwtTokensData jwtToken = jwtTokenService.CreateJwtTokens(user);

				await jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

				return Ok(new { accessToken = jwtToken.AccessToken, refreshToken = jwtToken.RefreshToken });
			}
			else
			{
				return BadRequest("User with this username has exsit.");
			}
		}
		[Authorize]
		[HttpPost]
		public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}

			User user = await userService.GetCurrentUserDataAsync();

			if (user.Password != securityService.GetSha256Hash(model.OldPassword))
			{
				return BadRequest("Old password is wrong.");
			}

			if (await userService.ChangePassword(user.Id, model.NewPassword))
			{
				return Ok(new { message = "password changed successfully."});
			}

			return BadRequest("change password failed.");

		}

		[HttpPost]
		public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenViewModel model)
		{
			string refreshToken = model.RefreshToken;
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				return BadRequest("refreshToken is not set.");
			}

			(Token token, User user) = await jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);
			if (token == null)
			{
				return Unauthorized();
			}

			var result = jwtTokenService.CreateJwtTokens(user);
			await jwtTokenService.AddUserTokenAsync(user, result.RefreshTokenSerial, result.AccessToken, jwtTokenService.GetRefreshTokenSerial(refreshToken));

			return Ok(new { access_token = result.AccessToken, refresh_token = result.RefreshToken });
		}

		[HttpPost]
		public async Task<IActionResult> Logout([FromBody] RefreshTokenViewModel model)
		{
			string refreshToken = model.RefreshToken;
			(Token token, User user) = await jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);

			if (token == null)
			{
				return Unauthorized();
			}

			await jwtTokenService.RevokeUserBearerTokensAsync(user.Id, refreshToken);

			return Ok(new { message = "You loged out successfully." });
		}

	}
}
