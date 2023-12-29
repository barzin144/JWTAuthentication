using Domain.Entities;
using Domain.Models;
using Domain.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Service
{
	public class JwtTokenService : IJwtTokenService
	{
		private readonly IUserService userService;
		private readonly ISecurityService securityService;
		private readonly IOptionsSnapshot<JwtOptions> jwtOptionSpanshot;

		public JwtTokenService(IUserService userService, ISecurityService securityService, IOptionsSnapshot<JwtOptions> jwtOptionSpanshot)
		{
			this.userService = userService;
			this.securityService = securityService;
			this.jwtOptionSpanshot = jwtOptionSpanshot;
		}

		public async Task AddUserTokenAsync(User user, string refreshTokenSerial, string accessToken, string refreshTokenSourceSerial)
		{
			var now = DateTimeOffset.UtcNow;
			var token = new Token
			{
				RefreshTokenIdHash = securityService.GetSha256Hash(refreshTokenSerial),
				RefreshTokenIdHashSource = string.IsNullOrWhiteSpace(refreshTokenSourceSerial) ?
																		 null : securityService.GetSha256Hash(refreshTokenSourceSerial),
				AccessTokenHash = securityService.GetSha256Hash(accessToken),
				RefreshTokenExpiresDateTime = now.AddMinutes(jwtOptionSpanshot.Value.RefreshTokenExpirationMinutes),
				AccessTokenExpiresDateTime = now.AddMinutes(jwtOptionSpanshot.Value.AccessTokenExpirationMinutes)
			};

			await userService.DeleteTokensWithSameRefreshTokenSourceAsync(token.RefreshTokenIdHashSource, user.Id);
			await AddUserTokenAsync(token, user.Id);
		}

		public JwtTokensData CreateJwtTokens(User user)
		{
			var (accessToken, claims) = createAccessToken(user);
			var (refreshTokenValue, refreshTokenSerial) = createRefreshToken();
			return new JwtTokensData
			{
				AccessToken = accessToken,
				Claims = claims,
				RefreshToken = refreshTokenValue,
				RefreshTokenSerial = refreshTokenSerial
			};
		}

		public async Task<bool> IsValidTokenAsync(string accessToken, string userId)
		{
			var accessTokenHash = securityService.GetSha256Hash(accessToken);
			var userToken = await userService.FindTokenByUserIdAndAccessTokenAsync(userId, accessTokenHash);
			return userToken?.AccessTokenExpiresDateTime >= DateTimeOffset.UtcNow;
		}

		public async Task ValidateAsync(TokenValidatedContext context)
		{
			ClaimsIdentity claimsIdentity = context.Principal.Identity as ClaimsIdentity;

			if (claimsIdentity?.Claims == null || claimsIdentity.Claims.Any() == false)
			{
				context.Fail("This is not out issued token. It has no claims.");
				return;
			}

			Claim serialNumberClaim = claimsIdentity.FindFirst(ClaimTypes.SerialNumber);
			if (serialNumberClaim == null)
			{
				context.Fail("This is not out issued token. It has no serial.");
				return;
			}

			string userId = claimsIdentity.FindFirst(ClaimTypes.UserData).Value;
			if (string.IsNullOrWhiteSpace(userId))
			{
				context.Fail("This is not out issued token. It has no user-id.");
				return;
			}

			User user = await userService.FindUserByIdAsync(userId);
			if (user == null || user.SerialNumber != serialNumberClaim.Value || user.IsActive == false)
			{
				// user has changed his/her password/roles/stat/IsActive
				context.Fail("This token is expired. Please login again.");
			}

			if (!(context.SecurityToken is JwtSecurityToken accessToken) || string.IsNullOrWhiteSpace(accessToken.RawData) || !await IsValidTokenAsync(accessToken.RawData, userId))
			{
				context.Fail("This token is not in out database");
				return;
			}

			await userService.UpdateUserLastActivityDateAsync(user);

		}

		private (string AccessToken, IEnumerable<Claim> Claims) createAccessToken(User user)
		{
			string jwtIssuer = jwtOptionSpanshot.Value.Issuer;

			List<Claim> claims = new List<Claim> {
			new Claim(JwtRegisteredClaimNames.Jti, securityService.CreateCryptographicallySecureGuid().ToString(), ClaimValueTypes.String, jwtIssuer),
			new Claim(JwtRegisteredClaimNames.Iss, jwtIssuer, ClaimValueTypes.String, jwtIssuer),
			new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64, jwtIssuer),
			new Claim(ClaimTypes.NameIdentifier, user.Id.ToString(), ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.Name, user.UserName, ClaimValueTypes.String, jwtIssuer),
			new Claim("DisplayName", user.DisplayName, ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.SerialNumber, user.SerialNumber, ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.UserData, user.Id.ToString(), ClaimValueTypes.String, jwtIssuer)
			};

			List<Role> roles = user.Roles.ToList();
			foreach (Role role in roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role.Name, ClaimValueTypes.String, jwtIssuer));
			}

			SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptionSpanshot.Value.Key));
			SigningCredentials credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			DateTime now = DateTime.UtcNow;

			JwtSecurityToken token = new JwtSecurityToken(
				issuer: jwtIssuer,
				audience: jwtOptionSpanshot.Value.Audience,
				claims: claims,
				notBefore: now,
				expires: now.AddMinutes(jwtOptionSpanshot.Value.AccessTokenExpirationMinutes),
				signingCredentials: credential
			);

			return (new JwtSecurityTokenHandler().WriteToken(token), claims);
		}

		private (string RefreshTokenValue, string RefreshTokenSerial) createRefreshToken()
		{
			string jwtIssuer = jwtOptionSpanshot.Value.Issuer;

			string refreshTokenSerial = securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "");

			List<Claim> claims = new List<Claim>
						{
								new Claim(JwtRegisteredClaimNames.Jti, securityService.CreateCryptographicallySecureGuid().ToString(), ClaimValueTypes.String, jwtIssuer),
								new Claim(JwtRegisteredClaimNames.Iss, jwtIssuer, ClaimValueTypes.String, jwtIssuer),
								new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64, jwtIssuer),
								new Claim(ClaimTypes.SerialNumber, refreshTokenSerial, ClaimValueTypes.String, jwtIssuer)
						};
			SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptionSpanshot.Value.Key));
			SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
			DateTime now = DateTime.UtcNow;
			JwtSecurityToken token = new JwtSecurityToken(
					issuer: jwtIssuer,
					audience: jwtOptionSpanshot.Value.Audience,
					claims: claims,
					notBefore: now,
					expires: now.AddMinutes(jwtOptionSpanshot.Value.RefreshTokenExpirationMinutes),
					signingCredentials: creds);
			string refreshTokenValue = new JwtSecurityTokenHandler().WriteToken(token);

			return (refreshTokenValue, refreshTokenSerial);
		}

		private async Task AddUserTokenAsync(Token userToken, string userId)
		{
			if (!jwtOptionSpanshot.Value.AllowMultipleLoginsFromTheSameUser)
			{
				await InvalidateUserTokensAsync(userId);
			}
			await DeleteExpiredTokensAsync(userId);
			await userService.AddUserTokenByUserIdAsync(userId, userToken);
		}

		private async Task InvalidateUserTokensAsync(string userId)
		{
			await userService.DeleteUserTokensByUserIdAsync(userId);
		}

		public string GetRefreshTokenSerial(string refreshTokenValue)
		{
			if (string.IsNullOrWhiteSpace(refreshTokenValue))
			{
				return null;
			}

			ClaimsPrincipal decodedRefreshTokenPrincipal = null;
			try
			{
				decodedRefreshTokenPrincipal = new JwtSecurityTokenHandler().ValidateToken(
						refreshTokenValue,
						new TokenValidationParameters
						{
							RequireExpirationTime = true,
							ValidateIssuer = false,
							ValidateAudience = false,
							IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptionSpanshot.Value.Key)),
							ValidateIssuerSigningKey = true,
							ValidateLifetime = true,
							ClockSkew = TimeSpan.Zero
						},
						out _
				);
			}
			catch
			{
				throw;
			}

			return decodedRefreshTokenPrincipal?.Claims?.FirstOrDefault(c => c.Type == ClaimTypes.SerialNumber)?.Value;
		}

		public async Task<bool> DeleteExpiredTokensAsync(string userId)
		{
			return await userService.DeleteExpiredTokensAsync(userId);
		}

		public async Task RevokeUserBearerTokensAsync(string userId, string refreshToken)
		{
			if (!string.IsNullOrWhiteSpace(userId))
			{
				if (jwtOptionSpanshot.Value.AllowSignoutAllUserActiveClients)
				{
					await InvalidateUserTokensAsync(userId);
				}
			}

			if (!string.IsNullOrWhiteSpace(refreshToken))
			{
				var refreshTokenSerial = GetRefreshTokenSerial(refreshToken);
				if (!string.IsNullOrWhiteSpace(refreshTokenSerial))
				{
					var refreshTokenIdHashSource = securityService.GetSha256Hash(refreshTokenSerial);
					await userService.DeleteTokensWithSameRefreshTokenSourceAsync(refreshTokenIdHashSource, userId);
				}
			}

			await DeleteExpiredTokensAsync(userId);
		}

		public async Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken)
		{
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				throw new Exception("Invalid refresh token");
			}
			string refreshTokenSerial = GetRefreshTokenSerial(refreshToken);
			if (string.IsNullOrWhiteSpace(refreshTokenSerial))
			{
				throw new Exception("Invalid refresh token");
			}
			return await userService.FindUserAndTokenByRefreshTokenAsync(refreshTokenSerial);
		}
	}
}
