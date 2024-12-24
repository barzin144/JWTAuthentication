using Domain.Entities;
using Domain.Models;
using Domain.Services;
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
		private readonly IOptionsSnapshot<JwtOptions> jwtOption;

		public JwtTokenService(IUserService userService, ISecurityService securityService, IOptionsSnapshot<JwtOptions> jwtOption)
		{
			this.userService = userService;
			this.securityService = securityService;
			this.jwtOption = jwtOption;
		}

		public async Task AddUserTokenAsync(User user, string refreshTokenSerial, string accessToken, string refreshTokenSourceSerial)
		{
			var now = DateTimeOffset.UtcNow;
			var token = new Token
			{
				RefreshTokenIdHash = securityService.GetSha256Hash(refreshTokenSerial),
				RefreshTokenIdHashSource = string.IsNullOrWhiteSpace(refreshTokenSourceSerial) ? null : securityService.GetSha256Hash(refreshTokenSourceSerial),
				AccessTokenHash = securityService.GetSha256Hash(accessToken),
				RefreshTokenExpiresDateTime = now.AddMinutes(jwtOption.Value.RefreshTokenExpirationMinutes),
				AccessTokenExpiresDateTime = now.AddMinutes(jwtOption.Value.AccessTokenExpirationMinutes)
			};

			await userService.DeleteTokensWithSameRefreshTokenSourceAsync(token.RefreshTokenIdHashSource, user.Id);
			await AddUserTokenAsync(token, user.Id);
		}

		public JwtTokensData CreateJwtTokens(User user)
		{
			var (accessToken, claims) = CreateAccessToken(user);
			var (refreshTokenValue, refreshTokenSerial) = CreateRefreshToken();
			return new JwtTokensData
			{
				AccessToken = accessToken,
				Claims = claims,
				RefreshToken = refreshTokenValue,
				RefreshTokenSerial = refreshTokenSerial
			};
		}

		private (string AccessToken, IEnumerable<Claim> Claims) CreateAccessToken(User user)
		{
			string jwtIssuer = jwtOption.Value.Issuer;

			List<Claim> claims = [
			new Claim(JwtRegisteredClaimNames.Jti, securityService.CreateCryptographicallySecureGuid().ToString(), ClaimValueTypes.String, jwtIssuer),
			new Claim(JwtRegisteredClaimNames.Iss, jwtIssuer, ClaimValueTypes.String, jwtIssuer),
			new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64, jwtIssuer),
			new Claim(ClaimTypes.NameIdentifier, user.Id.ToString(), ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.Name, user.UserName, ClaimValueTypes.String, jwtIssuer),
			new Claim("DisplayName", user.DisplayName, ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.SerialNumber, user.SerialNumber, ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.UserData, user.Id.ToString(), ClaimValueTypes.String, jwtIssuer)
			];

			foreach (Role role in user.Roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role.Name, ClaimValueTypes.String, jwtIssuer));
			}

			SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOption.Value.Key));
			SigningCredentials credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			DateTime now = DateTime.UtcNow;

			JwtSecurityToken token = new JwtSecurityToken(
				issuer: jwtIssuer,
				audience: jwtOption.Value.Audience,
				claims: claims,
				notBefore: now,
				expires: now.AddMinutes(jwtOption.Value.AccessTokenExpirationMinutes),
				signingCredentials: credential
			);

			return (new JwtSecurityTokenHandler().WriteToken(token), claims);
		}

		private (string RefreshTokenValue, string RefreshTokenSerial) CreateRefreshToken()
		{
			string jwtIssuer = jwtOption.Value.Issuer;

			string refreshTokenSerial = securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "");

			List<Claim> claims = new List<Claim>
						{
								new Claim(JwtRegisteredClaimNames.Jti, securityService.CreateCryptographicallySecureGuid().ToString(), ClaimValueTypes.String, jwtIssuer),
								new Claim(JwtRegisteredClaimNames.Iss, jwtIssuer, ClaimValueTypes.String, jwtIssuer),
								new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64, jwtIssuer),
								new Claim(ClaimTypes.SerialNumber, refreshTokenSerial, ClaimValueTypes.String, jwtIssuer)
						};
			SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOption.Value.Key));
			SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
			DateTime now = DateTime.UtcNow;
			JwtSecurityToken token = new JwtSecurityToken(
					issuer: jwtIssuer,
					audience: jwtOption.Value.Audience,
					claims: claims,
					notBefore: now,
					expires: now.AddMinutes(jwtOption.Value.RefreshTokenExpirationMinutes),
					signingCredentials: creds);
			string refreshTokenValue = new JwtSecurityTokenHandler().WriteToken(token);

			return (refreshTokenValue, refreshTokenSerial);
		}

		private async Task AddUserTokenAsync(Token userToken, string userId)
		{
			if (!jwtOption.Value.AllowMultipleLoginsFromTheSameUser)
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
							IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOption.Value.Key)),
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
				if (jwtOption.Value.AllowSignoutAllUserActiveClients)
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
