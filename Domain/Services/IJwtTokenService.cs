using Domain.Entities;
using Domain.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Threading.Tasks;

namespace Domain.Services
{
	public interface IJwtTokenService
	{
		Task ValidateAsync(TokenValidatedContext context);
		Task<bool> IsValidTokenAsync(string accessToken, string userId);
		JwtTokensData CreateJwtTokens(User user);
		Task AddUserTokenAsync(User user, string refreshTokenSerial, string accessToken, string refreshTokenSourceSerial);
		string GetRefreshTokenSerial(string refreshTokenValue);
		Task<bool> DeleteExpiredTokensAsync(string userId);
		Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken);
		Task RevokeUserBearerTokensAsync(string userId, string refreshToken);
	}
}
