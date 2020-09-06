using Domain.Entities;
using System.Threading.Tasks;

namespace Domain.Services
{
	public interface IUserService
	{
		Task<bool> AddUserAsync(User user);
		Task<User> FindUserByUsernameAndPasswordAsync(string username, string password);
		Task<User> FindUserByUsernameAsync(string username);
		ValueTask<User> FindUserByIdAsync(string userId);
		Task<bool> DeleteUserTokensByUserIdAsync(string userId);
		Task<bool> AddUserTokenByUserIdAsync(string userId, Token token);
		Task UpdateUserLastActivityDateAsync(User user);
		Task<Token> FindTokenByUserIdAndAccessTokenAsync(string userId, string accessTokenHash);
		Task<bool> DeleteExpiredTokensAsync(string userId);
		Task<bool> DeleteTokensWithSameRefreshTokenSourceAsync(string refreshTokenIdHashSource, string userId);
		Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken);
		Task<User> GetCurrentUserDataAsync();
		Task<bool> ChangePassword(string userId, string newPassword);
	}
}
