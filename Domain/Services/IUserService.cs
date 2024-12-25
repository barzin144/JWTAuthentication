using Domain.Entities;
using System.Threading.Tasks;

namespace Domain.Services
{
	public interface IUserService
	{
		Task<bool> AddUserAsync(User user);
		Task<User> FindUserByLoginAsync(string provider, string providerKey);
		Task<User> FindUserByEmailAsync(string email);
		ValueTask<User> FindUserByIdAsync(string userId);
		Task<bool> DeleteUserTokensByUserIdAsync(string userId);
		Task<bool> AddUserTokenByUserIdAsync(string userId, Token token);
		Task<bool> DeleteExpiredTokensAsync(string userId);
		Task<bool> DeleteTokensWithSameRefreshTokenSourceAsync(string refreshTokenIdHashSource, string userId);
		Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken);
		Task<User> GetCurrentUserDataAsync();
	}
}
