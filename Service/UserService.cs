using DataAccess;
using Domain.Entities;
using Domain.Repositories;
using Domain.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Service
{
	public class UserService : IUserService
	{
		private readonly IUserRepository userRepository;

		public UserService(IUserRepository userRepository)
		{
			this.userRepository = userRepository;
		}
		public async Task<bool> AddUserAsync(User user)
		{
			return await userRepository.InsertOneAsync(user);
		}

		public async Task<User> FindUserByUsernameAndPasswordAsync(string username, string password)
		{
			return await userRepository.FindUserByUsernameAndPasswordAsync(username, password);
		}

		public async ValueTask<User> FindUserByIdAsync(string userId)
		{
			return await userRepository.FindById(userId);
		}

		public async Task UpdateUserLastActivityDateAsync(User user)
		{
			await userRepository.UpdateUserLastActivityDateAsync(user);
		}

		public async Task<bool> DeleteUserTokensByUserIdAsync(string userId)
		{
			return await userRepository.DeleteUserTokensByUserIdAsync(userId);
		}

		public async Task<bool> AddUserTokenByUserIdAsync(string userId, Token token)
		{
			return await userRepository.AddUserTokenByUserIdAsync(userId, token);
		}

		public async Task<Token> FindTokenByUserIdAndAccessTokenAsync(string userId, string accessTokenHash)
		{
			return await userRepository.FindTokenByUserIdAndAccessTokenAsync(userId, accessTokenHash);
		}

		public async Task<bool> DeleteExpiredTokensAsync(string userId)
		{
			return await userRepository.DeleteExpiredTokensAsync(userId);
		}

		public async Task<bool> DeleteTokensWithSameRefreshTokenSourceAsync(string refreshTokenIdHashSource, string userId)
		{
			return await userRepository.DeleteTokensWithSameRefreshTokenSourceAsync(refreshTokenIdHashSource, userId);
		}

		public async Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken)
		{
			return await userRepository.FindUserAndTokenByRefreshTokenAsync(refreshToken);
		}

		public async Task<User> FindUserByUsernameAsync(string username)
		{
			return await userRepository.FindUserByUsernameAsync(username);
		}
	}
}
