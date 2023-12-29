using DataAccess;
using Domain.Entities;
using Domain.Repositories;
using Domain.Services;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Service
{
	public class UserService : IUserService
	{
		private readonly IUserRepository userRepository;
		private readonly IHttpContextAccessor contextAccessor;
		private readonly ISecurityService securityService;

		public UserService(IUserRepository userRepository, IHttpContextAccessor contextAccessor, ISecurityService securityService)
		{
			this.userRepository = userRepository;
			this.contextAccessor = contextAccessor;
			this.securityService = securityService;
		}
		public async Task<bool> AddUserAsync(User user)
		{
			return await userRepository.InsertOneAsync(user);
		}

		public async Task<User> FindUserByUsernameAndPasswordAsync(string username, string password)
		{
			string passwordHash = securityService.GetSha256Hash(password);
			return await userRepository.FindUserByUsernameAndPasswordAsync(s => s.UserName == username && s.Password == passwordHash);
		}

		public async ValueTask<User> FindUserByIdAsync(string userId)
		{
			return await userRepository.FindByIdAsync(userId);
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
		
		public async Task<User> GetCurrentUserDataAsync()
		{
			ClaimsIdentity claimsIdentity = contextAccessor.HttpContext.User.Identity as ClaimsIdentity;

			string userId = claimsIdentity?.FindFirst(ClaimTypes.UserData).Value;
			return await FindUserByIdAsync(userId);
		}

		public async Task<bool> ChangePassword(string userId, string newPassword)
		{
			string newPasswordHash = securityService.GetSha256Hash(newPassword);
			string newSerialNumber = securityService.CreateCryptographicallySecureGuid().ToString();

			return await userRepository.ChangePassword(userId, newPasswordHash, newSerialNumber);
		}
	}
}
