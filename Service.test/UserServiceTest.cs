using Domain.Repositories;
using System.Linq.Expressions;
using Domain.Entities;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Service.test;

public class UserServiceTest
{
    private Mock<IUserRepository> _userRepository;
    private readonly Mock<IHttpContextAccessor> _httpContextAccessor;
    private readonly SecurityService _securityService;
    private readonly UserService _userService;

    public UserServiceTest()
    {
        _userRepository = new Mock<IUserRepository>();
        _httpContextAccessor = new Mock<IHttpContextAccessor>();
        _securityService = new SecurityService();
        _userService = new UserService(_userRepository.Object, _httpContextAccessor.Object, _securityService);
    }

    [Fact]
    public async void FindUserByUsernameAndPasswordAsync_ShouldSendCorrectFilter()
    {
        //Arrange
        string username = "abc";
        string password = "abc";
        string passwordHash = _securityService.GetSha256Hash(password);
        //Act
        var result = await _userService.FindUserByUsernameAndPasswordAsync(username, password);
        //Assert
        _userRepository.Verify(x => x.FindUserByUsernameAndPasswordAsync(s => s.UserName == username && s.Password == passwordHash), Times.Once);
        _userRepository.Verify(x => x.FindUserByUsernameAndPasswordAsync(It.IsAny<Expression<Func<User, bool>>>()), Times.Once);
    }

    [Fact]
    public async void AddUserAsync_ShouldCallInsertOneAsync()
    {
        //Arrange
        User newUser = new User();
        //Act
        var result = await _userService.AddUserAsync(newUser);
        //Assert
        _userRepository.Verify(x => x.InsertOneAsync(newUser), Times.Once);
    }

    [Fact]
    public async void FindUserByIdAsync_ShouldCallFindByIdAsync()
    {
        //Arrange
        string userID = "abc";
        //Act
        var result = await _userService.FindUserByIdAsync(userID);
        //Assert
        _userRepository.Verify(x => x.FindByIdAsync(userID), Times.Once);
    }

    [Fact]
    public async void DeleteUserTokensByUserIdAsync_ShouldCallDeleteUserTokensByUserIdAsync()
    {
        //Arrange
        string userID = "abc";
        //Act
        var result = await _userService.DeleteUserTokensByUserIdAsync(userID);
        //Assert
        _userRepository.Verify(x => x.DeleteUserTokensByUserIdAsync(userID), Times.Once);
    }

    [Fact]
    public async void AddUserTokenByUserIdAsync_ShouldCallAddUserTokenByUserIdAsync()
    {
        //Arrange
        string userID = "abc";
        Token token = new Token()
        {
            AccessTokenHash = "abc"
        };
        //Act
        var result = await _userService.AddUserTokenByUserIdAsync(userID, token);
        //Assert
        _userRepository.Verify(x => x.AddUserTokenByUserIdAsync(userID, token), Times.Once);
    }

    [Fact]
    public async void DeleteExpiredTokensAsync_ShouldCallDeleteExpiredTokensAsync()
    {
        //Arrange
        string userID = "abc";
        //Act
        var result = await _userService.DeleteExpiredTokensAsync(userID);
        //Assert
        _userRepository.Verify(x => x.DeleteExpiredTokensAsync(userID), Times.Once);
    }

    [Fact]
    public async void DeleteTokensWithSameRefreshTokenSourceAsync_ShouldCallDeleteTokensWithSameRefreshTokenSourceAsync()
    {
        //Arrange
        string userID = "abc";
        string refreshTokenIdHashSource = "abc";
        //Act
        var result = await _userService.DeleteTokensWithSameRefreshTokenSourceAsync(refreshTokenIdHashSource, userID);
        //Assert
        _userRepository.Verify(x => x.DeleteTokensWithSameRefreshTokenSourceAsync(refreshTokenIdHashSource, userID), Times.Once);
    }

    [Fact]
    public async void FindUserAndTokenByRefreshTokenAsync_ShouldCallFindUserAndTokenByRefreshTokenAsync()
    {
        //Arrange
        string refreshToekn = "abc";
        //Act
        var result = await _userService.FindUserAndTokenByRefreshTokenAsync(refreshToekn);
        //Assert
        _userRepository.Verify(x => x.FindUserAndTokenByRefreshTokenAsync(refreshToekn), Times.Once);
    }

    [Fact]
    public async void FindUserByUsernameAsync_ShouldCallFindUserByUsernameAsync()
    {
        //Arrange
        string username = "abc";
        //Act
        var result = await _userService.FindUserByUsernameAsync(username);
        //Assert
        _userRepository.Verify(x => x.FindUserByUsernameAsync(username), Times.Once);
    }

    [Fact]
    public async void GetCurrentUserDataAsync_ShouldCallFindByIdAsync()
    {
        //Arrange
        string userId = "abc";
        var claims = new List<Claim> { new Claim(ClaimTypes.UserData, userId) };
        _httpContextAccessor.Setup(req => req.HttpContext!.User.Identity).Returns(new ClaimsIdentity(claims));
        //Act
        var result = await _userService.GetCurrentUserDataAsync();
        //Assert
        _userRepository.Verify(x => x.FindByIdAsync(userId), Times.Once);
    }

    [Fact]
    public void ChangePassword_ShouldCallChangePassword()
    {
        //Arrange
        string newPassword = "abc";
        string userID = "abc";
        string newPasswordHash = _securityService.GetSha256Hash(newPassword);
        //Act
        var result = _userService.ChangePassword(userID, newPassword);
        //Assert
        _userRepository.Verify(x => x.ChangePassword(userID, newPasswordHash, It.IsAny<string>()), Times.Once);
    }
}