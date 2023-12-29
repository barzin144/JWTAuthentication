using Domain.Repositories;
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
    }
}