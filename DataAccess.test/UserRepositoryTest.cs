using Domain.Entities;
using Domain.Repositories;
using MongoDB.Driver;
using Service;

namespace DataAccess.test;

public class UserRepositoryTest
{
    private UserRepository _userRepository;
    private SecurityService _securityService;
    private Mock<IMongoDbContext> _mongodbContext;
    private Mock<IBaseRepository<User>> _baseRepository;

    public UserRepositoryTest()
    {
        _securityService = new SecurityService();

        _mongodbContext = new Mock<IMongoDbContext>();
        _baseRepository = new Mock<IBaseRepository<User>>();
        // _mongoCollection = new Mock<IMongoCollection<User>>();
        // var a = new Mock<IFindFluent<User, User>>();
        // a.Setup(x => x.SingleOrDefaultAsync(default)).Returns(() => Task<User>.FromResult(new User
        // {
        //     UserName = "a",
        //     Password = "b"
        // }));

        // _mongodbContext.Setup(_ => _.GetCollection<User>("Users")).Returns(_mongoCollection.Object);

        // _mongoCollection.Setup(_ => _.Find(It.IsAny<FilterDefinition<User>>(), null)).Returns(() => a);

        _userRepository = new UserRepository(_mongodbContext.Object, _securityService);
    }
    [Fact]
    public void FindUserByUsernameAndPasswordAsync_ShouldFindUserByUsernameAndPassword()
    {
    }
}