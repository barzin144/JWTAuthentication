using Domain.Entities;
using MongoDB.Driver;

namespace DataAccess
{
	public interface IMongoDbContext
	{
		IMongoCollection<T> GetCollection<T>(string name);
	}

	public class MongoDbContext : IMongoDbContext
	{
		private readonly IMongoDatabase _mongoDatabase;

		public MongoDbContext(IMongoClient client, string dbName)
		{
			_mongoDatabase = client.GetDatabase(dbName);
		}

		public IMongoCollection<T> GetCollection<T>(string name)
		{
			return _mongoDatabase.GetCollection<T>(name);
		}
	}
}
