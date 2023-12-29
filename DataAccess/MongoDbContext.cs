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
		private readonly IMongoDatabase mongoDatabase;

		public MongoDbContext(IMongoClient client, string dbName)
		{
			mongoDatabase = client.GetDatabase(dbName);
		}

		public IMongoCollection<T> GetCollection<T>(string name)
		{
			return mongoDatabase.GetCollection<T>(name);
		}
	}
}
