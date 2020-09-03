using Domain.Entities;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccess
{
	public class MongoDbContext
	{
		private readonly IMongoDatabase mongoDatabase;

		public MongoDbContext(IMongoClient client, string dbName)
		{
			mongoDatabase = client.GetDatabase(dbName);
		}

		public IMongoCollection<User> Users => mongoDatabase.GetCollection<User>("Users");
		public IMongoCollection<T> GetCollection<T>(string name)
		{
			return mongoDatabase.GetCollection<T>(name);
		}
	}
}
