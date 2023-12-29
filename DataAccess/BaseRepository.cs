using Domain.Entities;
using Domain.Repositories;
using MongoDB.Driver;
using System;
using System.Threading.Tasks;

namespace DataAccess
{
	public class BaseRepository<T> : IBaseRepository<T> where T : BaseEntity
	{
		protected IMongoCollection<T> collection = null;
		public BaseRepository(IMongoDbContext mongoDbContext)
		{
			collection = mongoDbContext.GetCollection<T>($"{typeof(T).Name}s");
		}

		public async Task<T> FindByIdAsync(string Id)
		{
			return await collection.Find(x => x.Id == Id).SingleOrDefaultAsync();
		}

		public async Task<bool> InsertOneAsync(T entity)
		{
			try
			{
				await collection.InsertOneAsync(entity);
				return true;
			}
			catch
			{
				throw;
			}
		}
	}
}
