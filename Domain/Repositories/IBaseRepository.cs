using System.Threading.Tasks;

namespace Domain.Repositories
{
	public interface IBaseRepository<T> where T:class
	{
		Task<bool> InsertOneAsync(T entity);
		Task<T> FindByIdAsync(string Id);
	}
}
