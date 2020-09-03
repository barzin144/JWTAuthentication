using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Repositories
{
	public interface IBaseRepository<T> where T:class
	{
		Task<bool> InsertOneAsync(T entity);
		Task<T> FindById(string Id);
	}
}
