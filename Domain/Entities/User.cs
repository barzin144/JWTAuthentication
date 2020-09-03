using Domain.Models;
using System;
using System.Collections.Generic;

namespace Domain.Entities
{
	public class User : BaseEntity
	{
		public User()
		{
			Roles = new HashSet<Role>();
			Tokens = new List<Token>();
		}
		public string UserName { get; set; }
		public string Password { get; set; }
		public string DisplayName { get; set; }
		public bool IsActive { get; set; }
		public DateTimeOffset? LastLoggedIn { get; set; }
		public string SerialNumber { get; set; }

		public ICollection<Role> Roles { get; set; }
		public List<Token> Tokens { get; set; }
	}
}
