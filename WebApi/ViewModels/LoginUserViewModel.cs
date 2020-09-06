using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class LoginUserViewModel
	{
		[Required]
		public string UserName { get; set; }
		
		[Required]
		[MinLength(6)]
		public string Password { get; set; }
	}
}
