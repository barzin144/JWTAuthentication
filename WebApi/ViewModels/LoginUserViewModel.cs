using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class LoginUserViewModel
	{
		[Required]
		public string Email { get; set; }

		[Required]
		[MinLength(6)]
		public string Password { get; set; }
	}
}
