using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class LoginUserViewModel
	{
		[Required]
		public required string Email { get; set; }

		[Required]
		[MinLength((8), ErrorMessage = "Password must be at least 8 characters long")]
		public required string Password { get; set; }
	}
}
