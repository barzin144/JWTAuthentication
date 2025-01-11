using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class RegisterUserViewModel
	{
		[Required]
		[EmailAddress]
		public required string Email { get; set; }

		[Required]
		[MinLength((8), ErrorMessage = "Password must be at least 8 characters long")]
		public required string Password { get; set; }

		[Required]
		public required string Name { get; set; }
	}
}
