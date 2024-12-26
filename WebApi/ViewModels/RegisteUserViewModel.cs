using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class RegisterUserViewModel
	{
		[Required]
		[EmailAddress]
		public string Email { get; set; }

		[Required]
		[MinLength(6)]
		public string Password { get; set; }

		[Required]
		public string Name { get; set; }
	}
}
