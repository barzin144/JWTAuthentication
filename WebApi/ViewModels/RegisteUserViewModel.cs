using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class RegisterUserViewModel
	{
		[Required]
		public string UserName { get; set; }
		
		[Required]
		[MinLength(6)]
		public string Password { get; set; }
		
		[Required]
		public string DisplayName { get; set; }
	}
}
