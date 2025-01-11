using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class ChangePasswordViewModel
	{
		[Required]
		[MinLength(8, ErrorMessage = "Password must be at least 8 characters long")]
		public required string OldPassword { get; set; }

		[Required]
		[MinLength(8, ErrorMessage = "Password must be at least 8 characters long")]
		public required string NewPassword { get; set; }

		[Required]
		[MinLength(8, ErrorMessage = "Password must be at least 8 characters long")]
		[Compare(nameof(NewPassword))]
		public required string ConfirmNewPassword { get; set; }
	}
}
