using Domain.Enums;

namespace WebApi.ViewModels;

public class AuthResponseViewModel
{
	public string Name { get; set; }
	public string Email { get; set; }
	public string Provider { get; set; }
	public string AccessToken { get; set; }
	public string RefreshToken { get; set; }
}
