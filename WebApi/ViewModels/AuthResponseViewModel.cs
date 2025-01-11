using System;

namespace WebApi.ViewModels;

public class AuthResponseViewModel
{
	public required string Email { get; set; }
	public required string Name { get; set; }
	public required string Provider { get; set; }
}