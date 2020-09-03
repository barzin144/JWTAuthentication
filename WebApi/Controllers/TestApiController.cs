using Domain.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace WebApi.Controllers
{
	[Route("api/[controller]/[action]")]
	[ApiController]
	[EnableCors("CorsPolicy")]
	[Authorize]
	public class TestApiController : ControllerBase
	{
		[HttpGet]
		public IActionResult GetDataIfAuthorized()
		{
			return Ok(new
			{
				Message = "If you can see this message that mean you were authorized."
			});
		}

		[HttpGet]
		[Authorize(Policy = CustomRoles.Admin)]
		public IActionResult GetDataIfIamAdmin()
		{
			return Ok(new
			{
				Message = "If you can seethis message that mean you have admin access."
			});
		}

		[HttpGet]
		[Authorize(Roles ="User,Admin")]
		public IActionResult GetDataIfIamAdminOrUser()
		{
			return Ok(new
			{
				Message = "If you can see this message that mean you have admin or user access."
			});
		}
	}
}
