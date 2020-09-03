namespace Domain.Models
{
	public class JwtOptions
	{
		public string Key { set; get; }
		public string Issuer { set; get; }
		public string Audience { set; get; }
		public int AccessTokenExpirationMinutes { set; get; }
		public int RefreshTokenExpirationMinutes { set; get; }
		public bool AllowMultipleLoginsFromTheSameUser { set; get; }
		public bool AllowSignoutAllUserActiveClients { set; get; }
	}
}
