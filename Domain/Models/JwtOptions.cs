namespace Domain.Models
{
	public class JwtOptions
	{
		public string PrivateKey { set; get; }
		public string Issuer { set; get; }
		public string Audience { set; get; }
		public int AccessTokenExpirationMinutes { set; get; }
		public int RefreshTokenExpirationMinutes { set; get; }
		public bool AllowMultipleLoginsFromTheSameUser { set; get; }
		public bool AllowSignoutAllUserActiveClients { set; get; }
		public string DataProtectionApplicationName { get; set; }
		public string DataProtectionKeysPath { get; set; }
		public string DataProtectionPurpose { get; set; }
		public string CookieName { get; set; }

	}
}
