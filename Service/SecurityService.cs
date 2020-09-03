using Domain.Services;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Service
{
	public class SecurityService : ISecurityService
  {
    private readonly RandomNumberGenerator _rand = RandomNumberGenerator.Create();

    public string GetSha256Hash(string input)
    {
      using SHA256CryptoServiceProvider hashAlgorithm = new SHA256CryptoServiceProvider();
      var byteValue = Encoding.UTF8.GetBytes(input);
      var byteHash = hashAlgorithm.ComputeHash(byteValue);
      return Convert.ToBase64String(byteHash);
    }

    public Guid CreateCryptographicallySecureGuid()
    {
			byte[] bytes = new byte[16];
      _rand.GetBytes(bytes);
      return new Guid(bytes);
    }
  }
}
