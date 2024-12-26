# Micro IDP Service

## Features:

- Sign up with Email
- Sign in with Email
- Sign in with Google
- Generate JWT
- Generate Refresh Token

## Usage

- #### Generate Private and Public key

  - C# Interactive

    ```C#
    using System.Security.Cryptography;
    using (var rsa = RSA.Create(2048))
    {
    	// Export the private key
    	var privateKey = rsa.ExportRSAPrivateKey();
    	var privateKeyBase64 = Convert.ToBase64String(privateKey);
    	Console.WriteLine("Private Key:");
    	Console.WriteLine(privateKeyBase64);

    	// Export the public key
    	var publicKey = rsa.ExportRSAPublicKey();
    	var publicKeyBase64 = Convert.ToBase64String(publicKey);
    	Console.WriteLine("\nPublic Key:");
    	Console.WriteLine(publicKeyBase64);
    }
    ```

  - BASH

    ```SHELL
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    cat private_key.pem | base64

    openssl rsa -pubout -in private_key.pem -out public_key.pem
    cat public_key.pem | base64
    ```

- #### Replace PRIVATE_KEY placeholder in docker-compose.yml with generated private key

  ```YML
  webapi:
  		build: .
  		ports:
  			- 8000:80
  			- 8001:443
  		environment:
  			JWT__PrivateKey: "PRIVATE_KEY"
  ```

- #### Generate certificate to host application with docker over HTTPS

  - windows

    ```SHELL
    dotnet dev-certs https -ep %USERPROFILE%\.aspnet\https\aspnetapp.pfx -p <CREDENTIAL_PLACEHOLDER>
    dotnet dev-certs https --trust
    ```

    In the preceding commands, replace <CREDENTIAL_PLACEHOLDER> with a password.

  - Linux

    ```SHELL
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout aspnetcore.key -out aspnetcore.crt -subj "/CN=localhost"
    ```

    ```SHELL
    openssl pkcs12 -export -out aspnetcore.pfx -inkey aspnetcore.key -in aspnetcore.crt
    ```

  Replace **_ASPNETCORE_Kestrel\_\_Certificates\_\_Default\_\_Password_** with certificate password in docker-compose.yml

  Replace volume mount source with generated certificate path in docker-compose.yml

  ```YML
  volumes:
  	- type: bind
  		source: ./aspnetcore.pfx
  		target: /https/aspnetcore.pfx
  ```

- #### Sing in with Google configuration

  - Create OAuth2.0 client in [Google Cloud Console](https://console.cloud.google.com).
  - Replace **_OAuth_GoogleClientId_** placeholder in docker-compose.yml
  - Replace **_OAuth_GoogleClientSecret_** placeholder in docker-compose.yml
  - Replace **_OAuth_GoogleCallBackURL_** placeholder in docker-compose.yml with your client app google callback page (this page should call https://IDP_SERVER_URL/api/auth/google-callback to get JWT)

- #### Run IDP

  ```SHELL
  docker compose up --wait
  ```

### Client App

- #### Add Jwt section to you appsettings.json

  ```JSON
  "Jwt": {
  	"PublicKey": "PUBLIC_KEY",
  	"Issuer": "https://localhost:8001",
  	"Audience": "http://localhost:5010"
  }
  ```

  Replace PUBLIC_KEY placeholder with generated public key

- #### Install JwtBearer package
  ```SHELL
  dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
  ```
- #### Add Authentication middleware

  ```C#
  var rsa = RSA.Create();
  rsa.ImportRSAPublicKey(Convert.FromBase64String(configuration["Jwt:PublicKey"] ?? ""), out _);

  services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(options =>
  {
  	options.TokenValidationParameters = new TokenValidationParameters
  	{
  		ValidateIssuer = true,
  		ValidateAudience = true,
  		ValidateLifetime = true,
  		ValidateIssuerSigningKey = true,
  		ValidIssuer = configuration["Jwt:Issuer"],
  		ValidAudience = configuration["Jwt:Audience"],
  		IssuerSigningKey = new RsaSecurityKey(rsa)
  	};
  });
  ```
