using Service;
using Domain.Models;
using Domain.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using System.Collections.Generic;
using DataAccess;
using MongoDB.Driver;
using Domain.Repositories;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace IoCConfig
{
	public static class ConfigureServicesExtensions
	{
		public static void AddCustomCors(this IServiceCollection services)
		{
			services.AddCors(options =>
			options.AddPolicy("CorsPolicy",
			builder => builder
				.WithOrigins("http://localhost:5000")
				.AllowAnyMethod()
				.AllowAnyHeader()
				.SetIsOriginAllowed((host) => true)
				.AllowCredentials()
			));
		}

		public static void AddCustomAuthentication(this IServiceCollection services, IConfiguration configuration)
		{
			var rsa = RSA.Create();
			rsa.ImportRSAPrivateKey(Convert.FromBase64String(configuration["Jwt:PrivateKey"] ?? ""), out _);
			services.AddAuthentication(options =>
			{
				options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
				options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
			})
			.AddCookie()
			.AddGoogle(options =>
			{
				options.ClientId = configuration["OAuth:GoogleClientId"] ?? "";
				options.ClientSecret = configuration["OAuth:GoogleClientSecret"] ?? "";
				options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
			})
			.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
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
		}

		public static void AddCustomServices(this IServiceCollection services)
		{
			services.AddScoped<IJwtTokenService, JwtTokenService>();
			services.AddScoped<IUserService, UserService>();
			services.AddSingleton<ISecurityService, SecurityService>();
			services.AddScoped<IUserRepository, UserRepository>();
			services.AddHttpContextAccessor();
		}

		public static void AddCustomOptions(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddOptions<JwtOptions>().Bind(configuration.GetSection("Jwt"));
		}

		public static void AddCustomSwagger(this IServiceCollection services)
		{

			services.AddSwaggerGen(options =>
			{
				options.SwaggerDoc("v1", new OpenApiInfo
				{
					Title = "JWT Authentication API Document",
					Version = "v1"
				});

				options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
				{
					Description = @"JWT Authorization header using the Bearer scheme.",
					Name = "Authorization",
					In = ParameterLocation.Header,
					Type = SecuritySchemeType.ApiKey,
					Scheme = "Bearer"
				});

				options.AddSecurityRequirement(new OpenApiSecurityRequirement() { { new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }, Scheme = "oauth2", Name = "Bearer", In = ParameterLocation.Header, }, new List<string>() } });
			});
		}

		public static void AddCustomMongoDbService(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddSingleton<IMongoClient>(s => new MongoClient(configuration.GetConnectionString("MongoDb")));
			services.AddScoped<IMongoDbContext>(s => new MongoDbContext(s.GetRequiredService<IMongoClient>(), configuration["DbName"]));
		}
	}
}
