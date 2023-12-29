using System;
using Service;
using System.Text;
using Domain.Models;
using Domain.Services;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using System.Collections.Generic;
using DataAccess;
using Microsoft.AspNetCore.Mvc.Formatters;
using MongoDB.Driver;
using Domain.Repositories;

namespace IoCConfig
{
	public static class ConfigureServicesExtensions
	{
		public static void AddCustonCors(this IServiceCollection services)
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

		public static void AddCustomJwtBearer(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddAuthorization(options =>
			{
				options.AddPolicy(CustomRoles.Admin, policy => policy.RequireRole(CustomRoles.Admin));
				options.AddPolicy(CustomRoles.User, policy => policy.RequireRole(CustomRoles.User));
			});

			services.AddAuthentication(options =>
		 {
			 options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
			 options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
			 options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
		 })
			.AddJwtBearer(configureOptions =>
			{
				configureOptions.RequireHttpsMetadata = false;
				configureOptions.SaveToken = true;
				configureOptions.TokenValidationParameters = new TokenValidationParameters
				{
					ValidIssuer = configuration["Jwt:Issuer"],
					ValidateIssuer = true,
					ValidAudience = configuration["Jwt:Audience"],
					ValidateAudience = true,
					IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"])),
					ValidateIssuerSigningKey = true,
					ValidateLifetime = true,
					ClockSkew = TimeSpan.Zero
				};
				configureOptions.Events = new JwtBearerEvents
				{
					OnTokenValidated = context =>
					{
						IJwtTokenService jwtTokenService = context.HttpContext.RequestServices.GetRequiredService<IJwtTokenService>();
						return jwtTokenService.ValidateAsync(context);
					}
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
					Description = @"JWT Authorization header using the Bearer scheme. \r\n\r\n 
                      Enter 'Bearer' [space] and then your token in the text input below.
                      \r\n\r\nExample: 'Bearer 12345abcdef'",
					Name = "Authorization",
					In = ParameterLocation.Header,
					Type = SecuritySchemeType.ApiKey,
					Scheme = "Bearer"
				});

				options.AddSecurityRequirement(new OpenApiSecurityRequirement()
								{
										{
												new OpenApiSecurityScheme
												{
														Reference = new OpenApiReference
														{
																Type = ReferenceType.SecurityScheme,
																Id = "Bearer"
														},
														Scheme = "oauth2",
														Name = "Bearer",
														In = ParameterLocation.Header,

												},
												new List<string>()
										}
								});
			});
		}

		public static void AddCustomMongoDbService(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddSingleton<IMongoClient>(s => new MongoClient(configuration.GetConnectionString("MongoDb")));
			services.AddScoped<IMongoDbContext>(s => new MongoDbContext(s.GetRequiredService<IMongoClient>(), configuration["DbName"]));
		}
	}
}
