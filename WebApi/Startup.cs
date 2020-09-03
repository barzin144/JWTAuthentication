using IoCConfig;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;

namespace WebApi
{
	public class Startup
	{
		private readonly IConfiguration configuration;

		public Startup(IConfiguration configuration)
		{
			this.configuration = configuration;
		}
		public void ConfigureServices(IServiceCollection services)
		{
			services.AddCustomOptions(configuration);
			services.AddCustomServices();
			services.AddCustomJwtBearer(configuration);
			services.AddCustonCors();
			services.AddControllers();
			services.AddCustomSwagger();
			services.AddCustomMongoDbService(configuration);
		}
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}

			app.UseSwagger();
			app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "JWT Authentication API V1"); });

			app.UseStatusCodePages();
			app.UseRouting();
			app.UseAuthentication();
			app.UseCors("CorsPolicy");
			app.UseAuthorization();

			app.UseEndpoints(endpoints =>
			{
				endpoints.MapControllers();
			});
		}
	}
}
