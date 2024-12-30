using IoCConfig;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

var services = builder.Services;
var configuration = builder.Configuration;
Log.Logger = new LoggerConfiguration().ReadFrom.Configuration(configuration).CreateLogger();

services.AddCustomOptions(configuration);
services.AddCustomServices();
services.AddCustomAuthentication(configuration);
services.AddCustomCors(configuration);
services.AddControllers();
services.AddCustomSwagger();
services.AddCustomMongoDbService(configuration);
services.AddSerilog();

var app = builder.Build();

if (configuration.GetValue<bool>("EnableSwagger"))
{
	app.UseSwagger();
	app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "Micro IDP API V1"); });
}

app.UseCors("CorsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.UseSerilogRequestLogging();
app.MapControllers();

app.Run();