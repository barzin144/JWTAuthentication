using IoCConfig;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

var services = builder.Services;
var configuration = builder.Configuration;
Log.Logger = new LoggerConfiguration().ReadFrom.Configuration(configuration).CreateLogger();

services.AddCustomOptions(configuration);
services.AddCustomServices();
services.AddCustomAuthentication(configuration);
services.AddCustomCors();
services.AddControllers();
services.AddCustomSwagger();
services.AddCustomMongoDbService(configuration);
services.AddSerilog();

var app = builder.Build();


if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "JWT Authentication API V1"); });
}

app.UseHttpsRedirection();
app.UseCors("CorsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.UseSerilogRequestLogging();
app.MapControllers();

app.Run();