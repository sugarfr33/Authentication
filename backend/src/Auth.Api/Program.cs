using Auth.Services;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthServices(builder.Configuration);

WebApplication app = builder.Build();

app.Run();
