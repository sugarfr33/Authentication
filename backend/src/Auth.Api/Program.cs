using Auth.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthServices(builder.Configuration);

var app = builder.Build();

app.Run();
