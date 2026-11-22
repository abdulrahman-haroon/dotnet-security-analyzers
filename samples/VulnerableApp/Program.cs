// Deliberately insecure demo. Each commented line triggers a DSA rule. Never deploy this app.
using System.Text;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// DSA002: trusts every origin AND sends cookies, so any website can call the API as the logged-in user.
builder.Services.AddCors(options => options.AddPolicy("spa", policy =>
    policy.SetIsOriginAllowed(_ => true).AllowCredentials()));

// DSA003: signing key written in source (even via a variable). The value is fake, for the demo only.
var signingKey = "FAKE-DEMO-KEY-do-not-use-0000000000000000";
builder.Services.AddSingleton<SecurityKey>(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)));

// DSA005: the session cookie can be read by JavaScript and sent over plain HTTP.
builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = false;
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;
});

// DSA004: SignalR sends exception details to clients; identity logs include personal data.
builder.Services.AddSignalR(options => options.EnableDetailedErrors = true);
Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;

var app = builder.Build();

// DSA004: shows stack traces to everyone, including in production.
app.UseDeveloperExceptionPage();

app.UseCors("spa");
app.UseSession();
app.MapControllers();

// DSA001: minimal API endpoint that anyone can call.
app.MapPost("/api/transfer", (decimal amount) => Results.Ok(amount));

// No warning: the group requires authorization.
var admin = app.MapGroup("/api/admin").RequireAuthorization();
admin.MapDelete("/users/{id}", (int id) => Results.NoContent());

app.Run();
