using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers;

[ApiController]
[Route("api/accounts")]
public class AccountsController : ControllerBase
{
    // DSA001: anyone can read any account balance; there is no [Authorize].
    [HttpGet("{id}/balance")]
    public IActionResult GetBalance(int id) => Ok(new { id, balance = 100m });

    // No warning: intentionally public, and says so.
    [AllowAnonymous]
    [HttpGet("/health")]
    public IActionResult Health() => Ok("healthy");
}
