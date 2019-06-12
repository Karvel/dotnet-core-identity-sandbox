using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using dotnet_core_identity_sandbox.Areas.Identity.Data;
using dotnet_core_identity_sandbox.Models;

namespace dotnet_core_identity_sandbox.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<UserEntity> _userManager;
        private readonly SignInManager<UserEntity> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly IPasswordHasher<UserEntity> _passwordHasher;
        private readonly IEmailSender _emailSender;

        public AccountController(
            UserManager<UserEntity> userManager,
            SignInManager<UserEntity> signInManager,
            ILogger<AccountController> logger,
            IPasswordHasher<UserEntity> passwordHasher,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _passwordHasher = passwordHasher;
            _emailSender = emailSender;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Login credentials)
        {  
            if (ModelState.IsValid)
            {
                var user = new UserEntity { UserName = credentials.Email, Email = credentials.Email };
                var result =  await _userManager.CreateAsync(user, credentials.Password);
                
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackUrl = Url.Page(
                        "/Account/ConfirmEmail",
                        pageHandler: null,
                        values: new { userId = user.Id, code = code },
                        protocol: Request.Scheme);

                    await _emailSender.SendEmailAsync(credentials.Email, "Confirm your email",
                        $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                    return Ok();
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            
            return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login credentials)
        {
			if (credentials == null)
			{
				return BadRequest("User is null.");
			}

			if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(credentials.Email, credentials.Password, isPersistent: false, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    return Ok();
                }
                if (result.IsLockedOut)
                {
                    return BadRequest("Invalid login attempt.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return BadRequest("Invalid login attempt.");
                }
            }

            return BadRequest("Invalid login attempt.");
        }
    }
}
