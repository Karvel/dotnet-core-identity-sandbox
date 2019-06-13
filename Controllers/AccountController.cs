using System.Linq;
using System.Threading.Tasks;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using dotnet_core_identity_sandbox.Areas.Identity.Data;
using dotnet_core_identity_sandbox.Models;
using Models.Managers;

namespace dotnet_core_identity_sandbox.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly AccountManager _accountManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly IEmailSender _emailSender;
        private readonly IConfiguration _configuration;

        public AccountController(
            AccountManager accountManager,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<AccountController> logger,
            IEmailSender emailSender,
            IConfiguration configuration)
        {
            _accountManager = accountManager;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register credentials)
        {  
            if (ModelState.IsValid)
            {
                var newUser = new ApplicationUser {
                    FirstName = credentials.FirstName,
                    LastName = credentials.LastName,
                    UserName = credentials.Email,
                    Email = credentials.Email,
                };
                IdentityResult result =  await _userManager.CreateAsync(newUser, credentials.Password);
                
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    ApplicationUser user =  await _userManager.FindByEmailAsync(credentials.Email);
                    
                    if (user.Email != null)
                    {
                        _logger.LogInformation("Setting User role to Consumer");

                        // TODO: Replace magic string
                        await _userManager.AddToRoleAsync(user, "Consumer");
                    }

                    string code = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                    string callbackUrl = Url.Page(
                        "/Account/ConfirmEmail",
                        pageHandler: null,
                        values: new { area = "Identity", userId = newUser.Id, code = code },
                        protocol: Request.Scheme);

                    await _emailSender.SendEmailAsync(credentials.Email, "Confirm your email",
                        $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
                    return Ok();
                }
                foreach (IdentityError error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            
            return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
        }

        [HttpPost("login")]
        public async Task<ActionResult<JWTToken>> Login([FromBody] Login credentials)
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
                    ApplicationUser appUser = _userManager.Users.SingleOrDefault(user => user.Email == credentials.Email);
                    JWTToken jwt = new JWTToken {
                        Token = await _accountManager.GenerateJwtToken(credentials.Email, appUser),
                    };
                    return Ok(jwt);
                }
                if (result.IsLockedOut)
                {
                    return BadRequest("Account is locked.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return BadRequest("Invalid login attempt.");
                }
            }

            return BadRequest("Invalid login attempt.");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] Login credentials)
        {
            if (ModelState.IsValid)
            {
                ApplicationUser user = await _userManager.FindByEmailAsync(credentials.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return Ok();
                }

                // For more information on how to enable account confirmation and password reset please 
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                string code = await _userManager.GeneratePasswordResetTokenAsync(user);
                string callbackUrl = Url.Page(
                    "/Account/ResetPassword",
                    pageHandler: null,
                    values: new { area = "Identity", code },
                    protocol: Request.Scheme);

                await _emailSender.SendEmailAsync(
                    credentials.Email,
                    "Reset Password",
                    $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
                return Ok();
            }

            return BadRequest("Password reset failed.");
        }
    }
}
