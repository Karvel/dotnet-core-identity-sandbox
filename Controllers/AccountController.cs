using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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
        private readonly IPasswordHasher<UserEntity> _passwordHasher;

        public AccountController(
            UserManager<UserEntity> userManager,
            SignInManager<UserEntity> signInManager,
            IPasswordHasher<UserEntity> passwordHasher)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordHasher = passwordHasher;
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] Login credentials)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }
            
            var user = new UserEntity { UserName = credentials.Email, Email = credentials.Email };
            var result =  await _userManager.CreateAsync(user, credentials.Password);
            
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors.Select(x => x.Description).ToList());
            }
            
            await _signInManager.SignInAsync(user, false);
            
            return Ok();
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

            // If we got this far, something failed, redisplay form
            return BadRequest("Invalid login attempt.");
        }
    }
}
