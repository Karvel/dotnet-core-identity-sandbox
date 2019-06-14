using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

using dotnet_core_identity_sandbox.Areas.Identity.Data;
using dotnet_core_identity_sandbox.Services;
using Models.Managers;

namespace dotnet_core_identity_sandbox
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddTransient<IEmailSender, EmailSender>();
			services
			   .AddAuthentication(options =>
			   {
				   options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				   options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
				   options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			   })
			   .AddJwtBearer(cfg =>
			   {
				   cfg.RequireHttpsMetadata = false;
				   cfg.SaveToken = true;
				   cfg.TokenValidationParameters = new TokenValidationParameters
				   {
					   ValidIssuer = Configuration["JwtIssuer"],
					   ValidAudience = Configuration["JwtIssuer"],
					   IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JwtKey"])),
					   ClockSkew = TimeSpan.Zero // remove delay of token when expire
					};
				});
            services.Configure<AuthMessageSenderOptions>(Configuration);
			services.AddScoped<AccountManager>();
			services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2)
				.AddRazorPagesOptions(options =>
				{
					options.AllowAreas = true;
					options.Conventions.AuthorizeAreaPage("Identity", "/Account/ForgotPassword");
					options.Conventions.AuthorizeAreaPage("Identity", "/Account/ForgotPasswordConfirmation");
					options.Conventions.AuthorizeAreaPage("Identity", "/Account/ResetPassword");
					options.Conventions.AuthorizeAreaPage("Identity", "/Account/ResetPasswordConfirmation");
				});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, IServiceProvider serviceProvider)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseAuthentication();
            CreateUserRoles(serviceProvider).Wait();
            app.UseMvc();
        }

		// TODO: Break out functionality to indicate superuser creation side effect.
		private async Task CreateUserRoles(IServiceProvider serviceProvider)
		{
			//initializing custom roles 
			var RoleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
			var UserManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
			string[] roleNames = { "Administrator", "Consumer" };
			IdentityResult roleResult;

			foreach (string roleName in roleNames)
			{
				Boolean roleExist = await RoleManager.RoleExistsAsync(roleName);
				if (!roleExist)
				{
					//create the roles and seed them to the database: Question 1
					roleResult = await RoleManager.CreateAsync(new IdentityRole(roleName));
				}
			}

			//Here you could create a super user who will maintain the web app
			var superUser = new ApplicationUser
			{
				UserName = Configuration["AppSettings:UserName"],
				Email = Configuration["AppSettings:UserEmail"],
			};

			//Ensure you have these values in your appsettings.json file
			string userPWD = Configuration["AppSettings:UserPassword"];
			ApplicationUser _user = await UserManager.FindByEmailAsync(Configuration["AppSettings:AdminUserEmail"]);

			if (_user == null)
			{
				IdentityResult createSuperUser = await UserManager.CreateAsync(superUser, userPWD);
				if (createSuperUser.Succeeded)
				{
					//here we tie the new user to the role
					await UserManager.AddToRoleAsync(superUser, "Administrator");
				}
			}
		}
    }
}
