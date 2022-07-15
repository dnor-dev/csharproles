using csharproles.Auth;
using csharproles.Auth.Models;
using csharproles.Auth.Roles;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Collections.Generic;
using System.Linq;


namespace csharproles.Controllers
{
    [Route("/api/[controller]")]
    [ApiController]
    public class auth: ControllerBase
    {
        private readonly UserManager<AppUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
       
        public auth(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration _configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = _configuration;
        }

         private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }



        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            var user = await userManager.FindByNameAsync(model.Username);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = GetToken(authClaims);

                return Ok(
                    new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token),
                        expiration = token.ValidTo
                    });
            }
            else
            {
                return Unauthorized();
            }
        }

        [HttpPost]
        [Route("signup")]
        public async Task<IActionResult> Signup([FromBody] Register model)
        {
            var userExists = await userManager.FindByNameAsync(model.Username);
            if (userExists != null) return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Exists!" });
            AppUser user = new AppUser
            {
                Email = model.Email,
                UserName = model.Username,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            
            var result = await userManager.CreateAsync(user, model.Password);

            await roleManager.CreateAsync(new IdentityRole(roles.User));
            await userManager.AddToRoleAsync(user, roles.User);

            var useRoles = await userManager.GetRolesAsync(user);

            if (!result.Succeeded || !useRoles.Contains(roles.User)) return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "Error in signup, please try again", Status = "Error" });

            return Ok(new Response
            {
                Message = "User created!", 
                Status = "Success"
            });
        }

        [HttpPost]
        [Route("admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] Register model)
        {
            var userExists = await userManager.FindByNameAsync(model.Username);
            if (userExists == null) return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User does not exist" });
            if (!await roleManager.RoleExistsAsync(roles.Admin))
                await roleManager.CreateAsync(new IdentityRole(roles.Admin));

            if (await roleManager.RoleExistsAsync(roles.Admin))
            {
                await userManager.AddToRoleAsync(userExists, roles.Admin);
            }

            return Ok(
                new Response
                {
                    Status = "Success",
                    Message= "Youre now an admin"
                });
        }
    }
}
