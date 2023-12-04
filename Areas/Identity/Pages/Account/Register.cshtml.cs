using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityRazor.Identity.Pages;

public class RegisterModel(ILogger<LoginModel> logger, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IWebHostEnvironment hostingEnvironment) : PageModel
{
    private readonly ILogger<LoginModel> _logger = logger;
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;
    private readonly IWebHostEnvironment _hostingEnvironment = hostingEnvironment;


    [Required]
    [DataType(DataType.EmailAddress)]
    [EmailAddress]
    [BindProperty]
    public string? Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [BindProperty]
    public string? Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [DisplayName("Confirm password")]
    [Compare("Password")]
    [BindProperty]
    public string? PasswordConfirm { get; set; }

    public async Task<IActionResult> OnPostAsync(string email, string password)
    {
        if (!ModelState.IsValid) return Page();
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password)) return Page();

        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            ModelState.AddModelError("Email", "Email already registered to a user");
            _logger.LogError("User {email} already exists", email);

            return Page();
        }

        user = new IdentityUser(Guid.NewGuid().ToString())
        {
            Email = email,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded || user.UserName == null)
        {
            ModelState.AddModelError("Email", "Could not create user");
            _logger.LogError("Could not create user {email}", email);

            return Page();
        }

        if (_hostingEnvironment.IsDevelopment())
        {
            var loginResult = await _signInManager.PasswordSignInAsync(user.UserName, password, false, false);
            if (!loginResult.Succeeded)
            {
                ModelState.AddModelError("Email", "Could not login");
                _logger.LogError("Could not login user {email}", email);

                return Page();
            }
        }

        return RedirectToPage("/Index");
    }
}
