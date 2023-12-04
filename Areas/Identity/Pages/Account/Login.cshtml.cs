using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityRazor.Identity.Pages;

public class LoginModel(ILogger<LoginModel> logger, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager) : PageModel
{
    private readonly ILogger<LoginModel> _logger = logger;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;
    private readonly UserManager<IdentityUser> _userManager = userManager;

    [Required]
    [DataType(DataType.EmailAddress)]
    [EmailAddress]
    [BindProperty]
    public string? Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [BindProperty]
    public string? Password { get; set; }

    [BindProperty]
    public bool Remember { get; set; }

    public async Task<IActionResult> OnPostAsync(string email, string password, bool remember)
    {
        if (!ModelState.IsValid) return Page();
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password)) return Page();

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || user.UserName == null)
        {
            ModelState.AddModelError("Email", "Invalid email or password");
            _logger.LogError("Could not login user {email}", email);

            return Page();
        }

        var result = await _signInManager.PasswordSignInAsync(user.UserName, password, remember, false);
        if (!result.Succeeded)
        {
            ModelState.AddModelError("Email", "Invalid email or password");
            _logger.LogError("Could not login user {email}", email);

            return Page();
        }

        return RedirectToPage("/Index");
    }
}
