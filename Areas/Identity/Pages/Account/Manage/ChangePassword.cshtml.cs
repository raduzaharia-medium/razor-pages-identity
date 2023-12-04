using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityRazor.Identity.Pages;

public class ChangePasswordModel(ILogger<LoginModel> logger, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager) : PageModel
{
    private readonly ILogger<LoginModel> _logger = logger;
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;

    [Required]
    [DataType(DataType.Password)]
    [BindProperty]
    [DisplayName("Current password")]
    public string? CurrentPassword { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [BindProperty]
    [DisplayName("New password")]
    public string? NewPassword { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [BindProperty]
    [DisplayName("Confirm new password")]
    public string? ConfirmNewPassword { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        if (User.Identity == null || User.Identity.Name == null)
        {
            await _signInManager.SignOutAsync();
            return RedirectToPage("/Index");
        }

        var user = await _userManager.FindByNameAsync(User.Identity.Name);
        if (user == null)
        {
            _logger.LogError("Could not find logged in user");

            await _signInManager.SignOutAsync();
            return RedirectToPage("/Index");
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string currentPassword, string newPassword, string confirmNewPassword)
    {
        if (User.Identity == null || User.Identity.Name == null)
        {
            await _signInManager.SignOutAsync();
            return RedirectToPage("/Index");
        }

        if (!ModelState.IsValid) return Page();
        if (string.IsNullOrEmpty(currentPassword) || string.IsNullOrEmpty(newPassword) || string.IsNullOrEmpty(confirmNewPassword)) return Page();

        var user = await _userManager.FindByNameAsync(User.Identity.Name);
        if (user == null)
        {
            _logger.LogError("Could not find logged in user");

            await _signInManager.SignOutAsync();
            return RedirectToPage("/Index");
        }

        var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        if (!result.Succeeded)
        {
            ModelState.AddModelError("NewPassword", "Could not change the password");
            _logger.LogError("Could not change the password address for {email}", user.Email);

            return Page();
        }

        return RedirectToPage("/Account/Manage/Index");
    }
}
