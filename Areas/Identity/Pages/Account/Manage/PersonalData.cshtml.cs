using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityRazor.Identity.Pages;

public class PersonalDataModel(ILogger<LoginModel> logger, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager) : PageModel
{
    private readonly ILogger<LoginModel> _logger = logger;
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;

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

    public async Task<IActionResult> OnPostAsync()
    {
        if (User.Identity == null || User.Identity.Name == null)
        {
            await _signInManager.SignOutAsync();
            return RedirectToPage("/Index");
        }

        if (!ModelState.IsValid) return Page();

        var user = await _userManager.FindByNameAsync(User.Identity.Name);
        if (user == null)
        {
            _logger.LogError("Could not find logged in user");

            await _signInManager.SignOutAsync();
            return RedirectToPage("/Index");
        }

        var result = JsonSerializer.Serialize(new
        {
            user.Id,
            user.UserName,
            user.Email,
            user.EmailConfirmed,
            user.PhoneNumber,
            user.PhoneNumberConfirmed,
            user.TwoFactorEnabled
        });
        return File(Encoding.UTF8.GetBytes(result), "application/json", "PersonalData.json");
    }
}
