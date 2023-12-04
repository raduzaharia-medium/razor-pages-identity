using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityRazor.Identity.Pages;

public class TwoFactorModel(ILogger<LoginModel> logger, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager) : PageModel
{
    private readonly ILogger<LoginModel> _logger = logger;
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;

    public bool TwoFactorEnabled { get; set; }


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

        TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);

        return Page();
    }
}
