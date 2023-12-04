using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityRazor.Identity.Pages;

public class ProfileModel(ILogger<LoginModel> logger, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager) : PageModel
{
    private readonly ILogger<LoginModel> _logger = logger;
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;

    [Required]
    [DataType(DataType.EmailAddress)]
    [EmailAddress]
    [BindProperty]
    public string? Email { get; set; }

    [Required]
    [DataType(DataType.PhoneNumber)]
    [BindProperty]
    [Phone]
    public string? PhoneNumber { get; set; }

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

        Email = user.Email;
        PhoneNumber = user.PhoneNumber;

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string email, string phoneNumber)
    {
        if (!ModelState.IsValid) return Page();
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(phoneNumber)) return Page();

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            ModelState.AddModelError("Email", "Could not find user");
            _logger.LogError("Could not find user {email}", email);

            return Page();
        }

        var tokenResult = await _userManager.GenerateChangePhoneNumberTokenAsync(user, phoneNumber);
        if (tokenResult == null)
        {
            ModelState.AddModelError("PhoneNumber", "Could not change the phone number");
            _logger.LogError("Could not change the phone number for {email}", email);

            return Page();
        }

        var result = await _userManager.ChangePhoneNumberAsync(user, phoneNumber, tokenResult);
        if (!result.Succeeded)
        {
            ModelState.AddModelError("PhoneNumber", "Could not change the phone number");
            _logger.LogError("Could not change the phone number for {email}", email);

            return Page();
        }

        return RedirectToPage("/Account/Manage/Index");
    }
}
