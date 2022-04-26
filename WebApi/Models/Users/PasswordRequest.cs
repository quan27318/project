namespace WebApi.Models.Users;

using System.ComponentModel.DataAnnotations;

public class PasswordRequest
{
    [Required]
    public string? OldPassword { get; set; }
    [Required]
    public string? NewPassword { get; set; }
}