using System.ComponentModel.DataAnnotations;

namespace dotnet_core_identity_sandbox.Models
{
    public class Register
    {
            [Required]
            public string FirstName { get; set; }
            [Required]
            public string LastName { get; set; }
            [Required]
            [EmailAddress]
            public string Email { get; set; }
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }
    }
}
