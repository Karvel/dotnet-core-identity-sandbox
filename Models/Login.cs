using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
 
namespace dotnet_core_identity_sandbox.Models
{
    public class Login
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}

