﻿using System.ComponentModel.DataAnnotations;
namespace csharproles.Auth.Models
{
    public class Login
    {
        [Required(ErrorMessage ="Username is required")]
        public string? Username { get; set; }

        [Required(ErrorMessage ="Password is required")]
        public string? Password { get; set; }
    }
}
