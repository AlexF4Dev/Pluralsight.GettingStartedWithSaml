using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace sp.Controllers
{
    public class HomeController : Controller
    {
        private readonly SamlMessageStore messageStore;

        public HomeController(SamlMessageStore messageStore)
        {
            this.messageStore = messageStore ?? throw new ArgumentNullException(nameof(messageStore));
        }
        
        public IActionResult Index() => View(new ViewModel {SamlMessage = messageStore.CurrentMessage});
        public IActionResult Login() => Challenge(new AuthenticationProperties {RedirectUri = "/home"}, "saml");
    }

    public class ViewModel
    {
        public string SamlMessage { get; set; }
    }
}
