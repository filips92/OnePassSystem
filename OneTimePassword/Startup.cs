using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(OneTimePassword.Startup))]
namespace OneTimePassword
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
