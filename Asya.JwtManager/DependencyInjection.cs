using Asya.JwtManager.Settings;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Asya.JwtManager
{
    public static class DependencyInjection
    {
        public static IServiceCollection UseAsyaJwtServices(this IServiceCollection services,
            IConfiguration configuration)
        {
            //register JWT settings in global scope
            var jwtSettings = new JwtSettings();
            configuration.GetSection(nameof(jwtSettings)).Bind(jwtSettings);
            services.AddSingleton(jwtSettings);
            return services;
        }
    }
}