using System;
using System.Threading;
using System.Threading.Tasks;
using Asya.JwtManager.Settings;
using Microsoft.Extensions.Hosting;

namespace Asya.JwtManager.Cache
{
    public class RefreshTokenCache : IHostedService, IDisposable
    {
        private readonly JwtSettings _jwtSettings;
        private readonly IToken _tokenManager;
        private Timer _timer;

        public RefreshTokenCache(IToken tokenManager, JwtSettings jwtSettings)
        {
            _tokenManager = tokenManager;
            _jwtSettings = jwtSettings;
        }

        public void Dispose()
        {
            _timer?.Dispose();
        }

        public Task StartAsync(CancellationToken stoppingToken)
        {
            _timer = new Timer(RemoveExpiredTokens, null, TimeSpan.Zero,
                TimeSpan.FromMinutes(_jwtSettings.RemoveCachedRefreshTokensEvery));
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken stoppingToken)
        {
            _timer?.Change(Timeout.Infinite, 0);
            return Task.CompletedTask;
        }

        private void RemoveExpiredTokens(object state)
        {
            _tokenManager.RemoveExpiredRefreshTokens(DateTime.UtcNow);
        }
    }
}