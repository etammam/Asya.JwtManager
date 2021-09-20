using System;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Asya.JwtManager.Models;
using Asya.JwtManager.Settings;
using Microsoft.IdentityModel.Tokens;

namespace Asya.JwtManager
{
    public class TokenManager : IToken
    {
        private readonly JwtSettings _jwtTokenConfig;
        private readonly byte[] _secret;
        private readonly ConcurrentDictionary<string, RefreshToken> _usersRefreshTokens;

        public TokenManager(JwtSettings jwtTokenConfig)
        {
            _jwtTokenConfig = jwtTokenConfig;
            _usersRefreshTokens = new ConcurrentDictionary<string, RefreshToken>();
            _secret = Encoding.ASCII.GetBytes(jwtTokenConfig.Secret);
        }

        public IImmutableDictionary<string, RefreshToken> UsersRefreshTokensReadOnlyDictionary =>
            _usersRefreshTokens.ToImmutableDictionary();

        public void RemoveExpiredRefreshTokens(DateTime now)
        {
            var expiredTokens = _usersRefreshTokens.Where(x => x.Value.ExpireAt < now).ToList();
            foreach (var expiredToken in expiredTokens) _usersRefreshTokens.TryRemove(expiredToken.Key, out _);
        }

        public void RemoveRefreshTokenByUserName(string userName)
        {
            var refreshTokens = _usersRefreshTokens.Where(x => x.Value.UserName == userName).ToList();
            foreach (var refreshToken in refreshTokens) _usersRefreshTokens.TryRemove(refreshToken.Key, out _);
        }

        public AuthenticationResult GenerateTokens(string email, Claim[] claims, DateTime now)
        {
            var shouldAddAudienceClaim =
                string.IsNullOrWhiteSpace(claims?.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Aud)?.Value);
            var jwtToken = new JwtSecurityToken(
                _jwtTokenConfig.Issuer,
                shouldAddAudienceClaim ? _jwtTokenConfig.Audience : string.Empty,
                claims,
                expires: now.AddMinutes(_jwtTokenConfig.AccessTokenExpiration),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(_secret),
                    SecurityAlgorithms.HmacSha256Signature));
            var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            var refreshToken = new RefreshToken
            {
                UserName = email,
                TokenString = GenerateRefreshTokenString(),
                ExpireAt = now.AddMinutes(_jwtTokenConfig.RefreshTokenExpiration)
            };
            _usersRefreshTokens.AddOrUpdate(refreshToken.TokenString, refreshToken, (_, _) => refreshToken);

            return new AuthenticationResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public AuthenticationResult Refresh(string refreshToken, string accessToken, DateTime now)
        {
            var (principal, jwtToken) = DecodeJwtToken(accessToken);
            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature))
                throw new SecurityTokenException("Invalid token");
            var userName = principal.Claims.FirstOrDefault(d => d.Type == ClaimTypes.GivenName)?.Value.ToLower();
            if (!_usersRefreshTokens.TryGetValue(refreshToken, out var existingRefreshToken))
                throw new SecurityTokenException("Invalid token");
            if (existingRefreshToken.UserName != userName || existingRefreshToken.ExpireAt < now)
                throw new SecurityTokenException("Invalid token");

            return GenerateTokens(userName, principal.Claims.ToArray(), now);
        }

        public (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) throw new SecurityTokenException("Invalid token");
            var principal = new JwtSecurityTokenHandler()
                .ValidateToken(token,
                    new TokenValidationParameters
                    {
                        ValidateIssuer = _jwtTokenConfig.ValidateIssuer,
                        ValidIssuer = _jwtTokenConfig.Issuer,
                        ValidateIssuerSigningKey = _jwtTokenConfig.ValidateIssuerSigningKey,
                        IssuerSigningKey = new SymmetricSecurityKey(_secret),
                        ValidAudience = _jwtTokenConfig.Audience,
                        ValidateAudience = _jwtTokenConfig.ValidateAudience,
                        ValidateLifetime = _jwtTokenConfig.ValidateLifeTime,
                        ClockSkew = TimeSpan.FromMinutes(_jwtTokenConfig.ClockSkew)
                    },
                    out var validatedToken);
            return (principal, validatedToken as JwtSecurityToken);
        }

        private static string GenerateRefreshTokenString()
        {
            var randomNumber = new byte[32];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}