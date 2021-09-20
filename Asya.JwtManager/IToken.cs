using System;
using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Asya.JwtManager.Models;

namespace Asya.JwtManager
{
    public interface IToken
    {
        IImmutableDictionary<string, RefreshToken> UsersRefreshTokensReadOnlyDictionary { get; }
        AuthenticationResult GenerateTokens(string email, Claim[] claims, DateTime now);
        AuthenticationResult Refresh(string refreshToken, string accessToken, DateTime now);
        void RemoveExpiredRefreshTokens(DateTime now);
        void RemoveRefreshTokenByUserName(string userName);
        (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token);
    }
}