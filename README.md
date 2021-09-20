# Asya JWT Manager

a lightweight JWT authentication manager that's allow you to work with JWT token easily and safe

you can register the package on the startup class as following
in Configure method call
`UseAsyaJwtServices(configuration);` 
and you should pass the configuration instance on this function
then you **must** adding the JWT settings in you appsettings.json file as following

 

| Property                   | Description                                                  | Default Value |
| ------------------------------ | ------------------------------------------------------------ | ------------- |
| Secret                         | the secret key for you token generator                       | none          |
| Issuer                         | the token issuer                                             | none          |
| Audience                       | the token audience                                           | none          |
| ValidateIssuer                 | should manager validate  issuer                              | false         |
| ValidateAudience               | should manager validate audience                             | false         |
| ValidateLifeTime               | the token validation life time in minutes                    | none          |
| ValidateIssuerSigningKey       | should token validate the issuer signing key                 | false         |
| AccessTokenExpiration          | the access token expiring life time in minutes               | none          |
| RefreshTokenExpiration         | the refresh token expiring life time in minutes              | none          |
| RemoveCachedRefreshTokensEvery | the automation remover background process for expired tokens in minutes | 1             |
| ClockSkew                      | the token manger ClockSkew value                             | 1             |

then you have a strong interface with a bunch of ready to use functions as following

`AuthenticationResult GenerateTokens(string email, Claim[] claims, DateTime now);`
`AuthenticationResult Refresh(string refreshToken, string accessToken, DateTime now);`
`void RemoveExpiredRefreshTokens(DateTime now);`
`void RemoveRefreshTokenByUserName(string userName);`
`(ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token);`

the `AuthenticationResult` should return the following

| Proeprty  | Type       |
| ------------ | ------------ |
| AccessToken | string |
| RefreshToken | RefreshToken |

and the `RefreshToken`

| Proeprty  | Type       |
| ----------- | -------- |
| UserName    | string   |
| TokenString | string   |
| ExpireAt    | datetime |

