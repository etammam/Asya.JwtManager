using System.Text.Json.Serialization;

namespace Asya.JwtManager.Models
{
    public class AuthenticationResult
    {
        [JsonPropertyName("accessToken")] public string AccessToken { get; set; }

        [JsonPropertyName("refreshToken")] public RefreshToken RefreshToken { get; set; }
    }
}