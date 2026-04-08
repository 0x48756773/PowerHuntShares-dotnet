using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace PowerHuntShares.Utilities;

/// <summary>
/// Sends text (and optionally an image) to an OpenAI-compatible chat endpoint.
/// Translates Invoke-LLMRequest (line 28198) from PowerHuntShares.psm1.
/// Tested against Azure GPT-4o / GPT-4o-mini, matching the original PS behaviour.
/// </summary>
public class LlmClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _apiKey;
    private readonly string _endpoint;

    public LlmClient(string apiKey, string endpoint)
    {
        _apiKey = apiKey;
        _endpoint = endpoint;
        _http = new HttpClient();
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", apiKey);
    }

    /// <summary>
    /// Sends a text prompt (and optional image) to the API and returns the
    /// assistant's message content.
    ///
    /// Maps to Invoke-LLMRequest -SimpleOutput (line 28228).
    /// </summary>
    public async Task<string> SendAsync(
        string text,
        string? imagePath = null,
        double temperature = 0.6,
        double topP = 0.95,
        int maxTokens = 2000,
        CancellationToken ct = default)
    {
        var content = new List<object>
        {
            new { type = "text", text = text }
        };

        // Attach base64-encoded image if supplied (mirrors the $ImagePath branch, line 28265).
        if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
        {
            string encoded = Convert.ToBase64String(await File.ReadAllBytesAsync(imagePath, ct));
            content.Add(new { type = "image", image = encoded });
        }

        var body = new
        {
            messages = new[]
            {
                new { role = "user", content }
            },
            temperature,
            top_p = topP,
            max_tokens = maxTokens
        };

        string json = JsonSerializer.Serialize(body);
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        HttpResponseMessage response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        string responseBody = await response.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(responseBody);

        // Extract choices[0].message.content — standard OpenAI response shape.
        return doc.RootElement
            .GetProperty("choices")[0]
            .GetProperty("message")
            .GetProperty("content")
            .GetString() ?? string.Empty;
    }

    /// <summary>
    /// Like <see cref="SendAsync"/> but also returns token usage counts from the response body.
    /// </summary>
    public async Task<LlmResult> SendWithUsageAsync(
        string text,
        string? imagePath = null,
        double temperature = 0.6,
        double topP = 0.95,
        int maxTokens = 2000,
        CancellationToken ct = default)
    {
        var content = new List<object>
        {
            new { type = "text", text = text }
        };

        if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
        {
            string encoded = Convert.ToBase64String(await File.ReadAllBytesAsync(imagePath, ct));
            content.Add(new { type = "image", image = encoded });
        }

        var body = new
        {
            messages = new[] { new { role = "user", content } },
            temperature,
            top_p = topP,
            max_tokens = maxTokens
        };

        string json = System.Text.Json.JsonSerializer.Serialize(body);
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new System.Net.Http.StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };

        HttpResponseMessage response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        string responseBody = await response.Content.ReadAsStringAsync(ct);
        using var doc = System.Text.Json.JsonDocument.Parse(responseBody);

        string messageContent = doc.RootElement
            .GetProperty("choices")[0]
            .GetProperty("message")
            .GetProperty("content")
            .GetString() ?? string.Empty;

        int promptTokens = 0, completionTokens = 0, totalTokens = 0;
        if (doc.RootElement.TryGetProperty("usage", out var usage))
        {
            usage.TryGetProperty("prompt_tokens",     out var pt); promptTokens     = pt.ValueKind == System.Text.Json.JsonValueKind.Number ? pt.GetInt32() : 0;
            usage.TryGetProperty("completion_tokens", out var ct2); completionTokens = ct2.ValueKind == System.Text.Json.JsonValueKind.Number ? ct2.GetInt32() : 0;
            usage.TryGetProperty("total_tokens",      out var tt); totalTokens      = tt.ValueKind == System.Text.Json.JsonValueKind.Number ? tt.GetInt32() : 0;
        }

        return new LlmResult(messageContent, promptTokens, completionTokens, totalTokens);
    }

    /// <summary>
    /// Connectivity probe — mirrors the "hello" test in Invoke-HuntSMBShares (line 281).
    /// Returns true if the API is reachable and responds sensibly.
    /// </summary>
    public async Task<bool> TestConnectivityAsync(CancellationToken ct = default)
    {
        try
        {
            string reply = await SendAsync(
                "Please return the word 'hello' and nothing else.",
                ct: ct);
            return reply.Contains("hello", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>
/// Return value from <see cref="LlmClient.SendWithUsageAsync"/>.
/// </summary>
public record LlmResult(
    string Content,
    int    PromptTokens,
    int    CompletionTokens,
    int    TotalTokens);
