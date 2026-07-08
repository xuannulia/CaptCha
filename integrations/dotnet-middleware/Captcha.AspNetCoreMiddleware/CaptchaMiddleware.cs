using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Captcha.AspNetCoreMiddleware;

public sealed class CaptchaOptions
{
    public string PlatformUrl { get; set; } = "";
    public string ClientId { get; set; } = "demo";
    public string ClientSecret { get; set; } = "";
    public string TicketHeader { get; set; } = "X-Captcha-Ticket";
    public string ClearanceHeader { get; set; } = "X-Captcha-Clearance";
    public string ClearanceCookieName { get; set; } = "captcha_clearance";
    public bool ClearanceCookieSecure { get; set; }
    public string RequestNonceHeader { get; set; } = "X-Captcha-Request-Nonce";
    public string ResourceTagHeader { get; set; } = "X-Captcha-Resource-Tag";
    public string AccountIdHashHeader { get; set; } = "X-Captcha-Account-ID-Hash";
    public string DeviceIdHashHeader { get; set; } = "X-Captcha-Device-ID-Hash";
    public string RiskScoreHeader { get; set; } = "X-Captcha-Risk-Score";
    public string RiskLevelHeader { get; set; } = "X-Captcha-Risk-Level";
    public string ModelScoreHeader { get; set; } = "X-Captcha-Model-Score";
    public string ModelModeHeader { get; set; } = "X-Captcha-Model-Mode";
    public string SceneHeader { get; set; } = "X-Captcha-Scene";
    public string FailPolicy { get; set; } = "fail_open";
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMilliseconds(1500);
    public int CircuitBreakerFailureThreshold { get; set; }
    public TimeSpan CircuitBreakerCooldown { get; set; } = TimeSpan.Zero;
    public IList<string> TrustedProxyCidrs { get; set; } = new List<string>();
    public IList<string> HeaderAllowlist { get; set; } = new List<string>();
    public Func<HttpContext, bool>? ShouldProtect { get; set; }
    public Func<HttpContext, string>? ResolveScene { get; set; }
    public Func<HttpContext, string>? ResolveAccountIdHash { get; set; }
    public Func<HttpContext, string>? ResolveDeviceIdHash { get; set; }
    public HttpClient? HttpClient { get; set; }
}

public sealed class CaptchaMiddleware
{
    private readonly RequestDelegate _next;
    private readonly CaptchaOptions _options;
    private readonly HttpClient _client;
    private readonly CircuitBreaker _policyBreaker;
    private readonly CircuitBreaker _ticketBreaker;
    private readonly List<IPv4Cidr> _trustedProxies;

    public CaptchaMiddleware(RequestDelegate next, CaptchaOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.PlatformUrl))
        {
            throw new ArgumentException("PlatformUrl is required", nameof(options));
        }

        _next = next;
        _options = options;
        _options.PlatformUrl = _options.PlatformUrl.TrimEnd('/');
        _client = options.HttpClient ?? new HttpClient { Timeout = options.Timeout };
        _policyBreaker = new CircuitBreaker(options.CircuitBreakerFailureThreshold, options.CircuitBreakerCooldown);
        _ticketBreaker = new CircuitBreaker(options.CircuitBreakerFailureThreshold, options.CircuitBreakerCooldown);
        _trustedProxies = options.TrustedProxyCidrs
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(IPv4Cidr.Parse)
            .ToList();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_options.ShouldProtect is not null && !_options.ShouldProtect(context))
        {
            await _next(context);
            return;
        }

        var evaluateRequest = BuildEvaluateRequest(context);
        if (!string.IsNullOrWhiteSpace(evaluateRequest.Ticket))
        {
            await HandleTicketAsync(context, evaluateRequest);
            return;
        }

        await HandlePolicyAsync(context, evaluateRequest);
    }

    private async Task HandleTicketAsync(HttpContext context, PolicyEvaluateRequest evaluateRequest)
    {
        if (!_ticketBreaker.Allow())
        {
            await HandleUnavailableAsync(context, evaluateRequest, "TICKET_SERVICE_UNAVAILABLE");
            return;
        }

        TicketConsumeResponse ticket;
        try
        {
            ticket = await PostJsonAsync<TicketConsumeResponse>("/api/v1/tickets/verify", new TicketConsumeRequest
            {
                Ticket = evaluateRequest.Ticket,
                ClientId = evaluateRequest.ClientId,
                Scene = evaluateRequest.Scene,
                Route = evaluateRequest.Path,
                RequestNonce = evaluateRequest.RequestNonce,
                IpHash = HashValue(evaluateRequest.Ip),
                UserAgentHash = HashValue(evaluateRequest.UserAgent),
                AccountIdHash = evaluateRequest.AccountIdHash,
                DeviceIdHash = evaluateRequest.DeviceIdHash,
                Consume = true,
            }, context.RequestAborted);
            _ticketBreaker.RecordSuccess();
        }
        catch
        {
            _ticketBreaker.RecordFailure();
            await HandleUnavailableAsync(context, evaluateRequest, "TICKET_SERVICE_UNAVAILABLE");
            return;
        }

        if (ticket.Valid)
        {
            WriteClearance(context, ticket.ClearanceToken, ticket.ClearanceTtlSeconds);
            _ = ReportDecisionAsync(evaluateRequest, new PolicyDecision
            {
                Action = "allow",
                Reason = "TICKET_CONSUMED",
                Scene = FirstNonEmpty(ticket.Scene, evaluateRequest.Scene),
            });
            await _next(context);
            return;
        }

        var reason = FirstNonEmpty(ticket.Reason, "TICKET_INVALID");
        _ = ReportDecisionAsync(evaluateRequest, new PolicyDecision
        {
            Action = "block",
            Reason = reason,
            Scene = FirstNonEmpty(ticket.Scene, evaluateRequest.Scene),
        });
        await WriteJsonAsync(context, StatusCodes.Status403Forbidden, new { action = "block", reason });
    }

    private async Task HandlePolicyAsync(HttpContext context, PolicyEvaluateRequest evaluateRequest)
    {
        if (!_policyBreaker.Allow())
        {
            await HandleUnavailableAsync(context, evaluateRequest, "POLICY_UNAVAILABLE");
            return;
        }

        PolicyDecision decision;
        try
        {
            decision = await PostJsonAsync<PolicyDecision>("/api/v1/policy/evaluate", evaluateRequest, context.RequestAborted);
            _policyBreaker.RecordSuccess();
        }
        catch
        {
            _policyBreaker.RecordFailure();
            await HandleUnavailableAsync(context, evaluateRequest, "POLICY_UNAVAILABLE");
            return;
        }

        switch (decision.Action)
        {
            case "allow":
            case "observe":
            case "pass":
            case "skip_challenge":
                WriteClearance(context, decision.ClearanceToken, decision.ClearanceTtlSeconds);
                await _next(context);
                return;
            case "challenge":
            case "challenge_harder":
            case "step_up_challenge":
            case "rate_limit":
                await WriteJsonAsync(context, StatusCodes.Status403Forbidden, new
                {
                    action = decision.Action,
                    reason = decision.Reason,
                    challenge_url = AbsoluteChallengeUrl(decision.ChallengeUrl),
                    session_id = decision.SessionId,
                    scene = decision.Scene,
                    challenge_type = decision.ChallengeType,
                    ttl_seconds = decision.TtlSeconds,
                });
                return;
            case "block":
            case "cooldown":
            case "require_business_verify":
                await WriteJsonAsync(context, StatusCodes.Status403Forbidden, new
                {
                    action = decision.Action,
                    reason = decision.Reason,
                    cooldown_seconds = decision.CooldownSeconds,
                    business_verify_type = decision.BusinessVerifyType,
                });
                return;
            default:
                await WriteJsonAsync(context, StatusCodes.Status403Forbidden, new
                {
                    action = "block",
                    reason = "UNSUPPORTED_POLICY_DECISION",
                });
                return;
        }
    }

    private async Task HandleUnavailableAsync(HttpContext context, PolicyEvaluateRequest request, string reason)
    {
        var action = _options.FailPolicy == "fail_close" ? "block" : "allow";
        _ = ReportDecisionAsync(request, new PolicyDecision { Action = action, Reason = reason });
        if (_options.FailPolicy == "fail_close")
        {
            await WriteJsonAsync(context, StatusCodes.Status503ServiceUnavailable, new { action = "block", reason });
            return;
        }

        await _next(context);
    }

    private PolicyEvaluateRequest BuildEvaluateRequest(HttpContext context)
    {
        var path = context.Request.Path.HasValue ? context.Request.Path.Value! : "/";
        var scene = FirstNonEmpty(
            _options.ResolveScene?.Invoke(context) ?? "",
            Header(context, _options.SceneHeader),
            SceneFromPath(path));
        var accountIdHash = FirstNonEmpty(
            _options.ResolveAccountIdHash?.Invoke(context) ?? "",
            Header(context, _options.AccountIdHashHeader));
        var deviceIdHash = FirstNonEmpty(
            _options.ResolveDeviceIdHash?.Invoke(context) ?? "",
            Header(context, _options.DeviceIdHashHeader));

        return new PolicyEvaluateRequest
        {
            ClientId = _options.ClientId,
            Scene = scene,
            Path = path,
            Method = context.Request.Method.ToUpperInvariant(),
            Ip = RemoteIp(context),
            UserAgent = Header(context, "User-Agent"),
            AccountIdHash = accountIdHash,
            DeviceIdHash = deviceIdHash,
            Ticket = Header(context, _options.TicketHeader),
            Clearance = FirstNonEmpty(Header(context, _options.ClearanceHeader), Cookie(context, _options.ClearanceCookieName)),
            RequestNonce = Header(context, _options.RequestNonceHeader),
            ResourceTag = Header(context, _options.ResourceTagHeader),
            RiskScore = IntHeader(context, _options.RiskScoreHeader),
            RiskLevel = Header(context, _options.RiskLevelHeader),
            ModelScore = IntHeader(context, _options.ModelScoreHeader),
            ModelMode = Header(context, _options.ModelModeHeader),
            Headers = CollectAllowedHeaders(context),
        };
    }

    private string RemoteIp(HttpContext context)
    {
        var direct = context.Connection.RemoteIpAddress?.ToString() ?? "";
        if (string.IsNullOrWhiteSpace(direct) || _trustedProxies.Count == 0)
        {
            return direct;
        }

        if (!IPAddress.TryParse(direct, out var directAddress) || !_trustedProxies.Any(cidr => cidr.Contains(directAddress)))
        {
            return direct;
        }

        foreach (var part in Header(context, "X-Forwarded-For").Split(','))
        {
            var candidate = part.Trim();
            if (IPAddress.TryParse(candidate, out _))
            {
                return candidate;
            }
        }

        return direct;
    }

    private Dictionary<string, string> CollectAllowedHeaders(HttpContext context)
    {
        var headers = new Dictionary<string, string>();
        foreach (var name in _options.HeaderAllowlist)
        {
            var normalized = name.Trim().ToLowerInvariant();
            var value = Header(context, name);
            if (!string.IsNullOrWhiteSpace(normalized) && !string.IsNullOrWhiteSpace(value))
            {
                headers[normalized] = value;
            }
        }

        return headers;
    }

    private void WriteClearance(HttpContext context, string? token, int ttlSeconds)
    {
        token = token?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        context.Response.Headers[_options.ClearanceHeader] = token;
        if (string.IsNullOrWhiteSpace(_options.ClearanceCookieName))
        {
            return;
        }

        context.Response.Cookies.Append(_options.ClearanceCookieName, token, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = _options.ClearanceCookieSecure,
            Path = "/",
            MaxAge = ttlSeconds > 0 ? TimeSpan.FromSeconds(ttlSeconds) : null,
        });
    }

    private async Task ReportDecisionAsync(PolicyEvaluateRequest request, PolicyDecision decision)
    {
        try
        {
            await PostJsonAsync<ReportResult>("/api/v1/events/report", new EventBatch
            {
                Events =
                [
                    new AuditEvent
                    {
                        ClientId = request.ClientId,
                        Scene = FirstNonEmpty(decision.Scene, request.Scene),
                        Route = request.Path,
                        IpHash = HashValue(request.Ip),
                        AccountIdHash = request.AccountIdHash,
                        DeviceIdHash = request.DeviceIdHash,
                        Action = decision.Action,
                        DecisionReason = decision.Reason,
                        ChallengeType = decision.ChallengeType,
                        Result = decision.Action,
                    }
                ],
            }, CancellationToken.None);
        }
        catch
        {
            // Event reporting must never block protected requests.
        }
    }

    private async Task<T> PostJsonAsync<T>(string path, object body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, _options.PlatformUrl + path)
        {
            Content = JsonContent.Create(body),
        };
        if (!string.IsNullOrWhiteSpace(_options.ClientSecret))
        {
            request.Headers.TryAddWithoutValidation("X-Captcha-Client-Secret", _options.ClientSecret);
        }

        using var timeout = new CancellationTokenSource(_options.Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        using var response = await _client.SendAsync(request, linked.Token);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<T>(linked.Token))!;
    }

    private string AbsoluteChallengeUrl(string? value)
    {
        value = value?.Trim() ?? "";
        if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return value;
        }
        if (value.StartsWith('/'))
        {
            return _options.PlatformUrl + value;
        }
        return string.IsNullOrWhiteSpace(value) ? "" : _options.PlatformUrl + "/" + value;
    }

    private static async Task WriteJsonAsync(HttpContext context, int status, object body)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(body);
    }

    private static string Header(HttpContext context, string name)
    {
        return context.Request.Headers.TryGetValue(name, out var value) ? value.ToString().Trim() : "";
    }

    private static string Cookie(HttpContext context, string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "";
        }
        return context.Request.Cookies.TryGetValue(name, out var value) ? value.Trim() : "";
    }

    private static int IntHeader(HttpContext context, string name)
    {
        if (!int.TryParse(Header(context, name), out var value))
        {
            return 0;
        }
        return Math.Min(100, Math.Max(0, value));
    }

    private static string SceneFromPath(string path)
    {
        var trimmed = path.Trim('/');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return "default";
        }
        var slash = trimmed.IndexOf('/');
        return slash >= 0 ? trimmed[..slash] : trimmed;
    }

    private static string HashValue(string? value)
    {
        value = value?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }
        return "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..32].ToLowerInvariant();
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }
        return "";
    }
}

public static class CaptchaApplicationBuilderExtensions
{
    public static IApplicationBuilder UseCaptcha(this IApplicationBuilder app, Action<CaptchaOptions> configure)
    {
        var options = new CaptchaOptions();
        configure(options);
        return app.Use(next =>
        {
            var middleware = new CaptchaMiddleware(next, options);
            return middleware.InvokeAsync;
        });
    }
}

internal sealed class CircuitBreaker
{
    private readonly int _threshold;
    private readonly TimeSpan _cooldown;
    private int _failures;
    private DateTimeOffset _openUntil;
    private readonly object _gate = new();

    public CircuitBreaker(int threshold, TimeSpan cooldown)
    {
        _threshold = threshold;
        _cooldown = cooldown;
    }

    public bool Allow()
    {
        if (!Enabled)
        {
            return true;
        }
        lock (_gate)
        {
            return DateTimeOffset.UtcNow >= _openUntil;
        }
    }

    public void RecordSuccess()
    {
        if (!Enabled)
        {
            return;
        }
        lock (_gate)
        {
            _failures = 0;
            _openUntil = default;
        }
    }

    public void RecordFailure()
    {
        if (!Enabled)
        {
            return;
        }
        lock (_gate)
        {
            _failures++;
            if (_failures >= _threshold)
            {
                _failures = 0;
                _openUntil = DateTimeOffset.UtcNow.Add(_cooldown);
            }
        }
    }

    private bool Enabled => _threshold > 0 && _cooldown > TimeSpan.Zero;
}

internal sealed record IPv4Cidr(uint Network, int Prefix)
{
    public static IPv4Cidr Parse(string value)
    {
        var parts = value.Split('/', 2);
        var prefix = parts.Length == 2 && int.TryParse(parts[1], out var parsed) ? parsed : 32;
        return new IPv4Cidr(ToUInt32(IPAddress.Parse(parts[0])), Math.Clamp(prefix, 0, 32));
    }

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }
        var mask = Prefix == 0 ? 0u : uint.MaxValue << (32 - Prefix);
        return (ToUInt32(address) & mask) == (Network & mask);
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }
}

public sealed class PolicyEvaluateRequest
{
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = "";
    [JsonPropertyName("scene")] public string Scene { get; set; } = "";
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("method")] public string Method { get; set; } = "";
    [JsonPropertyName("ip")] public string Ip { get; set; } = "";
    [JsonPropertyName("user_agent")] public string UserAgent { get; set; } = "";
    [JsonPropertyName("account_id_hash")] public string AccountIdHash { get; set; } = "";
    [JsonPropertyName("device_id_hash")] public string DeviceIdHash { get; set; } = "";
    [JsonPropertyName("ticket")] public string Ticket { get; set; } = "";
    [JsonPropertyName("clearance")] public string Clearance { get; set; } = "";
    [JsonPropertyName("request_nonce")] public string RequestNonce { get; set; } = "";
    [JsonPropertyName("resource_tag")] public string ResourceTag { get; set; } = "";
    [JsonPropertyName("risk_score")] public int RiskScore { get; set; }
    [JsonPropertyName("risk_level")] public string RiskLevel { get; set; } = "";
    [JsonPropertyName("model_score")] public int ModelScore { get; set; }
    [JsonPropertyName("model_mode")] public string ModelMode { get; set; } = "";
    [JsonPropertyName("headers")] public Dictionary<string, string> Headers { get; set; } = new();
}

public sealed class PolicyDecision
{
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("reason")] public string Reason { get; set; } = "";
    [JsonPropertyName("challenge_url")] public string ChallengeUrl { get; set; } = "";
    [JsonPropertyName("session_id")] public string SessionId { get; set; } = "";
    [JsonPropertyName("scene")] public string Scene { get; set; } = "";
    [JsonPropertyName("challenge_type")] public string ChallengeType { get; set; } = "";
    [JsonPropertyName("ttl_seconds")] public int TtlSeconds { get; set; }
    [JsonPropertyName("cooldown_seconds")] public int CooldownSeconds { get; set; }
    [JsonPropertyName("business_verify_type")] public string BusinessVerifyType { get; set; } = "";
    [JsonPropertyName("clearance_token")] public string ClearanceToken { get; set; } = "";
    [JsonPropertyName("clearance_ttl_seconds")] public int ClearanceTtlSeconds { get; set; }
}

public sealed class TicketConsumeRequest
{
    [JsonPropertyName("ticket")] public string Ticket { get; set; } = "";
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = "";
    [JsonPropertyName("scene")] public string Scene { get; set; } = "";
    [JsonPropertyName("route")] public string Route { get; set; } = "";
    [JsonPropertyName("request_nonce")] public string RequestNonce { get; set; } = "";
    [JsonPropertyName("ip_hash")] public string IpHash { get; set; } = "";
    [JsonPropertyName("user_agent_hash")] public string UserAgentHash { get; set; } = "";
    [JsonPropertyName("account_id_hash")] public string AccountIdHash { get; set; } = "";
    [JsonPropertyName("device_id_hash")] public string DeviceIdHash { get; set; } = "";
    [JsonPropertyName("consume")] public bool Consume { get; set; }
}

public sealed class TicketConsumeResponse
{
    [JsonPropertyName("valid")] public bool Valid { get; set; }
    [JsonPropertyName("reason")] public string Reason { get; set; } = "";
    [JsonPropertyName("scene")] public string Scene { get; set; } = "";
    [JsonPropertyName("clearance_token")] public string ClearanceToken { get; set; } = "";
    [JsonPropertyName("clearance_ttl_seconds")] public int ClearanceTtlSeconds { get; set; }
}

public sealed class EventBatch
{
    [JsonPropertyName("events")] public List<AuditEvent> Events { get; set; } = new();
}

public sealed class AuditEvent
{
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = "";
    [JsonPropertyName("scene")] public string Scene { get; set; } = "";
    [JsonPropertyName("route")] public string Route { get; set; } = "";
    [JsonPropertyName("ip_hash")] public string IpHash { get; set; } = "";
    [JsonPropertyName("account_id_hash")] public string AccountIdHash { get; set; } = "";
    [JsonPropertyName("device_id_hash")] public string DeviceIdHash { get; set; } = "";
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("decision_reason")] public string DecisionReason { get; set; } = "";
    [JsonPropertyName("challenge_type")] public string ChallengeType { get; set; } = "";
    [JsonPropertyName("result")] public string Result { get; set; } = "";
}

public sealed class ReportResult
{
    [JsonPropertyName("accepted")] public int Accepted { get; set; }
}
