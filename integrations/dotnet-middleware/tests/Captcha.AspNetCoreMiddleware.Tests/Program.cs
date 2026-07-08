using System.Net;
using System.Text;
using System.Text.Json;
using Captcha.AspNetCoreMiddleware;
using Microsoft.AspNetCore.Http;

await TestAllowsRequestWhenPlatformAllows();
await TestConsumesTicketBeforePolicyEvaluation();
await TestReturnsChallengeDetails();
await TestBlocksUnsupportedPolicyDecision();
await TestBlocksInvalidTicketWithoutPolicyFallback();
await TestIgnoresForgedForwardedForFromUntrustedPeer();
await TestFailCloseAndCircuitBreaker();
Console.WriteLine("PASS: CaptCha ASP.NET Core middleware smoke tests");

static async Task TestAllowsRequestWhenPlatformAllows()
{
    var platform = new FakePlatform
    {
        PolicyResponse = """{"action":"allow","reason":"CLEARANCE_VALID","clearance_token":"clearance_dotnet","clearance_ttl_seconds":600}""",
    };
    var middleware = Middleware(platform, nextStatus: 204, options =>
    {
        options.HeaderAllowlist = new List<string> { "X-Trace-ID" };
        options.ClearanceCookieSecure = true;
    });
    var context = Context("/api/login", new Dictionary<string, string>
    {
        ["X-Captcha-Resource-Tag"] = "campaign",
        ["X-Captcha-Account-ID-Hash"] = "acct_hash_dotnet",
        ["X-Captcha-Device-ID-Hash"] = "device_hash_dotnet",
        ["X-Captcha-Risk-Score"] = "77",
        ["X-Captcha-Risk-Level"] = "high",
        ["X-Captcha-Model-Score"] = "88",
        ["X-Captcha-Model-Mode"] = "observe",
        ["X-Trace-ID"] = "trace-dotnet",
        ["Authorization"] = "Bearer should-not-forward",
    });

    await middleware.InvokeAsync(context);

    AssertEqual(204, context.Response.StatusCode, "allow status");
    AssertEqual("clearance_dotnet", context.Response.Headers["X-Captcha-Clearance"].ToString(), "clearance header");
    AssertContains(context.Response.Headers.SetCookie.ToString(), "captcha_clearance=clearance_dotnet", "clearance cookie");
    AssertContains(context.Response.Headers.SetCookie.ToString(), "secure", "secure clearance cookie");
    AssertEqual(1, platform.PolicyRequests.Count, "policy request count");
    var evaluated = platform.PolicyRequests[0];
    AssertContains(evaluated, "\"scene\":\"api\"", "scene from path");
    AssertContains(evaluated, "\"resource_tag\":\"campaign\"", "resource tag");
    AssertContains(evaluated, "\"account_id_hash\":\"acct_hash_dotnet\"", "account hash");
    AssertContains(evaluated, "\"headers\":{\"x-trace-id\":\"trace-dotnet\"}", "allowlisted header");
    AssertNotContains(evaluated, "authorization", "authorization must not be forwarded");
}

static async Task TestConsumesTicketBeforePolicyEvaluation()
{
    var platform = new FakePlatform
    {
        TicketResponse = """{"valid":true,"scene":"login","route":"/login","clearance_token":"clearance_ticket_dotnet","clearance_ttl_seconds":300}""",
    };
    var middleware = Middleware(platform, nextStatus: 202, options =>
    {
        options.ResolveScene = _ => "login";
    });
    var context = Context("/login", new Dictionary<string, string>
    {
        ["X-Captcha-Ticket"] = "ticket_ok",
        ["X-Captcha-Request-Nonce"] = "nonce-dotnet",
        ["X-Captcha-Account-ID-Hash"] = "acct_ticket_dotnet",
        ["X-Captcha-Device-ID-Hash"] = "device_ticket_dotnet",
    });

    await middleware.InvokeAsync(context);
    await WaitFor(() => platform.EventRequests.Count == 1);

    AssertEqual(202, context.Response.StatusCode, "ticket next status");
    AssertEqual("clearance_ticket_dotnet", context.Response.Headers["X-Captcha-Clearance"].ToString(), "ticket clearance header");
    AssertEqual(1, platform.TicketRequests.Count, "ticket request count");
    AssertEqual(0, platform.PolicyRequests.Count, "policy must not be called for ticket path");
    AssertContains(platform.TicketRequests[0], "\"ticket\":\"ticket_ok\"", "ticket body");
    AssertContains(platform.TicketRequests[0], "\"scene\":\"login\"", "ticket scene");
    AssertContains(platform.TicketRequests[0], "\"route\":\"/login\"", "ticket route");
    AssertContains(platform.TicketRequests[0], "\"request_nonce\":\"nonce-dotnet\"", "ticket nonce");
    AssertContains(platform.EventRequests[0], "\"action\":\"allow\"", "ticket event action");
    AssertContains(platform.EventRequests[0], "\"decision_reason\":\"TICKET_CONSUMED\"", "ticket event reason");
}

static async Task TestReturnsChallengeDetails()
{
    var platform = new FakePlatform
    {
        PolicyResponse = """{"action":"challenge","reason":"ALWAYS","challenge_url":"/challenge?session_id=cap_sess_test","session_id":"cap_sess_test","scene":"login","challenge_type":"SLIDER","ttl_seconds":120}""",
    };
    var middleware = Middleware(platform, nextStatus: 204);
    var context = Context("/login", new Dictionary<string, string>());

    await middleware.InvokeAsync(context);

    AssertEqual(403, context.Response.StatusCode, "challenge status");
    var body = Body(context);
    AssertContains(body, "\"challenge_url\":\"https://captcha.example.com/challenge?session_id=cap_sess_test\"", "absolute challenge url");
    AssertContains(body, "\"challenge_type\":\"SLIDER\"", "challenge type");
}

static async Task TestBlocksUnsupportedPolicyDecision()
{
    var platform = new FakePlatform
    {
        PolicyResponse = """{"action":"retry","reason":"VERIFY_RETRY"}""",
    };
    var middleware = Middleware(platform, nextStatus: 204);
    var context = Context("/login", new Dictionary<string, string>());

    await middleware.InvokeAsync(context);

    AssertEqual(403, context.Response.StatusCode, "unsupported decision status");
    var body = Body(context);
    AssertContains(body, "\"action\":\"block\"", "unsupported decision action");
    AssertContains(body, "\"reason\":\"UNSUPPORTED_POLICY_DECISION\"", "unsupported decision reason");
    AssertEqual(1, platform.PolicyRequests.Count, "unsupported decision policy request count");
}

static async Task TestBlocksInvalidTicketWithoutPolicyFallback()
{
    var platform = new FakePlatform
    {
        TicketResponse = """{"valid":false,"reason":"CONSUMED"}""",
    };
    var middleware = Middleware(platform, nextStatus: 204, options =>
    {
        options.ResolveScene = _ => "login";
    });
    var context = Context("/login", new Dictionary<string, string>
    {
        ["X-Captcha-Ticket"] = "ticket_consumed",
    });

    await middleware.InvokeAsync(context);
    await WaitFor(() => platform.EventRequests.Count == 1);

    AssertEqual(403, context.Response.StatusCode, "invalid ticket status");
    var body = Body(context);
    AssertContains(body, "\"action\":\"block\"", "invalid ticket action");
    AssertContains(body, "\"reason\":\"CONSUMED\"", "invalid ticket reason");
    AssertEqual(0, platform.PolicyRequests.Count, "invalid ticket must not fall back to policy");
    AssertContains(platform.EventRequests[0], "\"decision_reason\":\"CONSUMED\"", "invalid ticket event reason");
}

static async Task TestIgnoresForgedForwardedForFromUntrustedPeer()
{
    var platform = new FakePlatform();
    var middleware = Middleware(platform, nextStatus: 204, options =>
    {
        options.TrustedProxyCidrs = new List<string> { "203.0.113.0/24" };
    });
    var context = Context("/login", new Dictionary<string, string>
    {
        ["X-Forwarded-For"] = "10.0.0.1",
    });

    await middleware.InvokeAsync(context);

    AssertEqual(204, context.Response.StatusCode, "untrusted forwarded-for status");
    AssertContains(platform.PolicyRequests[0], "\"ip\":\"198.51.100.9\"", "direct peer ip");
    AssertNotContains(platform.PolicyRequests[0], "\"ip\":\"10.0.0.1\"", "forged forwarded-for ip");
}

static async Task TestFailCloseAndCircuitBreaker()
{
    var platform = new FakePlatform { PolicyStatus = HttpStatusCode.ServiceUnavailable };
    var middleware = Middleware(platform, nextStatus: 204, options =>
    {
        options.FailPolicy = "fail_close";
        options.CircuitBreakerFailureThreshold = 1;
        options.CircuitBreakerCooldown = TimeSpan.FromSeconds(60);
    });

    var first = Context("/login", new Dictionary<string, string>());
    await middleware.InvokeAsync(first);
    var second = Context("/login", new Dictionary<string, string>());
    await middleware.InvokeAsync(second);
    await WaitFor(() => platform.EventRequests.Count == 2);

    AssertEqual(503, first.Response.StatusCode, "first fail-close status");
    AssertEqual(503, second.Response.StatusCode, "breaker fail-close status");
    AssertEqual(1, platform.PolicyRequests.Count, "breaker skips second policy call");
    AssertContains(platform.EventRequests[0], "\"decision_reason\":\"POLICY_UNAVAILABLE\"", "first unavailable event");
    AssertContains(platform.EventRequests[1], "\"decision_reason\":\"POLICY_UNAVAILABLE\"", "second unavailable event");
}

static CaptchaMiddleware Middleware(FakePlatform platform, int nextStatus, Action<CaptchaOptions>? configure = null)
{
    var options = new CaptchaOptions
    {
        PlatformUrl = "https://captcha.example.com",
        HttpClient = new HttpClient(platform),
    };
    configure?.Invoke(options);
    return new CaptchaMiddleware(context =>
    {
        context.Response.StatusCode = nextStatus;
        return Task.CompletedTask;
    }, options);
}

static DefaultHttpContext Context(string path, Dictionary<string, string> headers)
{
    var context = new DefaultHttpContext();
    context.Request.Method = "POST";
    context.Request.Path = path;
    context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.9");
    context.Request.Headers.UserAgent = "dotnet-test";
    foreach (var (key, value) in headers)
    {
        context.Request.Headers[key] = value;
    }
    context.Response.Body = new MemoryStream();
    return context;
}

static string Body(DefaultHttpContext context)
{
    context.Response.Body.Position = 0;
    return new StreamReader(context.Response.Body).ReadToEnd();
}

static async Task WaitFor(Func<bool> predicate)
{
    for (var i = 0; i < 200; i++)
    {
        if (predicate())
        {
            return;
        }
        await Task.Delay(5);
    }
    throw new Exception("timed out waiting for condition");
}

static void AssertEqual<T>(T expected, T actual, string label)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new Exception($"{label}: expected {expected}, got {actual}");
    }
}

static void AssertContains(string value, string expected, string label)
{
    if (!value.Contains(expected, StringComparison.Ordinal))
    {
        throw new Exception($"{label}: expected {expected} in {value}");
    }
}

static void AssertNotContains(string value, string expected, string label)
{
    if (value.Contains(expected, StringComparison.Ordinal))
    {
        throw new Exception($"{label}: did not expect {expected} in {value}");
    }
}

sealed class FakePlatform : HttpMessageHandler
{
    public HttpStatusCode PolicyStatus { get; set; } = HttpStatusCode.OK;
    public HttpStatusCode TicketStatus { get; set; } = HttpStatusCode.OK;
    public string PolicyResponse { get; set; } = """{"action":"allow","reason":"OK"}""";
    public string TicketResponse { get; set; } = """{"valid":true}""";
    public List<string> PolicyRequests { get; } = [];
    public List<string> TicketRequests { get; } = [];
    public List<string> EventRequests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        return request.RequestUri!.AbsolutePath switch
        {
            "/api/v1/policy/evaluate" => Record(PolicyRequests, body, PolicyStatus, PolicyResponse),
            "/api/v1/tickets/verify" => Record(TicketRequests, body, TicketStatus, TicketResponse),
            "/api/v1/events/report" => Record(EventRequests, body, HttpStatusCode.OK, """{"accepted":1}"""),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("""{"error":"not found"}""", Encoding.UTF8, "application/json") },
        };
    }

    private static HttpResponseMessage Record(List<string> requests, string body, HttpStatusCode status, string response)
    {
        requests.Add(JsonSerializer.Serialize(JsonSerializer.Deserialize<object>(body)));
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(response, Encoding.UTF8, "application/json"),
        };
    }
}
