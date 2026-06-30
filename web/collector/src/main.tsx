import { render } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import "./style.css";

type InputDeviceHint = "mouse" | "touch";
type UADevice = "mobile" | "pc" | "unknown";
type CollectorTheme = "light" | "dark";

type CaptchaType =
  | "GESTURE"
  | "CURVE"
  | "CURVE_V2"
  | "CURVE_V3"
  | "SLIDER"
  | "SLIDER_V2"
  | "ROTATE";

type CollectorOptions = {
  clientID: string;
  sampleSource: string;
  scenePrefix: string;
  returnURL: string;
  limit: number;
  deviceHint: InputDeviceHint;
  uaDevice: UADevice;
  types: CaptchaType[];
  theme: CollectorTheme;
};

const defaultTypes: CaptchaType[] = [
  "SLIDER",
  "SLIDER_V2",
  "GESTURE",
  "CURVE",
  "CURVE_V2",
  "CURVE_V3",
  "ROTATE"
];

function App() {
  const options = useMemo(readCollectorOptions, []);
  const [step, setStep] = useState(0);
  const [completed, setCompleted] = useState(0);
  const [status, setStatus] = useState("加载中");
  const [nonce, setNonce] = useState(() => newNonce());
  const [activeType, setActiveType] = useState<CaptchaType>(() => randomCaptchaType(options.types));
  const completedRef = useRef(0);
  const iframeURL = runtimeURL(options, activeType, step, nonce);
  const done = options.limit > 0 && completed >= options.limit;

  useEffect(() => {
    document.title = "安全验证";
  }, []);

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      if (event.origin !== window.location.origin) return;
      const data = event.data || {};
      if (data.type === "CAPTCHA_READY") {
        setStatus("请完成验证");
      }
      if (data.type === "CAPTCHA_FAILURE") {
        setStatus("验证重试中");
        emitParentMessage("CAPTCHA_COLLECTOR_RETRY", {
          reason: data.reason || "",
          count: completedRef.current,
          limit: options.limit,
          captchaType: activeType,
          device: options.deviceHint,
          uaDevice: options.uaDevice,
          sampleSource: options.sampleSource
        });
      }
      if (data.type === "CAPTCHA_SUCCESS") {
        const nextCompleted = completedRef.current + 1;
        completedRef.current = nextCompleted;
        setCompleted(nextCompleted);
        emitParentMessage("CAPTCHA_COLLECTOR_PROGRESS", {
          count: nextCompleted,
          limit: options.limit,
          captchaType: activeType,
          device: options.deviceHint,
          uaDevice: options.uaDevice,
          sampleSource: options.sampleSource
        });
        if (options.limit > 0 && nextCompleted >= options.limit) {
          setStatus("已完成");
          emitParentMessage("CAPTCHA_COLLECTOR_DONE", {
            count: nextCompleted,
            device: options.deviceHint,
            uaDevice: options.uaDevice,
            sampleSource: options.sampleSource
          });
          redirectAfterDone(options.returnURL);
          return;
        }
        setStatus("加载下一题");
        setStep((current) => current + 1);
        setActiveType((current) => randomCaptchaType(options.types, current));
        setNonce(newNonce());
      }
      if (data.type === "CAPTCHA_CLOSE") {
        emitParentMessage("CAPTCHA_COLLECTOR_CLOSE", {
          count: completedRef.current,
          limit: options.limit,
          captchaType: activeType
        });
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [activeType, options]);

  const progressText = options.limit > 1 ? `${Math.min(completed, options.limit)}/${options.limit}` : "";
  return (
    <main class="collector-shell" data-device={options.deviceHint} data-theme={options.theme}>
      <section class="collector-panel" aria-label="安全验证">
        <header class="collector-header">
          <div>
            <strong>{done ? "验证完成" : "安全验证"}</strong>
            <span>{done ? "正在返回结果" : "完成后继续查看结果"}</span>
          </div>
          {progressText ? <b>{progressText}</b> : null}
        </header>

        <div class="real-captcha-frame-shell">
          {done ? (
            <div class="done-layer">
              <strong>验证完成</strong>
              <span>正在返回结果</span>
            </div>
          ) : (
            <iframe
              key={iframeURL}
              class="real-captcha-frame"
              title="验证码"
              src={iframeURL}
              allow="clipboard-read; clipboard-write"
            />
          )}
        </div>

        <footer class="collector-footer">
          <span>{status}</span>
          <i style={{ width: options.limit > 0 ? `${Math.min(100, (completed / options.limit) * 100)}%` : "100%" }} />
        </footer>
      </section>
    </main>
  );
}

function readCollectorOptions(): CollectorOptions {
  const params = new URLSearchParams(window.location.search);
  const uaDevice = detectUADevice();
  const deviceHint = normalizePublicInputDevice(params.get("input_device") || params.get("device") || "", uaDevice);
  const sampleSource = normalizeTag(params.get("sample_source") || params.get("source") || "personality-hk", 48);
  const scenePrefix = normalizeTag(params.get("scene") || `${sampleSource}-${uaDevice}-${deviceHint}`, 64);
  return {
    clientID: normalizeTag(params.get("client_id") || "demo", 64),
    sampleSource,
    scenePrefix,
    returnURL: params.get("return_url") || "",
    limit: numberParam(params.get("limit"), 1, 0, 50),
    deviceHint,
    uaDevice,
    types: captchaTypesFromParam(params.get("types") || params.get("captcha_types") || ""),
    theme: collectorTheme(params)
  };
}

function randomCaptchaType(types: CaptchaType[], previous?: CaptchaType): CaptchaType {
  const pool = types.length > 1 && previous ? types.filter((item) => item !== previous) : types;
  return pool[Math.floor(Math.random() * pool.length)] || "SLIDER";
}

function runtimeURL(options: CollectorOptions, captchaType: CaptchaType, step: number, nonce: string) {
  const params = new URLSearchParams({
    client_id: options.clientID,
    scene: normalizeTag(`${options.scenePrefix}-${captchaType.toLowerCase()}`, 64),
    captcha_type: captchaType,
    route: `/collector/${options.sampleSource}/${options.uaDevice}/${options.deviceHint}/${captchaType.toLowerCase()}`,
    request_nonce: nonce,
    input_device: options.deviceHint,
    sample_source: options.sampleSource,
    collector_mode: "real-runtime",
    step: String(step + 1)
  });
  if (options.theme === "dark") {
    params.set("theme", "dark");
    params.set("embed", "1");
  }
  return `/captcha/?${params.toString()}`;
}

function collectorTheme(params: URLSearchParams): CollectorTheme {
  const theme = (params.get("theme") || params.get("embed_theme") || "").trim().toLowerCase();
  const embed = (params.get("embed") || "").trim().toLowerCase();
  return theme === "dark" || embed === "1" || embed === "true" ? "dark" : "light";
}

function captchaTypesFromParam(value: string): CaptchaType[] {
  const requested = value
    .split(",")
    .map((item) => normalizeCaptchaType(item))
    .filter((item): item is CaptchaType => Boolean(item));
  return requested.length > 0 ? requested : defaultTypes;
}

function normalizeCaptchaType(value: string): CaptchaType | "" {
  const normalized = value.trim().toUpperCase().replace(/-/g, "_");
  switch (normalized) {
    case "DRAW":
    case "GESTURE":
      return "GESTURE";
    case "CURVE":
    case "CURVE_V2":
    case "CURVE_V3":
    case "SLIDER":
    case "SLIDER_V2":
    case "ROTATE":
      return normalized;
    case "ROTATE_DEGREE":
      return "ROTATE";
    default:
      return "";
  }
}

function detectUADevice(): UADevice {
  const ua = navigator.userAgent || "";
  if (/Mobile|Android|iPhone|iPod|IEMobile|Windows Phone/i.test(ua)) return "mobile";
  if (/iPad|Tablet/i.test(ua)) return "mobile";
  if (navigator.maxTouchPoints > 1 && mediaMatches("(pointer: coarse)")) return "mobile";
  return "pc";
}

function normalizePublicInputDevice(value: string, uaDevice: UADevice): InputDeviceHint {
  const normalized = value.trim().toLowerCase();
  if (normalized === "touch" || normalized === "mobile") return "touch";
  return uaDevice === "mobile" ? "touch" : "mouse";
}

function emitParentMessage(type: string, payload: Record<string, unknown>) {
  window.parent?.postMessage({ type, ...payload }, "*");
}

function redirectAfterDone(returnURL: string) {
  if (!returnURL || window.parent !== window) return;
  window.setTimeout(() => {
    window.location.assign(returnURL);
  }, 520);
}

function normalizeTag(value: string, maxLength: number) {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return (normalized || "collector").slice(0, maxLength);
}

function numberParam(value: string | null, fallback: number, min: number, max: number) {
  if (value == null || value.trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.round(Math.min(max, Math.max(min, parsed)));
}

function newNonce() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  return `collector-${Date.now()}-${Math.round(Math.random() * 100000)}`;
}

function mediaMatches(query: string) {
  try {
    return window.matchMedia?.(query).matches || false;
  } catch {
    return false;
  }
}

render(<App />, document.getElementById("app")!);
