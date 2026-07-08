import { render } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import "./style.css";

type CaptchaType =
  | "GESTURE"
  | "CURVE"
  | "CURVE_V2"
  | "CURVE_V3"
  | "SLIDER"
  | "SLIDER_V2"
  | "ROTATE"
  | "CONCAT"
  | "ROTATE_DEGREE"
  | "WORD_IMAGE_CLICK"
  | "IMAGE_CLICK"
  | "JIGSAW"
  | "GRID_IMAGE_CLICK";

type CaptchaRequestType = CaptchaType | "RANDOM";

type RenderResource = {
  id: string;
  captcha_type: CaptchaType | "AUTO";
  scene?: string;
  resource_type: string;
  storage_type: string;
  uri: string;
  tag?: string;
  checksum?: string;
  metadata?: Record<string, unknown>;
  status: string;
};

type ChallengePoint = {
  x: number;
  y: number;
};

type VerifyAnswerPayload = {
  x?: number;
  angle?: number;
  offset?: number;
  points?: ChallengePoint[];
  tile_order?: number[];
};

type InteractionSnapshot = {
  value: number;
  points: ChallengePoint[];
  track: TrackPoint[];
  completed?: boolean;
  autoVerify?: boolean;
};

type CurveProfile = {
  variant?: number;
  visual_style?: "single-rope" | "dual-noise" | "ring-deform";
  moving_points?: ChallengePoint[];
  drive_points?: ChallengePoint[];
  endpoint_mode?: "visible" | "hidden" | "drag";
};

type ChallengeParameters = {
  min?: number;
  max?: number;
  step?: number;
  piece_y?: number;
  piece_size?: number;
  split_y?: number;
  piece_width?: number;
  tile_cols?: number;
  tile_rows?: number;
  tile_width?: number;
  tile_height?: number;
  target_count?: number;
  resources?: RenderResource[];
  curve_profile?: CurveProfile;
};

type Challenge = {
  type: CaptchaType;
  prompt: string;
  view: { width: number; height: number };
  image?: string;
  piece?: string;
  words?: string[];
  parameters?: ChallengeParameters;
};

type SessionResponse = {
  session_id: string;
  challenge_url: string;
  captcha_type: CaptchaType;
  expire_in: number;
  route?: string;
  request_nonce?: string;
  resource_tag?: string;
  return_url?: string;
};

type ChallengeResponse = {
  ok?: boolean;
  reason?: string;
  reason_code?: string;
  session_id: string;
  client_id: string;
  scene: string;
  status?: string;
  expire_at?: string;
  route?: string;
  request_nonce?: string;
  resource_tag?: string;
  return_url?: string;
  challenge?: Challenge;
};

type RefreshResponse = {
  ok?: boolean;
  session_id?: string;
  expire_at?: string;
  reason?: string;
  reason_code?: string;
  can_refresh?: boolean;
  route?: string;
  request_nonce?: string;
  resource_tag?: string;
  return_url?: string;
  challenge?: Challenge;
};

type VerifyResponse = {
  ok?: boolean;
  decision?: string;
  reason?: string;
  reason_code?: string;
  can_refresh?: boolean;
  captcha_type?: string;
  ticket?: string;
  route?: string;
  request_nonce?: string;
  resource_tag?: string;
  return_url?: string;
  expire_at?: string;
  challenge?: Challenge;
};

type TrackPoint = {
  x: number;
  y: number;
  t: number;
  type: "start" | "move" | "end";
};

type PointerInputType = "mouse" | "touch" | "keyboard" | "unknown";
type InputDeviceHint = "mouse" | "trackpad" | "touch" | "unknown";

type InputMetaState = {
  inputDeviceHint: InputDeviceHint;
  primaryPointerType: PointerInputType;
  lastPointerType: PointerInputType;
  pointerCounts: Record<PointerInputType, number>;
  keyboardUsed: boolean;
  touchCapable: boolean;
  coarsePointer: boolean;
  hoverCapable: boolean;
  maxTouchPoints: number;
};

type CollectorTaskType = "slider_short" | "slider_medium" | "slider_long" | "slider_slow" | "slider_fast" | "slider_adjust";

type CollectorTask = {
  id: string;
  type: CollectorTaskType;
  title: string;
  start: ChallengePoint;
  target: ChallengePoint;
  path: ChallengePoint[];
};

const apiBase = import.meta.env.VITE_API_BASE || "http://localhost:8080";
const appBasePath = normalizeAppBasePath(import.meta.env.BASE_URL || "/");
const sliderThumbWidth = 52;
const recreateSessionReasons = new Set([
  "EXPIRED",
  "NOT_FOUND",
  "CONSUMED",
  "SESSION_NOT_ACTIVE",
  "SESSION_ALREADY_VERIFIED"
]);

function responseReason(response?: { reason?: string; reason_code?: string }, fallback = "UNKNOWN") {
  return response?.reason_code || response?.reason || fallback;
}

function shouldRecreateSession(reason?: string) {
  return Boolean(reason && recreateSessionReasons.has(reason));
}

function expiredRefreshStatus(reason?: string) {
  return reason === "EXPIRED" ? "验证码已过期，正在刷新" : "验证码已失效，正在刷新";
}

function runtimeThemeFromParams(params: URLSearchParams) {
  const theme = (params.get("theme") || "").trim().toLowerCase();
  const embed = (params.get("embed") || "").trim().toLowerCase();
  return theme === "dark" || embed === "1" || embed === "true" ? "dark" : "light";
}

function App() {
  const pathname = appPathname();
  if (pathname === "/collect") {
    return <CollectPage />;
  }
  if (pathname === "/demo") {
    return <DemoPage />;
  }
  return <RuntimeChallenge />;
}

function RefreshIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M20 11a8 8 0 1 0-2.34 5.66" />
      <path d="M20 5v6h-6" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M18 6 6 18" />
      <path d="m6 6 12 12" />
    </svg>
  );
}

function RuntimeHeaderActions({ onRefresh, onClose, refreshDisabled = false }: { onRefresh: () => void; onClose: () => void; refreshDisabled?: boolean }) {
  return (
    <div class="runtime-header-actions">
      <button type="button" class="icon-button" onClick={onRefresh} disabled={refreshDisabled} aria-label="刷新验证码" title="刷新">
        <RefreshIcon />
      </button>
      <button type="button" class="icon-button" onClick={onClose} aria-label="关闭验证码" title="关闭">
        <CloseIcon />
      </button>
    </div>
  );
}

function CollectPage() {
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const inputDeviceHint = useMemo(() => normalizeInputDeviceHint(params.get("input_device") || params.get("device") || params.get("input") || ""), [params]);
  const collectorToken = useMemo(() => params.get("collector_token") || params.get("token") || "", [params]);
  const clientID = useMemo(() => params.get("client_id") || "demo", [params]);
  const scene = useMemo(() => params.get("scene") || `collector-${inputDeviceHint}`, [params, inputDeviceHint]);
  const [taskIndex, setTaskIndex] = useState(0);
  const [task, setTask] = useState(() => createCollectorTask(0));
  const [collectorValue, setCollectorValue] = useState(0);
  const [track, setTrack] = useState<TrackPoint[]>([]);
  const [status, setStatus] = useState("等待操作");
  const [submitted, setSubmitted] = useState(0);
  const [paused, setPaused] = useState(false);
  const collectorControlRef = useRef<HTMLDivElement>(null);
  const startedAt = useRef(0);
  const trackRef = useRef<TrackPoint[]>([]);
  const draggingRef = useRef(false);
  const inputMetaRef = useRef<InputMetaState>(createInputMetaState(inputDeviceHint));
  const submitInFlight = useRef(false);
  const nextTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    document.title = "轨迹采集";
    return () => {
      if (nextTimer.current) clearTimeout(nextTimer.current);
    };
  }, []);

  function resetForTask(nextIndex: number) {
    const nextTask = createCollectorTask(nextIndex);
    setTaskIndex(nextIndex);
    setTask(nextTask);
    setCollectorValue(0);
    setTrack([]);
    setStatus("等待操作");
    trackRef.current = [];
    startedAt.current = 0;
    draggingRef.current = false;
    submitInFlight.current = false;
    inputMetaRef.current = createInputMetaState(inputDeviceHint);
  }

  function scheduleNext(delay = 380) {
    if (nextTimer.current) clearTimeout(nextTimer.current);
    nextTimer.current = setTimeout(() => {
      resetForTask(taskIndex + 1);
    }, delay);
  }

  function rememberCollectorPointer(inputType: PointerInputType) {
    const state = inputMetaRef.current;
    state.pointerCounts[inputType] = (state.pointerCounts[inputType] || 0) + 1;
    state.lastPointerType = inputType;
    if (inputType === "keyboard") {
      state.keyboardUsed = true;
      return;
    }
    if (state.primaryPointerType === "unknown" && inputType !== "unknown") {
      state.primaryPointerType = inputType;
    }
  }

  function appendCollectorTrack(type: TrackPoint["type"], point: ChallengePoint, inputType: PointerInputType) {
    rememberCollectorPointer(inputType);
    if (!startedAt.current) startedAt.current = performance.now();
    const t = Math.max(0, Math.round(performance.now() - startedAt.current));
    const previous = trackRef.current[trackRef.current.length - 1];
    if (previous && type === "move" && Math.hypot(previous.x - point.x, previous.y - point.y) < 2 && t - previous.t < 20) {
      return trackRef.current;
    }
    const monotonicT = previous && t < previous.t ? previous.t : t;
    const nextTrack = [...trackRef.current, { x: point.x, y: point.y, t: monotonicT, type }];
    trackRef.current = nextTrack.slice(-220);
    setTrack(trackRef.current);
    return trackRef.current;
  }

  function onCollectorPointerDown(event: PointerEvent) {
    if (paused || submitInFlight.current || !collectorControlRef.current) return;
    event.preventDefault();
    const point = collectorSliderPointFromEvent(event, collectorControlRef.current);
    startedAt.current = performance.now();
    trackRef.current = [];
    setTrack([]);
    setCollectorValue(point.x);
    draggingRef.current = true;
    setStatus("采集中");
    trySetPointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
    appendCollectorTrack("start", point, pointerTypeFromEvent(event));
  }

  function onCollectorPointerMove(event: PointerEvent) {
    if (!draggingRef.current || paused || submitInFlight.current || !collectorControlRef.current) return;
    event.preventDefault();
    const point = collectorSliderPointFromEvent(event, collectorControlRef.current);
    setCollectorValue(point.x);
    appendCollectorTrack("move", point, pointerTypeFromEvent(event));
  }

  function onCollectorPointerUp(event: PointerEvent) {
    if (!draggingRef.current || paused || submitInFlight.current || !collectorControlRef.current) return;
    event.preventDefault();
    const point = collectorSliderPointFromEvent(event, collectorControlRef.current);
    setCollectorValue(point.x);
    const nextTrack = appendCollectorTrack("end", point, pointerTypeFromEvent(event));
    draggingRef.current = false;
    tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
    void submitCollectorTrack(nextTrack);
  }

  function onCollectorPointerCancel(event: PointerEvent) {
    if (!draggingRef.current) return;
    draggingRef.current = false;
    tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
    setStatus("已取消");
    scheduleNext(260);
  }

  async function submitCollectorTrack(nextTrack: TrackPoint[]) {
    if (submitInFlight.current) return;
    if (nextTrack.length < 2) {
      setStatus("轨迹过短");
      scheduleNext(420);
      return;
    }
    submitInFlight.current = true;
    setStatus("提交中");
    try {
      await postWithHeaders("/api/v1/risk/track-samples", {
        client_id: clientID,
        scene,
        task_type: task.type,
        task_target: { x: Math.round(task.target.x), y: Math.round(task.target.y) },
        input_device_hint: inputDeviceHint,
        track: nextTrack,
        viewport: { width: 360, height: 48 },
        runtime_meta: {
          runtime_version: "0.1.0",
          device_pixel_ratio: window.devicePixelRatio || 1,
          ...runtimeInputMeta(inputMetaRef.current)
        }
      }, collectorToken ? { "X-Captcha-Collector-Token": collectorToken } : {});
      setSubmitted((current) => current + 1);
      setStatus("已提交");
      scheduleNext();
    } catch {
      setStatus("提交失败，自动跳过");
      scheduleNext(900);
    }
  }

  const deviceLabel = inputDeviceHint === "unknown" ? "未指定设备" : inputDeviceHint;
  const collectorRatio = clamp(collectorValue / 360, 0, 1);
  return (
    <main class="collector-shell">
      <section class="collector-panel">
        <header class="collector-header">
          <div>
            <strong>轨迹采集</strong>
            <span>{deviceLabel}</span>
          </div>
          <div class="collector-actions">
            <b>{submitted}</b>
            <button type="button" onClick={() => setPaused((current) => !current)}>
              {paused ? "继续" : "暂停"}
            </button>
          </div>
        </header>
        <div
          ref={collectorControlRef}
          class="collector-slider-control"
          role="slider"
          aria-valuemin={0}
          aria-valuemax={360}
          aria-valuenow={Math.round(collectorValue)}
          onPointerDown={onCollectorPointerDown}
          onPointerMove={onCollectorPointerMove}
          onPointerUp={onCollectorPointerUp}
          onPointerCancel={onCollectorPointerCancel}
        >
          <span class="collector-slider-target" style={{ left: collectorTargetLeftStyle(task.target.x) }} />
          <span class="collector-slider-fill" style={{ width: sliderFillWidthStyle(collectorRatio) }} />
          <span class="collector-slider-thumb" style={{ left: sliderThumbLeftStyle(collectorRatio) }} />
        </div>
        <footer class="collector-footer">
          <span>{paused ? "已暂停" : task.title}</span>
          <strong>{status}</strong>
        </footer>
      </section>
    </main>
  );
}

function DemoPage() {
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const inputDeviceHint = useMemo(() => normalizeInputDeviceHint(params.get("input_device") || params.get("device") || params.get("input") || ""), [params]);
  const sampleSource = useMemo(() => normalizeSampleSource(params.get("sample_source") || params.get("source") || "human-demo"), [params]);
  const scenePrefix = useMemo(() => normalizeScenePart(params.get("scene_prefix") || sampleSource || "human-demo"), [params, sampleSource]);
  const captchaTypes: Array<{ type: CaptchaRequestType; label: string; scene: string }> = [
    { type: "RANDOM", label: "随机验证", scene: "verify" },
    { type: "GESTURE", label: "手势描绘", scene: "verify" },
    { type: "CURVE_V3", label: "滑动曲线 V3", scene: "verify" },
    { type: "CURVE_V2", label: "滑动曲线 V2", scene: "verify" },
    { type: "CURVE", label: "滑动曲线", scene: "verify" },
    { type: "SLIDER_V2", label: "滑块增强", scene: "login" },
    { type: "SLIDER", label: "滑块拼图", scene: "login" },
    { type: "ROTATE", label: "旋转校准", scene: "pay" },
    { type: "CONCAT", label: "滑动还原", scene: "verify" },
    { type: "WORD_IMAGE_CLICK", label: "文字点选", scene: "register" },
    { type: "IMAGE_CLICK", label: "图标点选", scene: "register" },
    { type: "JIGSAW", label: "乱序拼图", scene: "verify" },
    { type: "GRID_IMAGE_CLICK", label: "图片格子", scene: "verify" }
  ];
  const [active, setActive] = useState<CaptchaRequestType>("SLIDER");
  const [nonce, setNonce] = useState(() => newNonce());
  const [status, setStatus] = useState("待验证");
  const [lastTicket, setLastTicket] = useState("");
  const [elapsed, setElapsed] = useState(0);
  const [actualType, setActualType] = useState("");
  const [frameOpen, setFrameOpen] = useState(true);
  const startedAt = useRef(performance.now());
  const autoReloadTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const activeRef = useRef<CaptchaRequestType>(active);
  const activeItem = captchaTypes.find((item) => item.type === active) || captchaTypes[0];
  const src = challengeFrameURL(activeItem.type, activeItem.scene, nonce, { inputDeviceHint, sampleSource, scenePrefix });

  useEffect(() => {
    document.title = "CaptCha Demo";
    return () => {
      if (autoReloadTimer.current) clearTimeout(autoReloadTimer.current);
    };
  }, []);

  useEffect(() => {
    activeRef.current = active;
  }, [active]);

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      if (event.origin !== window.location.origin) return;
      const data = event.data as { type?: string; ticket?: string; captchaType?: string; loadingNext?: boolean };
      if (data?.type === "CAPTCHA_READY") {
        setActualType(String(data.captchaType || ""));
        setStatus("待验证");
        setLastTicket("");
        setElapsed(0);
        setFrameOpen(true);
      }
      if (data?.type === "CAPTCHA_SUCCESS") {
        setStatus("通过");
        setLastTicket(String(data.ticket || ""));
        setElapsed(Math.max(1, Math.round(performance.now() - startedAt.current)));
        scheduleAutoReload(activeRef.current);
      }
      if (data?.type === "CAPTCHA_FAILURE") {
        setStatus(data.loadingNext ? "验证码加载中..." : "失败");
        setLastTicket("");
        setElapsed(Math.max(1, Math.round(performance.now() - startedAt.current)));
      }
      if (data?.type === "CAPTCHA_LOADING") {
        setStatus("验证码加载中...");
        setLastTicket("");
      }
      if (data?.type === "CAPTCHA_CLOSE") {
        setStatus("已关闭");
        setLastTicket("");
        setElapsed(0);
        setFrameOpen(false);
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  function reload(nextType = active) {
    if (autoReloadTimer.current) {
      clearTimeout(autoReloadTimer.current);
      autoReloadTimer.current = null;
    }
    setActive(nextType);
    setNonce(newNonce());
    setStatus("待验证");
    setLastTicket("");
    setElapsed(0);
    setActualType("");
    setFrameOpen(true);
    startedAt.current = performance.now();
  }

  function scheduleAutoReload(nextType: CaptchaRequestType) {
    if (autoReloadTimer.current) clearTimeout(autoReloadTimer.current);
    autoReloadTimer.current = window.setTimeout(() => {
      autoReloadTimer.current = null;
      reload(nextType);
    }, 180);
  }

  return (
    <main class="demo-shell">
      <section class="demo-topbar">
        <div>
          <h1>CaptCha Demo</h1>
          <p>Iframe 模式</p>
        </div>
        <button type="button" onClick={() => reload()} aria-label="刷新当前验证码">刷新</button>
      </section>

      <section class="demo-layout">
        <nav class="type-tabs" aria-label="验证码类型">
          {captchaTypes.map((item) => (
            <button
              key={item.type}
              type="button"
              class={item.type === active ? "active" : ""}
              onClick={() => reload(item.type)}
            >
              <span>{item.label}</span>
              <small>{item.type}</small>
            </button>
          ))}
        </nav>

        <section class="demo-stage" aria-label="验证码预览">
          <div class="browser-bar">
            <span>
              {activeItem.label}
              {actualType && actualType !== activeItem.type && <small>{actualType}</small>}
            </span>
            <strong>{status}</strong>
          </div>
          {frameOpen ? (
            <iframe
              key={src}
              src={src}
              title="captcha runtime"
              onLoad={() => setStatus((current) => current === "通过" ? current : "待验证")}
            />
          ) : (
            <div class="demo-frame-closed">
              <strong>验证码已关闭</strong>
              <button type="button" onClick={() => reload()}>重新打开</button>
            </div>
          )}
        </section>

        <aside class="demo-metrics" aria-label="校验状态">
          <dl>
            <div>
              <dt>请求</dt>
              <dd>{activeItem.type}</dd>
            </div>
            <div>
              <dt>实际</dt>
              <dd>{actualType || "-"}</dd>
            </div>
            <div>
              <dt>结果</dt>
              <dd>{status}</dd>
            </div>
            <div>
              <dt>耗时</dt>
              <dd>{elapsed ? `${elapsed} ms` : "-"}</dd>
            </div>
            <div>
              <dt>ticket</dt>
              <dd>{lastTicket ? shortToken(lastTicket) : "-"}</dd>
            </div>
          </dl>
        </aside>
      </section>
    </main>
  );
}

function RuntimeChallenge() {
  const params = useMemo(() => new URLSearchParams(window.location.search), []);
  const inputDeviceHint = useMemo(() => normalizeInputDeviceHint(params.get("input_device") || params.get("device") || params.get("input") || ""), [params]);
  const sampleSource = useMemo(() => normalizeSampleSource(params.get("sample_source") || params.get("source") || ""), [params]);
  const runtimeTheme = useMemo(() => runtimeThemeFromParams(params), [params]);
  const initialSessionId = useMemo(() => params.get("session_id") || sessionIDFromPath(), [params]);
  const [sessionId, setSessionId] = useState(initialSessionId);
  const [route, setRoute] = useState(params.get("route") || "");
  const [requestNonce, setRequestNonce] = useState(params.get("request_nonce") || "");
  const [resourceTag, setResourceTag] = useState(params.get("resource_tag") || "");
  const [returnUrl, setReturnUrl] = useState(params.get("return_url") || "");
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [status, setStatus] = useState("加载中");
  const [ticket, setTicket] = useState("");
  const [sessionCompleted, setSessionCompleted] = useState(false);
  const [value, setValue] = useState(0);
  const [points, setPoints] = useState<ChallengePoint[]>([]);
  const [track, setTrack] = useState<TrackPoint[]>([]);
  const [jigsawTiles, setJigsawTiles] = useState<number[]>([]);
  const startedAt = useRef(0);
  const rangeTracking = useRef(false);
  const boardRangeTracking = useRef(false);
  const curveTracking = useRef(false);
  const controlDragStart = useRef<{ offset: number } | null>(null);
  const jigsawDragStart = useRef<ChallengePoint | null>(null);
  const suppressNextBoardClick = useRef(false);
  const verifyInFlight = useRef(false);
  const verifyLoadingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const valueRef = useRef(0);
  const pointsRef = useRef<ChallengePoint[]>([]);
  const trackRef = useRef<TrackPoint[]>([]);
  const inputMetaRef = useRef<InputMetaState>(createInputMetaState(inputDeviceHint));
  const jigsawTilesRef = useRef<number[]>([]);
  const ticketRef = useRef("");
  const boardRef = useRef<HTMLDivElement>(null);
  const controlRef = useRef<HTMLDivElement>(null);
  const curveBgCanvasRef = useRef<HTMLCanvasElement>(null);
  const curveMoveCanvasRef = useRef<HTMLCanvasElement>(null);
  const jigsawCanvasRef = useRef<HTMLCanvasElement>(null);
  const sliderBounds = challenge ? rangeBounds(challenge) : { min: 0, max: 360, step: 1 };
  const sliderRatio = sliderRatioFromValue(value, sliderBounds);
  const sliderFillWidth = sliderFillWidthStyle(sliderRatio);
  const sliderThumbLeft = sliderThumbLeftStyle(sliderRatio);
  const completed = sessionCompleted || Boolean(ticket);
  const completionMarker = completed ? (ticket || "completed") : "";

  useEffect(() => {
    void bootstrap();
    return () => clearVerifyLoadingHint();
  }, []);

  useEffect(() => {
    if (!challenge || !isCurveCaptcha(challenge) || !curveBgCanvasRef.current || !curveMoveCanvasRef.current) return;
    drawCurveCanvases(curveBgCanvasRef.current, curveMoveCanvasRef.current, challenge, value);
  }, [challenge, value]);

  useEffect(() => {
    if (!challenge || !isJigsawCaptcha(challenge)) return;
    void drawJigsawCanvas(jigsawCanvasRef.current, challenge, jigsawTiles, points);
  }, [challenge, jigsawTiles, points]);

  async function bootstrap() {
    try {
      let id = sessionId;
      if (!id) {
        await createFreshSession("加载中");
        return;
      }
      await loadChallenge(id);
    } catch (error) {
      const reason = error instanceof Error ? error.message : "LOAD_FAILED";
      if (shouldRecreateSession(reason)) {
        try {
          await createFreshSession(expiredRefreshStatus(reason));
        } catch {
          setStatus("加载失败");
        }
        return;
      }
      setStatus("加载失败");
    }
  }

  async function loadChallenge(id: string) {
    const loaded = await get<ChallengeResponse>(`/api/v1/challenge/sessions/${id}`);
    if (loaded.ok === false || !loaded.challenge) {
      throw new Error(responseReason(loaded, "LOAD_FAILED"));
    }
    applySessionContext(loaded);
    if (loaded.status === "verified") {
      resetChallenge(loaded.challenge, id);
      setSessionCompleted(true);
      setStatus("验证通过");
      return;
    }
    resetChallenge(loaded.challenge, id);
  }

  async function createFreshSession(statusText = "验证码加载中...") {
    setStatus(statusText);
    const created = await post<SessionResponse>("/api/v1/challenge/sessions", {
      client_id: params.get("client_id") || "demo",
      scene: params.get("scene") || "login",
      captcha_type: params.get("captcha_type") || "AUTO",
      route,
      return_url: returnUrl,
      request_nonce: requestNonce,
      resource_tag: resourceTag
    });
    applySessionContext(created);
    setSessionId(created.session_id);
    await loadChallenge(created.session_id);
  }

  async function refresh(options: { allowDuringVerify?: boolean } = {}) {
    if (sessionCompleted || ticketRef.current || ticket) {
      setStatus("验证通过");
      return;
    }
    if (verifyInFlight.current && !options.allowDuringVerify) {
      return;
    }
    if (!sessionId) {
      await bootstrap();
      return;
    }
    setStatus("验证码加载中...");
    try {
      const refreshed = await post<RefreshResponse>(`/api/v1/challenge/sessions/${sessionId}/refresh`, {});
      applySessionContext(refreshed);
      if (!refreshed.challenge) {
        const reason = responseReason(refreshed, "REFRESH_FAILED");
        if (shouldRecreateSession(reason)) {
          await createFreshSession(expiredRefreshStatus(reason));
          return;
        }
        if (refreshed.reason_code === "SESSION_ALREADY_VERIFIED") {
          setSessionCompleted(true);
        }
        setStatus(reason === "SESSION_ALREADY_VERIFIED" ? "验证通过" : "刷新失败");
        return;
      }
      resetChallenge(refreshed.challenge, sessionId);
    } catch {
      setStatus("刷新失败");
    }
  }

  function closeCaptcha() {
    window.parent?.postMessage({ type: "CAPTCHA_CLOSE", sessionId, route, requestNonce, captchaType: challenge?.type }, "*");
    if (window.parent === window) {
      window.close();
      return;
    }
    try {
      const frame = window.frameElement;
      if (frame instanceof HTMLElement) {
        frame.style.display = "none";
      }
    } catch {
      // Cross-origin parents can still react to CAPTCHA_CLOSE through postMessage.
    }
  }

  function resetChallenge(next: Challenge, readySessionId = sessionId) {
    clearVerifyLoadingHint();
    setChallenge(next);
    setStatus("");
    setTicket("");
    setSessionCompleted(false);
    setPoints([]);
    setTrack([]);
    setValue(0);
    ticketRef.current = "";
    pointsRef.current = [];
    trackRef.current = [];
    inputMetaRef.current = createInputMetaState(inputDeviceHint);
    valueRef.current = 0;
    const nextJigsawTiles = isJigsawCaptcha(next) ? initialJigsawTiles(next) : [];
    jigsawTilesRef.current = nextJigsawTiles;
    setJigsawTiles(nextJigsawTiles);
    startedAt.current = performance.now();
    rangeTracking.current = false;
    boardRangeTracking.current = false;
    curveTracking.current = false;
    controlDragStart.current = null;
    jigsawDragStart.current = null;
    suppressNextBoardClick.current = false;
    verifyInFlight.current = false;
    window.parent?.postMessage({ type: "CAPTCHA_READY", captchaType: next.type, prompt: next.prompt, sessionId: readySessionId, route, requestNonce }, "*");
  }

  function applySessionContext(context: { route?: string; request_nonce?: string; resource_tag?: string; return_url?: string }) {
    if (context.route) setRoute(context.route);
    if (context.request_nonce) setRequestNonce(context.request_nonce);
    if (context.resource_tag) setResourceTag(context.resource_tag);
    if (context.return_url) setReturnUrl(context.return_url);
  }

  function beginVerifyLoadingHint() {
    clearVerifyLoadingHint();
    verifyLoadingTimer.current = window.setTimeout(() => {
      verifyLoadingTimer.current = null;
      if (!verifyInFlight.current || ticketRef.current || sessionCompleted) return;
      setStatus("验证码加载中...");
      notifyParentLoading();
    }, 250);
  }

  function clearVerifyLoadingHint() {
    if (!verifyLoadingTimer.current) return;
    clearTimeout(verifyLoadingTimer.current);
    verifyLoadingTimer.current = null;
  }

  async function verify(snapshot?: { value?: number; points?: ChallengePoint[]; track?: TrackPoint[] }) {
    if (!challenge || !sessionId) return;
    if (verifyInFlight.current || ticketRef.current || sessionCompleted) return;
    verifyInFlight.current = true;
    setStatus("验证中");
    beginVerifyLoadingHint();
    const answerValue = snapshot?.value ?? valueRef.current;
    const answerPoints = snapshot?.points ?? pointsRef.current;
    const answerTrack = snapshot?.track ?? trackRef.current;
    const payload = {
      answer: buildAnswer(challenge, answerValue, answerPoints, jigsawTilesRef.current),
      track: ensureTrack(answerTrack, answerValue),
      viewport: {
        width: challenge.view.width,
        height: challenge.view.height
      },
      route,
      runtime_meta: {
        runtime_version: "0.1.0",
        device_pixel_ratio: window.devicePixelRatio || 1,
        request_nonce: requestNonce,
        sample_source: sampleSource,
        ...runtimeInputMeta(inputMetaRef.current)
      }
    };
    try {
      const result = await post<VerifyResponse>(`/api/v1/challenge/sessions/${sessionId}/verify`, payload);
      if (result.ok) {
        clearVerifyLoadingHint();
        const issued = String(result.ticket || "");
        const successRoute = result.route || route;
        const successRequestNonce = result.request_nonce || requestNonce;
        const successReturnUrl = result.return_url || returnUrl;
        setTicket(issued);
        setSessionCompleted(true);
        ticketRef.current = issued;
        setStatus("验证通过");
        window.parent?.postMessage({ type: "CAPTCHA_SUCCESS", ticket: issued, sessionId, route: successRoute, requestNonce: successRequestNonce, returnUrl: successReturnUrl }, "*");
        redirectIfTopLevel(successReturnUrl, issued, sessionId, successRoute, successRequestNonce);
      } else {
        await handleFailedVerify(result);
      }
    } catch {
      await handleFailedVerify(undefined, "NETWORK_ERROR");
    } finally {
      verifyInFlight.current = false;
    }
  }

  async function handleFailedVerify(result?: VerifyResponse, fallbackReason = "VERIFY_FAILED") {
    clearVerifyLoadingHint();
    const reason = responseReason(result, fallbackReason);
    const loadingNext = result?.decision !== "block";
    const nextStatus = loadingNext ? "验证码加载中..." : "验证失败次数过多";
    setStatus(nextStatus);
    notifyParentFailure(reason, loadingNext);
    if (result?.challenge) {
      applySessionContext(result);
      resetChallenge(result.challenge, sessionId);
      return;
    }
    if (shouldRecreateSession(reason)) {
      try {
        await createFreshSession(expiredRefreshStatus(reason));
      } catch {
        setStatus("刷新失败");
        if (challenge) resetAttemptState(challenge);
      }
      return;
    }
    if (result?.decision === "block") {
      if (challenge) resetAttemptState(challenge);
      return;
    }
    await refresh({ allowDuringVerify: true });
  }

  function onPointer(type: TrackPoint["type"], event: PointerEvent) {
    if (!challenge || !boardRef.current) return;
    const point = challengePointFromEvent(event, challenge, boardRef.current);
    appendTrack(type, point.x, point.y, pointerTypeFromEvent(event));
  }

  function onBoardPointerDown(event: PointerEvent) {
    if (!challenge) return;
    if (interactionLocked()) return;
    if (isPathCaptcha(challenge)) {
      event.preventDefault();
      trySetPointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
      handlePathPointer("start", event, true);
      return;
    }
    if (isJigsawCaptcha(challenge)) {
      event.preventDefault();
      const point = challengePointFromEvent(event, challenge, event.currentTarget as HTMLDivElement);
      jigsawDragStart.current = point;
      trySetPointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
      appendTrack("start", point.x, point.y, pointerTypeFromEvent(event));
      return;
    }
    if (usesBoardDragControl(challenge)) {
      if (isSliderCaptcha(challenge) && !isPointerNearSliderPiece(event, challenge, event.currentTarget as HTMLDivElement, valueRef.current)) {
        return;
      }
      event.preventDefault();
      boardRangeTracking.current = true;
      trySetPointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
      updateValueFromBoard(event, "start");
      return;
    }
    if (isClickCaptcha(challenge)) {
      rememberPointerInput(pointerTypeFromEvent(event));
    }
    if (!isClickCaptcha(challenge)) {
      onPointer("start", event);
    }
  }

  function onBoardPointerMove(event: PointerEvent) {
    if (!challenge || !event.buttons) return;
    if (interactionLocked()) return;
    if (isPathCaptcha(challenge)) {
      event.preventDefault();
      handlePathPointer("move", event, false);
      return;
    }
    if (isJigsawCaptcha(challenge) && jigsawDragStart.current) {
      event.preventDefault();
      const point = challengePointFromEvent(event, challenge, event.currentTarget as HTMLDivElement);
      appendTrack("move", point.x, point.y, pointerTypeFromEvent(event));
      return;
    }
    if (usesBoardDragControl(challenge) && boardRangeTracking.current) {
      event.preventDefault();
      updateValueFromBoard(event, "move");
      return;
    }
    if (!isClickCaptcha(challenge)) {
      onPointer("move", event);
    }
  }

  function onBoardPointerUp(event: PointerEvent) {
    if (!challenge) return;
    if (interactionLocked()) return;
    if (isPathCaptcha(challenge)) {
      event.preventDefault();
      const snapshot = handlePathPointer("end", event, false);
      tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
      if (snapshot && snapshot.points.length >= 4) {
        void verify(snapshot);
      }
      return;
    }
    if (isJigsawCaptcha(challenge) && jigsawDragStart.current) {
      event.preventDefault();
      const snapshot = handleJigsawPointerUp(event);
      tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
      if (snapshot?.autoVerify && snapshot.points.length >= clickTargetCount(challenge)) {
        void verify(snapshot);
      }
      return;
    }
    if (usesBoardDragControl(challenge) && boardRangeTracking.current) {
      event.preventDefault();
      const snapshot = updateValueFromBoard(event, "end");
      boardRangeTracking.current = false;
      tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
      if (snapshot && shouldAutoVerifyOnRelease(challenge, snapshot.value)) {
        void verify(snapshot);
      }
      return;
    }
    if (!isClickCaptcha(challenge)) {
      onPointer("end", event);
    }
  }

  function onBoardPointerCancel(event: PointerEvent) {
    if (!challenge) return;
    if (isJigsawCaptcha(challenge) && jigsawDragStart.current) {
      event.preventDefault();
      jigsawDragStart.current = null;
      tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
    }
    if (usesBoardDragControl(challenge) && boardRangeTracking.current) {
      event.preventDefault();
      updateValueFromBoard(event, "end");
      boardRangeTracking.current = false;
      tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
    }
  }

  function handlePathPointer(type: TrackPoint["type"], event: PointerEvent, reset: boolean) {
    if (!challenge || !boardRef.current) return undefined;
    const point = challengePointFromEvent(event, challenge, boardRef.current);
    const nextTrack = appendTrack(type, point.x, point.y, pointerTypeFromEvent(event));
    const nextPoints = appendPathPoint(point, reset);
    return { points: nextPoints, track: nextTrack, value: valueRef.current };
  }

  function handleJigsawPointerUp(event: PointerEvent) {
    if (!challenge || !boardRef.current || !jigsawDragStart.current) return undefined;
    const start = jigsawDragStart.current;
    const end = challengePointFromEvent(event, challenge, boardRef.current);
    jigsawDragStart.current = null;
    suppressNextBoardClick.current = true;
    const nextTrack = appendTrack("end", end.x, end.y, pointerTypeFromEvent(event));
    if (distanceBetweenPoints(start, end) >= Math.min(numberParam(challenge, "tile_width", 80), numberParam(challenge, "tile_height", 40)) * 0.45) {
      const snapshot = applyJigsawPair(start, end, nextTrack);
      return snapshot ? { ...snapshot, autoVerify: false } : snapshot;
    }
    return toggleJigsawPoint(end, nextTrack);
  }

  function applyJigsawPair(first: ChallengePoint, second: ChallengePoint, nextTrack = trackRef.current): InteractionSnapshot | undefined {
    if (!challenge || !isJigsawCaptcha(challenge)) return undefined;
    const firstIndex = jigsawTileIndexFromPoint(challenge, first);
    const secondIndex = jigsawTileIndexFromPoint(challenge, second);
    if (firstIndex < 0 || secondIndex < 0 || firstIndex === secondIndex) {
      return toggleJigsawPoint(second, nextTrack);
    }
    swapJigsawTilesByIndex(firstIndex, secondIndex);
    const nextPoints: ChallengePoint[] = [];
    pointsRef.current = nextPoints;
    setPoints(nextPoints);
    return { points: nextPoints, value: valueRef.current, track: nextTrack, completed: false };
  }

  function swapJigsawTiles(first: ChallengePoint, second: ChallengePoint) {
    if (!challenge || !isJigsawCaptcha(challenge)) return;
    const firstIndex = jigsawTileIndexFromPoint(challenge, first);
    const secondIndex = jigsawTileIndexFromPoint(challenge, second);
    swapJigsawTilesByIndex(firstIndex, secondIndex);
  }

  function swapJigsawTilesByIndex(firstIndex: number, secondIndex: number) {
    if (!challenge || !isJigsawCaptcha(challenge)) return;
    if (firstIndex < 0 || secondIndex < 0 || firstIndex === secondIndex) return;
    const base = jigsawTilesRef.current.length ? jigsawTilesRef.current : initialJigsawTiles(challenge);
    if (firstIndex >= base.length || secondIndex >= base.length) return;
    const nextTiles = [...base];
    [nextTiles[firstIndex], nextTiles[secondIndex]] = [nextTiles[secondIndex], nextTiles[firstIndex]];
    jigsawTilesRef.current = nextTiles;
    setJigsawTiles(nextTiles);
  }

  function updateValueFromControl(event: PointerEvent, type: TrackPoint["type"]) {
    if (!challenge || !controlRef.current) return undefined;
    const rect = controlRef.current.getBoundingClientRect();
    if (rect.width <= 0) return undefined;
    const bounds = rangeBounds(challenge);
    const thumbOffset = controlDragStart.current?.offset ?? sliderThumbWidth / 2;
    const travelWidth = Math.max(1, rect.width - sliderThumbWidth);
    const ratio = clamp((event.clientX - rect.left - thumbOffset) / travelWidth, 0, 1);
    const raw = bounds.min + ratio * (bounds.max - bounds.min);
    const next = snapValue(raw, bounds.min, bounds.max, bounds.step);
    const trackY = Math.round(clamp(event.clientY - rect.top, 0, rect.height));
    setCurrentValue(next);
    const nextTrack = appendTrack(type, next, trackY, pointerTypeFromEvent(event));
    return { value: next, track: nextTrack };
  }

  function updateValueFromBoard(event: PointerEvent, type: TrackPoint["type"]) {
    if (!challenge || !boardRef.current) return undefined;
    const point = challengePointFromEvent(event, challenge, boardRef.current);
    const bounds = rangeBounds(challenge);
    let raw: number;
    if (challenge.type === "SLIDER" || challenge.type === "SLIDER_V2") {
      raw = point.x - sliderPieceSize(challenge) / 2;
    } else {
      raw = bounds.min + (point.x / Math.max(1, challenge.view.width)) * (bounds.max - bounds.min);
    }
    const next = snapValue(raw, bounds.min, bounds.max, bounds.step);
    setCurrentValue(next);
    const nextTrack = appendTrack(type, next, Math.round(point.y), pointerTypeFromEvent(event));
    return { value: next, track: nextTrack };
  }

  function onControlPointerDown(event: PointerEvent) {
    if (interactionLocked()) return;
    if (!challenge) return;
    const dragStart = controlThumbDragStart(event, challenge, valueRef.current);
    if (!dragStart) return;
    event.preventDefault();
    rangeTracking.current = true;
    controlDragStart.current = dragStart;
    trySetPointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
    updateValueFromControl(event, "start");
  }

  function onControlPointerMove(event: PointerEvent) {
    if (!rangeTracking.current) return;
    if (interactionLocked()) return;
    event.preventDefault();
    updateValueFromControl(event, "move");
  }

  function onControlPointerEnd(event: PointerEvent) {
    if (!rangeTracking.current) return;
    if (interactionLocked()) return;
    event.preventDefault();
    const snapshot = updateValueFromControl(event, "end");
    rangeTracking.current = false;
    controlDragStart.current = null;
    tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
    if (snapshot && challenge && shouldAutoVerifyOnRelease(challenge, snapshot.value)) {
      void verify(snapshot);
    }
  }

  function onControlPointerCancel(event: PointerEvent) {
    if (!rangeTracking.current) return;
    if (interactionLocked()) return;
    event.preventDefault();
    updateValueFromControl(event, "end");
    rangeTracking.current = false;
    controlDragStart.current = null;
    tryReleasePointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
  }

  function onControlKeyDown(event: KeyboardEvent) {
    if (!challenge) return;
    if (interactionLocked()) return;
    const bounds = rangeBounds(challenge);
    let next = value;
    if (event.key === "ArrowLeft" || event.key === "ArrowDown") next -= bounds.step;
    if (event.key === "ArrowRight" || event.key === "ArrowUp") next += bounds.step;
    if (event.key === "Home") next = bounds.min;
    if (event.key === "End") next = bounds.max;
    if (next !== value) {
      event.preventDefault();
      const snapped = snapValue(next, bounds.min, bounds.max, bounds.step);
      setCurrentValue(snapped);
      appendTrack("move", snapped, 0, "keyboard");
    }
  }

  function appendTrack(type: TrackPoint["type"], x: number, y: number, inputType?: PointerInputType) {
    if (inputType) rememberPointerInput(inputType);
    if (!startedAt.current) startedAt.current = performance.now();
    const t = Math.max(0, Math.round(performance.now() - startedAt.current));
    const previous = trackRef.current[trackRef.current.length - 1];
    const monotonicT = previous && t < previous.t ? previous.t : t;
    const nextTrack = [
      ...trackRef.current,
      { x, y, t: monotonicT, type }
    ];
    trackRef.current = nextTrack;
    setTrack(nextTrack);
    return nextTrack;
  }

  function rememberPointerInput(inputType: PointerInputType) {
    const state = inputMetaRef.current;
    state.pointerCounts[inputType] = (state.pointerCounts[inputType] || 0) + 1;
    state.lastPointerType = inputType;
    if (inputType === "keyboard") {
      state.keyboardUsed = true;
      return;
    }
    if (state.primaryPointerType === "unknown" && inputType !== "unknown") {
      state.primaryPointerType = inputType;
    }
  }

  function setCurrentValue(next: number) {
    valueRef.current = next;
    setValue(next);
  }

  function appendPathPoint(point: ChallengePoint, reset: boolean) {
    const base = reset ? [] : pointsRef.current;
    const nextPoints = appendPathPointTo(base, point);
    pointsRef.current = nextPoints;
    setPoints(nextPoints);
    return nextPoints;
  }

  function appendClickPoint(point: ChallengePoint, nextTrack = trackRef.current) {
    if (!challenge) return undefined;
    const nextPoints = [
      ...pointsRef.current,
      point
    ].slice(0, clickTargetCount(challenge));
    pointsRef.current = nextPoints;
    setPoints(nextPoints);
    return { points: nextPoints, value: valueRef.current, track: nextTrack };
  }

  function toggleJigsawPoint(point: ChallengePoint, nextTrack = trackRef.current): InteractionSnapshot | undefined {
    if (!challenge || !isJigsawCaptcha(challenge)) return undefined;
    const targetCount = clickTargetCount(challenge);
    const base = pointsRef.current;
    const tileIndex = jigsawTileIndexFromPoint(challenge, point);
    if (tileIndex < 0) return undefined;
    const existingIndex = base.findIndex((selected) => jigsawTileIndexFromPoint(challenge, selected) === tileIndex);
    if (existingIndex >= 0) {
      const nextPoints = base.filter((_, index) => index !== existingIndex);
      pointsRef.current = nextPoints;
      setPoints(nextPoints);
      return { points: nextPoints, value: valueRef.current, track: nextTrack, completed: false };
    }
    if (base.length >= targetCount - 1 && base.length > 0) {
      return applyJigsawPair(base[0], jigsawTileCenterPoint(challenge, tileIndex), nextTrack);
    }
    const nextPoints = existingIndex >= 0
      ? base.filter((_, index) => index !== existingIndex)
      : [...base, jigsawTileCenterPoint(challenge, tileIndex)].slice(0, targetCount);
    pointsRef.current = nextPoints;
    setPoints(nextPoints);
    return { points: nextPoints, value: valueRef.current, track: nextTrack, completed: false };
  }

  function toggleClickPoint(point: ChallengePoint, nextTrack = trackRef.current) {
    if (!challenge) return undefined;
    if (isGridImageClickCaptcha(challenge)) {
      return toggleGridPoint(point, nextTrack);
    }
    const base = pointsRef.current;
    const radius = clickCancelRadius(challenge);
    const existingIndex = base.findIndex((selected) => distanceBetweenPoints(selected, point) <= radius);
    const nextPoints = existingIndex >= 0
      ? base.filter((_, index) => index !== existingIndex)
      : base.length < clickTargetCount(challenge)
        ? [...base, point]
        : base;
    pointsRef.current = nextPoints;
    setPoints(nextPoints);
    return { points: nextPoints, value: valueRef.current, track: nextTrack };
  }

  function toggleGridPoint(point: ChallengePoint, nextTrack = trackRef.current) {
    if (!challenge || !isGridImageClickCaptcha(challenge)) return undefined;
    const tileIndex = jigsawTileIndexFromPoint(challenge, point);
    if (tileIndex < 0) return undefined;
    const base = pointsRef.current;
    const existingIndex = base.findIndex((selected) => jigsawTileIndexFromPoint(challenge, selected) === tileIndex);
    const nextPoints = existingIndex >= 0
      ? base.filter((_, index) => index !== existingIndex)
      : base.length < gridTileCount(challenge)
        ? [...base, jigsawTileCenterPoint(challenge, tileIndex)]
        : base;
    pointsRef.current = nextPoints;
    setPoints(nextPoints);
    return { points: nextPoints, value: valueRef.current, track: nextTrack };
  }

  function onBoardClick(event: MouseEvent) {
    if (!challenge || !isClickCaptcha(challenge)) return;
    if (interactionLocked()) return;
    if (!boardRef.current) return;
    if (suppressNextBoardClick.current) {
      suppressNextBoardClick.current = false;
      return;
    }
    const point = challengePointFromEvent(event, challenge, boardRef.current);
    const nextTrack = appendTrack("end", point.x, point.y, inputMetaRef.current.lastPointerType === "unknown" ? "mouse" : inputMetaRef.current.lastPointerType);
    if (isJigsawCaptcha(challenge)) {
      toggleJigsawPoint(point, nextTrack);
      return;
    }
    toggleClickPoint(point, nextTrack);
  }

  function interactionLocked() {
    return verifyInFlight.current || Boolean(ticketRef.current);
  }

  function notifyParentFailure(reason: string, loadingNext: boolean) {
    window.parent?.postMessage({ type: "CAPTCHA_FAILURE", sessionId, route, requestNonce, reason, loadingNext }, "*");
  }

  function notifyParentLoading() {
    window.parent?.postMessage({ type: "CAPTCHA_LOADING", sessionId, route, requestNonce }, "*");
  }

  function resetAttemptState(next: Challenge) {
    if (isClickCaptcha(next) || isPathCaptcha(next) || isCurveCaptcha(next)) {
      pointsRef.current = [];
      setPoints([]);
    }
    if (isJigsawCaptcha(next)) {
      const nextJigsawTiles = initialJigsawTiles(next);
      jigsawTilesRef.current = nextJigsawTiles;
      setJigsawTiles(nextJigsawTiles);
      jigsawDragStart.current = null;
    }
    if (isCurveCaptcha(next)) {
      setCurrentValue(0);
    }
    if (usesDragControl(next)) {
      setCurrentValue(0);
    }
    trackRef.current = [];
    setTrack([]);
    rangeTracking.current = false;
    boardRangeTracking.current = false;
    curveTracking.current = false;
    jigsawDragStart.current = null;
    suppressNextBoardClick.current = false;
    startedAt.current = performance.now();
  }

  const verifyDisabled = !challenge || manualVerifyDisabled(challenge, status, completionMarker, points.length, value, jigsawTiles);
  return (
    <main class="shell" data-theme={runtimeTheme}>
      <section class="panel">
        {(!challenge || !isCurveCaptcha(challenge)) && (
          <header>
            <strong>{challenge?.prompt || "人机验证"}</strong>
            <RuntimeHeaderActions onRefresh={refresh} onClose={closeCaptcha} refreshDisabled={completed || status === "验证中"} />
          </header>
        )}

        {challenge && isCurveCaptcha(challenge) && (
          <div id="tianai-captcha" class="tianai-captcha-slider runtime-curve-captcha" style={{ transform: "translateX(0px)" }}>
            <div class="slider-tip">
              <span id="tianai-captcha-slider-move-track-font">{challenge.prompt}</span>
              <RuntimeHeaderActions onRefresh={refresh} onClose={closeCaptcha} refreshDisabled={completed || status === "验证中"} />
            </div>
            <div class="content">
              <div class="bg-img-div" style={{ aspectRatio: `${challenge.view.width} / ${challenge.view.height}` }}>
                {challenge.image && (
                  <img id="tianai-captcha-slider-bg-img" src={challenge.image} alt="" draggable={false} />
                )}
                <canvas
                  ref={curveBgCanvasRef}
                  id="tianai-captcha-slider-bg-canvas"
                  width={challenge.view.width}
                  height={challenge.view.height}
                  aria-hidden="true"
                />
                <canvas
                  ref={curveMoveCanvasRef}
                  id="tianai-captcha-curve-bg-canvas"
                  width={challenge.view.width}
                  height={challenge.view.height}
                  data-view-width={challenge.view.width}
                  data-view-height={challenge.view.height}
                  data-curve-profile={curveProfileDataset(challenge)}
                  aria-hidden="true"
                />
                <div
                  class="tianai-captcha-curve-ball-div"
                  id="tianai-captcha-curve-ball-div-left"
                  style={curveEndpointStyle(challenge, "left", value)}
                />
                <div
                  class="tianai-captcha-curve-ball-div"
                  id="tianai-captcha-curve-ball-div-right"
                  style={curveEndpointStyle(challenge, "right", value)}
                />
              </div>
              <div class="tianai-captcha-tips" id="tianai-captcha-tips">{curveTipText(status)}</div>
            </div>
          <div
              ref={controlRef}
              class="slider-move"
              role="slider"
              tabIndex={0}
              aria-valuemin={sliderBounds.min}
              aria-valuemax={sliderBounds.max}
              aria-valuenow={value}
              onPointerDown={onControlPointerDown}
              onPointerMove={onControlPointerMove}
              onPointerUp={onControlPointerEnd}
              onPointerCancel={onControlPointerCancel}
              onKeyDown={onControlKeyDown}
            >
              <div class="slider-move-track">
                <div id="tianai-captcha-slider-move-track-mask" style={{ width: sliderFillWidth }} />
                <div class="slider-move-shadow" />
              </div>
              <div
                class="slider-move-btn"
                id="tianai-captcha-slider-move-btn"
                style={{ left: sliderThumbLeft }}
              />
            </div>
          </div>
        )}

        {challenge && !isCurveCaptcha(challenge) && (
          <div
            ref={boardRef}
            class={`board ${isPathCaptcha(challenge) ? "path-board" : ""} ${isCurveCaptcha(challenge) ? "curve-board" : ""} ${isJigsawCaptcha(challenge) ? "jigsaw-board" : ""} ${challenge.type === "ROTATE" ? "rotate-board" : ""} ${usesBoardDragControl(challenge) ? "drag-board" : ""}`}
            style={{ aspectRatio: `${challenge.view.width} / ${challenge.view.height}` }}
            onPointerDown={onBoardPointerDown}
            onPointerMove={onBoardPointerMove}
            onPointerUp={onBoardPointerUp}
            onPointerCancel={onBoardPointerCancel}
            onClick={onBoardClick}
          >
            {isJigsawCaptcha(challenge) && challenge.image ? (
              <canvas
                ref={jigsawCanvasRef}
                class="jigsaw-canvas"
                width={challenge.view.width}
                height={challenge.view.height}
                aria-hidden="true"
              />
            ) : challenge.image && (
              <img
                class={challenge.type === "ROTATE" ? "rotating-image" : ""}
                src={challenge.image}
                alt=""
                draggable={false}
                style={challenge.type === "ROTATE" ? { transform: `rotate(${value}deg)` } : undefined}
              />
            )}
            {challenge.type === "ROTATE_DEGREE" && (
              <span class="degree-needle" style={{ transform: `translate(-50%, -100%) rotate(${value}deg)` }} />
            )}
            {(challenge.type === "SLIDER" || challenge.type === "SLIDER_V2") && challenge.piece && (
              <img
                class="piece"
                src={challenge.piece}
                alt=""
                draggable={false}
                style={{
                  left: percent(value, challenge.view.width),
                  top: percent(numberParam(challenge, "piece_y", challenge.view.height - 60), challenge.view.height),
                  width: percent(sliderPieceSize(challenge), challenge.view.width),
                  height: percent(sliderPieceSize(challenge), challenge.view.height)
                }}
              />
            )}
            {challenge.type === "CONCAT" && challenge.piece && (
              <img
                class="concat-piece concat-piece-top"
                src={challenge.piece}
                alt=""
                draggable={false}
                style={{
                  left: percent(value - concatPieceShift(challenge), challenge.view.width),
                  width: percent(numberParam(challenge, "piece_width", challenge.view.width), challenge.view.width),
                  height: "100%"
                }}
              />
            )}
            {isPathCaptcha(challenge) && points.map((point, index) => (
              <span
                key={`${point.x}-${point.y}-${index}`}
                class={index === points.length - 1 ? "path-cursor" : "path-dot"}
                style={{ left: percent(point.x, challenge.view.width), top: percent(point.y, challenge.view.height) }}
              />
            ))}
            {isClickCaptcha(challenge) && !isJigsawCaptcha(challenge) && points.map((point, index) => (
              <span
                class="mark"
                style={{ left: percent(point.x, challenge.view.width), top: percent(point.y, challenge.view.height) }}
              >
                {index + 1}
              </span>
            ))}
          </div>
        )}

        {challenge && usesDragControl(challenge) && !isCurveCaptcha(challenge) && (
          <div
            ref={controlRef}
            class="drag-control"
            role="slider"
            tabIndex={0}
            aria-valuemin={sliderBounds.min}
            aria-valuemax={sliderBounds.max}
            aria-valuenow={value}
            onPointerDown={onControlPointerDown}
            onPointerMove={onControlPointerMove}
            onPointerUp={onControlPointerEnd}
            onPointerCancel={onControlPointerCancel}
            onKeyDown={onControlKeyDown}
          >
            <span class="drag-fill" style={{ width: sliderFillWidth }} />
            <span class="drag-thumb" style={{ left: sliderThumbLeft }} />
          </div>
        )}

        <footer>
          <span>{challenge ? footerStatus(challenge, completionMarker, status, points.length) : status}</span>
          {challenge && !usesDragControl(challenge) && (
            <button type="button" onClick={() => void verify()} disabled={verifyDisabled}>确认</button>
          )}
        </footer>
      </section>
    </main>
  );
}

function challengeFrameURL(type: CaptchaRequestType, scene: string, nonce: string, options?: { inputDeviceHint?: InputDeviceHint; sampleSource?: string; scenePrefix?: string }) {
  const inputDevice = options?.inputDeviceHint || normalizeInputDeviceHint(new URLSearchParams(window.location.search).get("input_device") || "");
  const sampleSource = normalizeSampleSource(options?.sampleSource || new URLSearchParams(window.location.search).get("sample_source") || "human-demo");
  const scenePrefix = normalizeScenePart(options?.scenePrefix || new URLSearchParams(window.location.search).get("scene_prefix") || sampleSource);
  const sceneParts = [scenePrefix, inputDevice !== "unknown" ? inputDevice : "", scene].filter(Boolean);
  const demoScene = sceneParts.join("-");
  const params = new URLSearchParams({
    client_id: "demo",
    scene: demoScene,
    captcha_type: type,
    route: `/demo/${sampleSource}/${inputDevice}/${type.toLowerCase()}`,
    request_nonce: nonce
  });
  if (inputDevice !== "unknown") params.set("input_device", inputDevice);
  params.set("sample_source", sampleSource);
  return appURL("", params);
}

const collectorTaskTypes: CollectorTaskType[] = ["slider_medium", "slider_long", "slider_adjust", "slider_slow", "slider_short", "slider_fast"];

function createCollectorTask(index: number): CollectorTask {
  const type = collectorTaskTypes[index % collectorTaskTypes.length];
  const start = { x: 0, y: 24 };
  const target = { x: collectorTargetX(type), y: 24 };
  return {
    id: `${type}-${index}-${Date.now()}`,
    type,
    title: collectorTaskTitle(type),
    start,
    target,
    path: [start, target]
  };
}

function collectorTargetX(type: CollectorTaskType) {
  switch (type) {
    case "slider_short":
      return randomInt(88, 145);
    case "slider_medium":
      return randomInt(165, 235);
    case "slider_long":
      return randomInt(268, 342);
    case "slider_adjust":
      return randomInt(210, 326);
    case "slider_slow":
      return randomInt(180, 310);
    case "slider_fast":
      return randomInt(205, 335);
  }
}

function collectorTaskTitle(type: CollectorTaskType) {
  switch (type) {
    case "slider_short":
      return "短距离拖动滑块";
    case "slider_medium":
      return "拖动滑块到目标";
    case "slider_long":
      return "长距离拖动滑块";
    case "slider_adjust":
      return "拖动滑块并微调";
    case "slider_slow":
      return "稍慢拖动滑块";
    case "slider_fast":
      return "快速拖动滑块";
    default:
      return "拖动滑块";
  }
}

function randomInt(min: number, max: number) {
  return Math.floor(min + Math.random() * (max - min + 1));
}

function collectorSliderPointFromEvent(event: MouseEvent | PointerEvent, element: HTMLDivElement) {
  const rect = element.getBoundingClientRect();
  return {
    x: Math.round(clamp((event.clientX - rect.left) / Math.max(1, rect.width), 0, 1) * 360),
    y: Math.round(clamp((event.clientY - rect.top) / Math.max(1, rect.height), 0, 1) * 48)
  };
}

function collectorTargetLeftStyle(targetX: number) {
  const ratio = clamp(targetX / 360, 0, 1);
  return `calc(${ratio * 100}% - 1px)`;
}

function newNonce() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  return `demo-${Date.now()}-${Math.round(Math.random() * 100000)}`;
}

function shortToken(value: string) {
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

function rangeBounds(challenge: Challenge) {
  return {
    min: numberParam(challenge, "min", 0),
    max: numberParam(challenge, "max", 360),
    step: Math.max(1, numberParam(challenge, "step", 1))
  };
}

function numberParam(challenge: Challenge, name: keyof ChallengeParameters, fallback: number) {
  const value = challenge.parameters?.[name];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function sliderPieceSize(challenge: Challenge) {
  return numberParam(challenge, "piece_size", 47);
}

function controlThumbDragStart(event: PointerEvent, challenge: Challenge, currentValue: number) {
  const control = event.currentTarget as HTMLDivElement;
  const rect = control.getBoundingClientRect();
  const relativeX = clamp(event.clientX - rect.left, 0, rect.width);
  const thumbWidth = control.querySelector<HTMLElement>(".slider-move-btn, .drag-thumb")?.getBoundingClientRect().width || sliderThumbWidth;
  const thumbLeft = sliderThumbLeftPx(sliderRatioFromValue(currentValue, rangeBounds(challenge)), rect.width);
  const nearThumb = relativeX >= thumbLeft - 8 && relativeX <= thumbLeft + thumbWidth + 8;
  if (!nearThumb) return null;
  return { offset: relativeX - thumbLeft };
}

function isPointerNearSliderPiece(event: PointerEvent, challenge: Challenge, board: HTMLDivElement, currentValue: number) {
  const point = challengePointFromEvent(event, challenge, board);
  const pieceSize = sliderPieceSize(challenge);
  const pieceY = numberParam(challenge, "piece_y", challenge.view.height - 60);
  const tolerance = Math.max(8, Math.round(pieceSize * 0.12));
  return (
    point.x >= currentValue - tolerance &&
    point.x <= currentValue + pieceSize + tolerance &&
    point.y >= pieceY - tolerance &&
    point.y <= pieceY + pieceSize + tolerance
  );
}

function sliderRatioFromValue(value: number, bounds: { min: number; max: number }) {
  return clamp((value - bounds.min) / Math.max(1, bounds.max - bounds.min), 0, 1);
}

function sliderThumbLeftPx(ratio: number, width: number) {
  return ratio * Math.max(1, width - sliderThumbWidth);
}

function sliderThumbLeftStyle(ratio: number) {
  const percentValue = ratio * 100;
  const pixelOffset = -ratio * sliderThumbWidth;
  return `calc(${percentValue}% + ${pixelOffset}px)`;
}

function sliderFillWidthStyle(ratio: number) {
  return sliderThumbLeftStyle(ratio);
}

function drawCurveCanvases(bgCanvas: HTMLCanvasElement, moveCanvas: HTMLCanvasElement, challenge: Challenge, value: number) {
  const profile = challenge.parameters?.curve_profile;
  const movingBase = normalizeCurvePoints(profile?.moving_points);
  const drives = normalizeCurvePoints(profile?.drive_points);
  const width = challenge.view.width;
  const height = challenge.view.height;
  const bgContext = prepareCurveCanvas(bgCanvas, width, height);
  const moveContext = prepareCurveCanvas(moveCanvas, width, height);
  if (!bgContext || !moveContext) return;
  moveCanvas.dataset.viewWidth = String(width);
  moveCanvas.dataset.viewHeight = String(height);
  moveCanvas.dataset.curveProfile = curveProfileDataset(challenge);
  if (movingBase.length < 2 || drives.length < 2) return;

  const variant = typeof profile?.variant === "number" ? profile.variant : 1;
  const moving = movingBase.map((point, index) => {
    const drive = drives[index] || { x: 0, y: 0 };
    return {
      x: point.x - drive.x * value,
      y: point.y - drive.y * value
    };
  });
  drawCurveVariant(moveContext, moving, variant, profile?.visual_style);
}

function prepareCurveCanvas(canvas: HTMLCanvasElement, width: number, height: number) {
  const ratio = Math.max(1, Math.round((window.devicePixelRatio || 1) * 100) / 100);
  const pixelWidth = Math.max(1, Math.round(width * ratio));
  const pixelHeight = Math.max(1, Math.round(height * ratio));
  if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
    canvas.width = pixelWidth;
    canvas.height = pixelHeight;
  }
  const context = canvas.getContext("2d");
  if (!context) return null;
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  return context;
}

function normalizeCurvePoints(points?: ChallengePoint[]) {
  if (!Array.isArray(points)) return [];
  return points
    .map((point) => ({
      x: Number(point?.x),
      y: Number(point?.y)
    }))
    .filter((point) => Number.isFinite(point.x) && Number.isFinite(point.y));
}

function drawCurveLine(context: CanvasRenderingContext2D, points: ChallengePoint[], width: number, color: string) {
  if (points.length < 2) return;
  context.beginPath();
  context.moveTo(points[0].x, points[0].y);
  for (let index = 1; index < points.length; index++) {
    context.lineTo(points[index].x, points[index].y);
  }
  context.lineWidth = width;
  context.strokeStyle = color;
  context.stroke();
}

function drawCurveVariant(
  moveContext: CanvasRenderingContext2D,
  moving: ChallengePoint[],
  variant: number,
  visualStyle?: CurveProfile["visual_style"]
) {
  const style = visualStyle || (variant === 2 ? "dual-noise" : variant === 3 ? "ring-deform" : "single-rope");
  if (style === "dual-noise") {
    drawCurveLayer(moveContext, moving, [
      [15, "rgba(15, 23, 42, 0.30)"],
      [10, "rgba(255, 255, 255, 0.76)"],
      [4, "rgba(148, 163, 184, 0.92)"]
    ]);
    drawRoughCurve(moveContext, moving, {
      dotColor: "rgba(255, 255, 255, 0.88)",
      lineColor: "rgba(255, 255, 255, 0.18)",
      radius: 1.4,
      jitter: 1.2,
      stride: 2,
      seed: 109
    });
    return;
  }

  if (style === "ring-deform") {
    drawCurveLayer(moveContext, moving, [
      [16, "rgba(15, 23, 42, 0.30)"],
      [11, "rgba(255, 255, 255, 0.78)"],
      [5, "rgba(241, 245, 249, 0.98)"]
    ]);
    drawCurveLayer(moveContext, offsetCurvePoints(moving, -4), [
      [5, "rgba(255, 255, 255, 0.26)"],
      [2, "rgba(255, 255, 255, 0.58)"]
    ]);
    drawCurveLayer(moveContext, offsetCurvePoints(moving, 4), [
      [5, "rgba(255, 255, 255, 0.22)"],
      [2, "rgba(255, 255, 255, 0.50)"]
    ]);
    return;
  }

  drawCurveLayer(moveContext, moving, [
    [18, "rgba(15, 23, 42, 0.32)"],
    [12, "rgba(255, 255, 255, 0.86)"],
    [6, "rgba(255, 255, 255, 0.98)"]
  ]);
}

function drawCurveLayer(context: CanvasRenderingContext2D, points: ChallengePoint[], strokes: Array<[number, string]>) {
  context.save();
  context.lineCap = "round";
  context.lineJoin = "round";
  for (const [width, color] of strokes) {
    drawCurveLine(context, points, width, color);
  }
  context.restore();
}

function drawRoughCurve(
  context: CanvasRenderingContext2D,
  points: ChallengePoint[],
  options: { dotColor: string; lineColor: string; radius: number; jitter: number; stride: number; seed: number }
) {
  if (points.length < 2) return;
  context.save();
  context.lineCap = "round";
  context.lineJoin = "round";
  drawCurveLine(context, points, Math.max(1.2, options.radius * 1.4), options.lineColor);
  context.fillStyle = options.dotColor;
  const step = Math.max(1, options.stride);
  for (let index = 0; index < points.length; index += step) {
    const point = points[index];
    const jx = deterministicNoise(index, options.seed) * options.jitter;
    const jy = deterministicNoise(index, options.seed + 37) * options.jitter;
    context.beginPath();
    context.arc(point.x + jx, point.y + jy, options.radius * (0.78 + Math.abs(deterministicNoise(index, options.seed + 73)) * 0.38), 0, Math.PI * 2);
    context.fill();
  }
  context.restore();
}

function offsetCurvePoints(points: ChallengePoint[], offset: number) {
  if (points.length < 2 || offset === 0) return points;
  return points.map((point, index) => {
    const previous = points[Math.max(0, index - 1)];
    const next = points[Math.min(points.length - 1, index + 1)];
    const dx = next.x - previous.x;
    const dy = next.y - previous.y;
    const length = Math.hypot(dx, dy);
    if (length <= 0) return point;
    return {
      x: point.x + (-dy / length) * offset,
      y: point.y + (dx / length) * offset
    };
  });
}

function deterministicNoise(index: number, seed: number) {
  const value = Math.sin((index + 1) * 12.9898 + seed * 78.233) * 43758.5453;
  return (value - Math.floor(value)) * 2 - 1;
}

function curveProfileDataset(challenge: Challenge) {
  try {
    return JSON.stringify(challenge.parameters?.curve_profile || {});
  } catch {
    return "{}";
  }
}

function curveEndpointStyle(challenge: Challenge, side: "left" | "right", value: number) {
  void challenge;
  void side;
  void value;
  return { display: "none" };
}

function curveTipText(status: string) {
  if (status === "验证失败，请重试") return "验证失败，请重新尝试!";
  return "";
}

function jigsawCols(challenge: Challenge) {
  return Math.max(1, Math.round(numberParam(challenge, "tile_cols", 4)));
}

function jigsawRows(challenge: Challenge) {
  return Math.max(1, Math.round(numberParam(challenge, "tile_rows", 4)));
}

function initialJigsawTiles(challenge: Challenge) {
  const count = jigsawCols(challenge) * jigsawRows(challenge);
  return Array.from({ length: count }, (_, index) => index);
}

function jigsawTileIndexFromPoint(challenge: Challenge, point: ChallengePoint) {
  const cols = jigsawCols(challenge);
  const rows = jigsawRows(challenge);
  if (challenge.view.width <= 0 || challenge.view.height <= 0) return -1;
  const col = Math.floor(clamp(point.x, 0, challenge.view.width - 1) / (challenge.view.width / cols));
  const row = Math.floor(clamp(point.y, 0, challenge.view.height - 1) / (challenge.view.height / rows));
  return clamp(row, 0, rows - 1) * cols + clamp(col, 0, cols - 1);
}

function jigsawTileCenterPoint(challenge: Challenge, tileIndex: number) {
  const cols = jigsawCols(challenge);
  const rows = jigsawRows(challenge);
  const safeIndex = clamp(tileIndex, 0, cols * rows - 1);
  const col = safeIndex % cols;
  const row = Math.floor(safeIndex / cols);
  return {
    x: Math.round((col + 0.5) * (challenge.view.width / cols)),
    y: Math.round((row + 0.5) * (challenge.view.height / rows))
  };
}

function isJigsawTileSelected(challenge: Challenge, cellIndex: number, points: ChallengePoint[]) {
  return points.some((point) => jigsawTileIndexFromPoint(challenge, point) === cellIndex);
}

const jigsawImageCache = new Map<string, Promise<HTMLImageElement>>();

async function drawJigsawCanvas(canvas: HTMLCanvasElement | null, challenge: Challenge, tiles: number[], points: ChallengePoint[]) {
  if (!canvas || !challenge.image) return;
  const width = Math.max(1, Math.round(challenge.view.width));
  const height = Math.max(1, Math.round(challenge.view.height));
  const cols = jigsawCols(challenge);
  const rows = jigsawRows(challenge);
  const total = cols * rows;
  const order = tiles.length === total ? tiles : initialJigsawTiles(challenge);
  const selectedTiles = points
    .map((point) => jigsawTileIndexFromPoint(challenge, point))
    .filter((index) => index >= 0 && index < total);
  const renderKey = `${challenge.image}:${order.join(",")}:${selectedTiles.join(",")}`;

  canvas.dataset.jigsawRenderKey = renderKey;
  if (canvas.width !== width) canvas.width = width;
  if (canvas.height !== height) canvas.height = height;

  const context = canvas.getContext("2d");
  if (!context) return;
  context.clearRect(0, 0, width, height);

  let image: HTMLImageElement;
  try {
    image = await loadJigsawImage(challenge.image);
  } catch {
    return;
  }
  if (!canvas.isConnected || canvas.dataset.jigsawRenderKey !== renderKey) return;

  context.clearRect(0, 0, width, height);
  context.imageSmoothingEnabled = true;
  context.imageSmoothingQuality = "high";
  if (isIdentityOrder(order)) {
    context.drawImage(image, 0, 0, width, height);
  } else {
    drawJigsawTiles(context, image, width, height, cols, rows, order);
  }
  drawJigsawGrid(context, width, height, cols, rows);
  selectedTiles.forEach((tileIndex) => drawJigsawSelection(context, challenge, tileIndex));
}

function loadJigsawImage(src: string) {
  const cached = jigsawImageCache.get(src);
  if (cached) return cached;
  const promise = new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.decoding = "async";
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("JIGSAW_IMAGE_LOAD_FAILED"));
    image.src = src;
  });
  jigsawImageCache.set(src, promise);
  return promise;
}

function isIdentityOrder(order: number[]) {
  return order.every((sourceIndex, cellIndex) => sourceIndex === cellIndex);
}

function drawJigsawTiles(
  context: CanvasRenderingContext2D,
  image: HTMLImageElement,
  width: number,
  height: number,
  cols: number,
  rows: number,
  order: number[]
) {
  const total = cols * rows;
  order.forEach((sourceIndex, cellIndex) => {
    const safeSourceIndex = clamp(Math.round(sourceIndex), 0, total - 1);
    const sourceCol = safeSourceIndex % cols;
    const sourceRow = Math.floor(safeSourceIndex / cols);
    const targetCol = cellIndex % cols;
    const targetRow = Math.floor(cellIndex / cols);
    const sx0 = Math.round((sourceCol * image.naturalWidth) / cols);
    const sx1 = Math.round(((sourceCol + 1) * image.naturalWidth) / cols);
    const sy0 = Math.round((sourceRow * image.naturalHeight) / rows);
    const sy1 = Math.round(((sourceRow + 1) * image.naturalHeight) / rows);
    const dx0 = Math.round((targetCol * width) / cols);
    const dx1 = Math.round(((targetCol + 1) * width) / cols);
    const dy0 = Math.round((targetRow * height) / rows);
    const dy1 = Math.round(((targetRow + 1) * height) / rows);
    context.drawImage(image, sx0, sy0, sx1 - sx0, sy1 - sy0, dx0, dy0, dx1 - dx0, dy1 - dy0);
  });
}

function drawJigsawGrid(context: CanvasRenderingContext2D, width: number, height: number, cols: number, rows: number) {
  context.save();
  context.lineWidth = 1;
  context.strokeStyle = "rgba(148, 163, 184, 0.9)";
  context.beginPath();
  for (let col = 1; col < cols; col += 1) {
    const x = Math.round((col * width) / cols) + 0.5;
    context.moveTo(x, 0);
    context.lineTo(x, height);
  }
  for (let row = 1; row < rows; row += 1) {
    const y = Math.round((row * height) / rows) + 0.5;
    context.moveTo(0, y);
    context.lineTo(width, y);
  }
  context.stroke();
  context.strokeStyle = "rgba(255, 255, 255, 0.82)";
  context.strokeRect(0.5, 0.5, width - 1, height - 1);
  context.restore();
}

function drawJigsawSelection(context: CanvasRenderingContext2D, challenge: Challenge, tileIndex: number) {
  const cols = jigsawCols(challenge);
  const rows = jigsawRows(challenge);
  const col = tileIndex % cols;
  const row = Math.floor(tileIndex / cols);
  const x = Math.round((col * challenge.view.width) / cols);
  const y = Math.round((row * challenge.view.height) / rows);
  const width = Math.round(((col + 1) * challenge.view.width) / cols) - x;
  const height = Math.round(((row + 1) * challenge.view.height) / rows) - y;
  context.save();
  context.fillStyle = "rgba(37, 99, 235, 0.1)";
  context.strokeStyle = "#2563eb";
  context.lineWidth = 3;
  context.fillRect(x, y, width, height);
  context.strokeRect(x + 1.5, y + 1.5, Math.max(0, width - 3), Math.max(0, height - 3));
  context.restore();
}

function stringParam(challenge: Challenge, name: keyof ChallengeParameters, fallback: string) {
  const value = challenge.parameters?.[name];
  return typeof value === "string" ? value : fallback;
}

function percent(value: number, total: number) {
  if (!Number.isFinite(value) || !Number.isFinite(total) || total <= 0) return "0%";
  return `${(value / total) * 100}%`;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function snapValue(value: number, min: number, max: number, step: number) {
  const snapped = min + Math.round((value - min) / step) * step;
  return clamp(snapped, min, max);
}

function trySetPointerCapture(element: HTMLDivElement, pointerId: number) {
  try {
    element.setPointerCapture?.(pointerId);
  } catch {
    // Synthetic pointer events used by tests do not always create an active pointer.
  }
}

function tryReleasePointerCapture(element: HTMLDivElement, pointerId: number) {
  try {
    if (!element.hasPointerCapture || element.hasPointerCapture(pointerId)) {
      element.releasePointerCapture?.(pointerId);
    }
  } catch {
    // Ignore stale pointer capture state; the verification gesture can still complete.
  }
}

function challengePointFromEvent(event: MouseEvent | PointerEvent, challenge: Challenge, element: HTMLDivElement) {
  const rect = element.getBoundingClientRect();
  return {
    x: Math.round(clamp((event.clientX - rect.left) / rect.width, 0, 1) * challenge.view.width),
    y: Math.round(clamp((event.clientY - rect.top) / rect.height, 0, 1) * challenge.view.height)
  };
}

function buildAnswer(challenge: Challenge, value: number, points: ChallengePoint[], jigsawTiles: number[] = []): VerifyAnswerPayload {
  if (challenge.type === "ROTATE" || challenge.type === "ROTATE_DEGREE") return { angle: value };
  if (isCurveCaptcha(challenge)) return { x: value };
  if (challenge.type === "CONCAT") return { offset: value };
  if (isJigsawCaptcha(challenge)) return { tile_order: normalizedJigsawTiles(challenge, jigsawTiles) };
  if (isPathCaptcha(challenge)) return { points };
  if (isClickCaptcha(challenge)) return { points };
  return { x: value };
}

function footerStatus(challenge: Challenge, ticket: string, status: string, pointCount: number) {
  const visibleStatus = visibleRuntimeStatus(status);
  if (ticket) return visibleStatus;
  if (visibleStatus) return visibleStatus;
  if (isGridImageClickCaptcha(challenge) && pointCount > 0) {
    return `已选择 ${pointCount}`;
  }
  if (isClickCaptcha(challenge) && pointCount > 0) {
    return `已选择 ${pointCount}/${clickTargetCount(challenge)}`;
  }
  return "";
}

function visibleRuntimeStatus(status: string) {
  if (status === "验证中" || status === "验证通过") return "";
  return status;
}

function clickTargetCount(challenge: Challenge) {
  return Math.max(1, challenge.words?.length || 3);
}

function clickCancelRadius(challenge: Challenge) {
  return Math.max(14, Math.min(challenge.view.width, challenge.view.height) * 0.055);
}

function manualVerifyDisabled(challenge: Challenge, status: string, ticket: string, pointCount: number, value: number, jigsawTiles: number[] = []) {
  if (status === "验证中" || Boolean(ticket)) return true;
  if (isJigsawCaptcha(challenge)) return !jigsawTilesChanged(challenge, jigsawTiles);
  if (usesDragControl(challenge)) return value <= rangeBounds(challenge).min;
  if (isGridImageClickCaptcha(challenge)) return pointCount < 1;
  if (isClickCaptcha(challenge)) return pointCount < clickTargetCount(challenge);
  if (isPathCaptcha(challenge)) return pointCount < 4;
  return false;
}

function gridTileCount(challenge: Challenge) {
  return jigsawCols(challenge) * jigsawRows(challenge);
}

function normalizedJigsawTiles(challenge: Challenge, tiles: number[]) {
  const count = jigsawCols(challenge) * jigsawRows(challenge);
  if (tiles.length !== count) return initialJigsawTiles(challenge);
  return tiles.map((tile) => Math.round(tile));
}

function jigsawTilesChanged(challenge: Challenge, tiles: number[]) {
  const normalized = normalizedJigsawTiles(challenge, tiles);
  return normalized.some((tile, index) => tile !== index);
}

function concatPieceShift(challenge: Challenge) {
  return Math.max(0, numberParam(challenge, "piece_width", challenge.view.width) - challenge.view.width);
}

function shouldAutoVerifyOnRelease(challenge: Challenge, value: number) {
  return usesDragControl(challenge) && value > rangeBounds(challenge).min;
}

function usesDragControl(challenge: Challenge) {
  return challenge.type === "SLIDER" || challenge.type === "SLIDER_V2" || isCurveCaptcha(challenge) || challenge.type === "ROTATE" || challenge.type === "CONCAT" || challenge.type === "ROTATE_DEGREE";
}

function usesBoardDragControl(challenge: Challenge) {
  return isSliderCaptcha(challenge) || challenge.type === "ROTATE" || challenge.type === "ROTATE_DEGREE";
}

function isSliderCaptcha(challenge: Challenge) {
  return challenge.type === "SLIDER" || challenge.type === "SLIDER_V2";
}

function isClickCaptcha(challenge: Challenge) {
  return challenge.type === "WORD_IMAGE_CLICK" || challenge.type === "IMAGE_CLICK" || challenge.type === "JIGSAW" || challenge.type === "GRID_IMAGE_CLICK";
}

function isJigsawCaptcha(challenge: Challenge) {
  return challenge.type === "JIGSAW";
}

function isGridImageClickCaptcha(challenge: Challenge) {
  return challenge.type === "GRID_IMAGE_CLICK";
}

function isPathCaptcha(challenge: Challenge) {
  return challenge.type === "GESTURE";
}

function isCurveCaptcha(challenge: Challenge) {
  return challenge.type === "CURVE" || challenge.type === "CURVE_V2" || challenge.type === "CURVE_V3";
}

function ensureTrack(track: TrackPoint[], value: number): TrackPoint[] {
  if (track.length >= 3) return track;
  return [
    { x: 0, y: 20, t: 0, type: "start" },
    { x: Math.max(8, Math.round(value / 2)), y: 22, t: 190, type: "move" },
    { x: value, y: 20, t: 420, type: "end" }
  ];
}

function normalizeInputDeviceHint(value: string): InputDeviceHint {
  const normalized = value.trim().toLowerCase();
  if (normalized === "mouse") return "mouse";
  if (normalized === "trackpad" || normalized === "touchpad" || normalized === "pad") return "trackpad";
  if (normalized === "touch" || normalized === "touchscreen" || normalized === "screen") return "touch";
  return "unknown";
}

function normalizeSampleSource(value: string) {
  const normalized = normalizeScenePart(value);
  return normalized || "human-demo";
}

function normalizeScenePart(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

function pointerTypeFromEvent(event: PointerEvent): PointerInputType {
  const value = String(event.pointerType || "").toLowerCase();
  if (value === "mouse" || value === "touch") return value;
  return "unknown";
}

function createInputMetaState(inputDeviceHint: InputDeviceHint): InputMetaState {
  return {
    inputDeviceHint,
    primaryPointerType: "unknown",
    lastPointerType: "unknown",
    pointerCounts: { mouse: 0, touch: 0, keyboard: 0, unknown: 0 },
    keyboardUsed: false,
    touchCapable: navigator.maxTouchPoints > 0,
    coarsePointer: mediaMatches("(pointer: coarse)"),
    hoverCapable: mediaMatches("(hover: hover)"),
    maxTouchPoints: clamp(navigator.maxTouchPoints || 0, 0, 16)
  };
}

function runtimeInputMeta(state: InputMetaState) {
  return {
    input_device_hint: state.inputDeviceHint,
    input_device_inferred: inferredInputDevice(state),
    pointer_type: state.primaryPointerType,
    last_pointer_type: state.lastPointerType,
    pointer_counts: { ...state.pointerCounts },
    keyboard_used: state.keyboardUsed,
    touch_capable: state.touchCapable,
    coarse_pointer: state.coarsePointer,
    hover_capable: state.hoverCapable,
    max_touch_points: state.maxTouchPoints
  };
}

function inferredInputDevice(state: InputMetaState) {
  if (state.inputDeviceHint !== "unknown") return state.inputDeviceHint;
  if (state.primaryPointerType === "touch") return "touch";
  if (state.primaryPointerType === "mouse") return "mouse_like";
  if (state.keyboardUsed) return "keyboard";
  return "unknown";
}

function mediaMatches(query: string) {
  try {
    return window.matchMedia?.(query).matches || false;
  } catch {
    return false;
  }
}

function appendPathPointTo(points: ChallengePoint[], point: ChallengePoint) {
  const last = points[points.length - 1];
  if (last && Math.hypot(last.x - point.x, last.y - point.y) < 4) return points;
  return [...points, point].slice(-160);
}

function distanceBetweenPoints(a: ChallengePoint, b: ChallengePoint) {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) throw new Error(response.statusText);
  return response.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(response.statusText);
  return response.json();
}

async function postWithHeaders<T>(path: string, body: unknown, headers: Record<string, string>): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(response.statusText);
  return response.json();
}

render(<App />, document.getElementById("app")!);

function sessionIDFromPath() {
  const match = appPathname().match(/\/challenge\/([^/?#]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

function normalizeAppBasePath(value: string) {
  const raw = (value || "/").trim();
  if (!raw || raw === ".") return "/";
  const withSlashes = `/${raw.replace(/^\/+|\/+$/g, "")}/`;
  return withSlashes === "//" ? "/" : withSlashes;
}

function appPathname() {
  const current = window.location.pathname || "/";
  if (appBasePath !== "/" && current.startsWith(appBasePath)) {
    const next = current.slice(appBasePath.length - 1) || "/";
    return normalizeRoutePath(next);
  }
  return normalizeRoutePath(current);
}

function normalizeRoutePath(path: string) {
  const next = path.startsWith("/") ? path : `/${path}`;
  return next.length > 1 ? next.replace(/\/+$/g, "") : next;
}

function appURL(path: string, params?: URLSearchParams) {
  const base = appBasePath.endsWith("/") ? appBasePath : `${appBasePath}/`;
  const cleanPath = path.replace(/^\/+/, "");
  const url = `${base}${cleanPath}`;
  const query = params?.toString();
  return query ? `${url}?${query}` : url;
}

function redirectIfTopLevel(returnUrl: string, ticket: string, sessionId: string, route: string, requestNonce: string) {
  if (!returnUrl || window.parent !== window) return;
  const next = buildReturnURL(returnUrl, ticket, sessionId, route, requestNonce);
  if (next) window.location.assign(next);
}

function buildReturnURL(returnUrl: string, ticket: string, sessionId: string, route: string, requestNonce: string) {
  try {
    const url = new URL(returnUrl, window.location.href);
    if (url.protocol !== "http:" && url.protocol !== "https:") return "";
    url.searchParams.set("captcha_ticket", ticket);
    url.searchParams.set("captcha_session_id", sessionId);
    if (route) url.searchParams.set("captcha_route", route);
    if (requestNonce) url.searchParams.set("captcha_request_nonce", requestNonce);
    return url.toString();
  } catch {
    return "";
  }
}
