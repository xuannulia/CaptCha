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
  session_id: string;
  client_id: string;
  scene: string;
  expire_at?: string;
  route?: string;
  request_nonce?: string;
  resource_tag?: string;
  return_url?: string;
  challenge: Challenge;
};

type RefreshResponse = {
  session_id: string;
  expire_at: string;
  route?: string;
  request_nonce?: string;
  resource_tag?: string;
  return_url?: string;
  challenge: Challenge;
};

type VerifyResponse = {
  ok?: boolean;
  decision?: string;
  reason_code?: string;
  can_refresh?: boolean;
  captcha_type?: string;
  ticket?: string;
  route?: string;
  request_nonce?: string;
  resource_tag?: string;
  return_url?: string;
};

type TrackPoint = {
  x: number;
  y: number;
  t: number;
  type: "start" | "move" | "end";
};

const apiBase = import.meta.env.VITE_API_BASE || "http://localhost:8080";
const refreshIconURL = "/refresh.svg";
const closeIconURL = "/close.svg";
const sliderLeadWidth = 52;
const sliderThumbWidth = 52;

function App() {
  if (window.location.pathname === "/demo") {
    return <DemoPage />;
  }
  return <RuntimeChallenge />;
}

function RuntimeHeaderActions({ onRefresh, onClose }: { onRefresh: () => void; onClose: () => void }) {
  return (
    <div class="runtime-header-actions">
      <button type="button" class="icon-button" onClick={onRefresh} aria-label="刷新验证码" title="刷新">
        <img src={refreshIconURL} alt="" aria-hidden="true" />
      </button>
      <button type="button" class="icon-button" onClick={onClose} aria-label="关闭验证码" title="关闭">
        <img src={closeIconURL} alt="" aria-hidden="true" />
      </button>
    </div>
  );
}

function DemoPage() {
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
    { type: "ROTATE_DEGREE", label: "角度刻度", scene: "pay" },
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
  const activeItem = captchaTypes.find((item) => item.type === active) || captchaTypes[0];
  const src = challengeFrameURL(activeItem.type, activeItem.scene, nonce);

  useEffect(() => {
    document.title = "CaptCha Demo";
  }, []);

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      if (event.origin !== window.location.origin) return;
      const data = event.data as { type?: string; ticket?: string; captchaType?: string };
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
      }
      if (data?.type === "CAPTCHA_FAILURE") {
        setStatus("失败");
        setLastTicket("");
        setElapsed(Math.max(1, Math.round(performance.now() - startedAt.current)));
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
    setActive(nextType);
    setNonce(newNonce());
    setStatus("待验证");
    setLastTicket("");
    setElapsed(0);
    setActualType("");
    setFrameOpen(true);
    startedAt.current = performance.now();
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
  const initialSessionId = useMemo(() => params.get("session_id") || sessionIDFromPath(), [params]);
  const [sessionId, setSessionId] = useState(initialSessionId);
  const [route, setRoute] = useState(params.get("route") || "");
  const [requestNonce, setRequestNonce] = useState(params.get("request_nonce") || "");
  const [resourceTag, setResourceTag] = useState(params.get("resource_tag") || "");
  const [returnUrl, setReturnUrl] = useState(params.get("return_url") || "");
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [status, setStatus] = useState("加载中");
  const [ticket, setTicket] = useState("");
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
  const valueRef = useRef(0);
  const pointsRef = useRef<ChallengePoint[]>([]);
  const trackRef = useRef<TrackPoint[]>([]);
  const jigsawTilesRef = useRef<number[]>([]);
  const ticketRef = useRef("");
  const boardRef = useRef<HTMLDivElement>(null);
  const controlRef = useRef<HTMLDivElement>(null);
  const curveBgCanvasRef = useRef<HTMLCanvasElement>(null);
  const curveMoveCanvasRef = useRef<HTMLCanvasElement>(null);
  const sliderBounds = challenge ? rangeBounds(challenge) : { min: 0, max: 360, step: 1 };
  const sliderRatio = sliderRatioFromValue(value, sliderBounds);
  const sliderFillWidth = sliderFillWidthStyle(sliderRatio);
  const sliderThumbLeft = sliderThumbLeftStyle(sliderRatio);

  useEffect(() => {
    void bootstrap();
  }, []);

  useEffect(() => {
    if (!challenge || !isCurveCaptcha(challenge) || !curveBgCanvasRef.current || !curveMoveCanvasRef.current) return;
    drawCurveCanvases(curveBgCanvasRef.current, curveMoveCanvasRef.current, challenge, value);
  }, [challenge, value]);

  async function bootstrap() {
    try {
      let id = sessionId;
      if (!id) {
        const created = await post<SessionResponse>("/api/v1/challenge/sessions", {
          client_id: params.get("client_id") || "demo",
          scene: params.get("scene") || "login",
          captcha_type: params.get("captcha_type") || "AUTO",
          route,
          return_url: returnUrl,
          request_nonce: requestNonce,
          resource_tag: resourceTag
        });
        id = created.session_id;
        setSessionId(id);
        applySessionContext(created);
      }
      await loadChallenge(id);
    } catch {
      setStatus("加载失败");
    }
  }

  async function loadChallenge(id: string) {
    const loaded = await get<ChallengeResponse>(`/api/v1/challenge/sessions/${id}`);
    applySessionContext(loaded);
    resetChallenge(loaded.challenge);
  }

  async function refresh() {
    if (!sessionId) {
      await bootstrap();
      return;
    }
    setStatus("刷新中");
    try {
      const refreshed = await post<RefreshResponse>(`/api/v1/challenge/sessions/${sessionId}/refresh`, {});
      applySessionContext(refreshed);
      resetChallenge(refreshed.challenge);
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

  function resetChallenge(next: Challenge) {
    setChallenge(next);
    setStatus("");
    setTicket("");
    setPoints([]);
    setTrack([]);
    setValue(0);
    ticketRef.current = "";
    pointsRef.current = [];
    trackRef.current = [];
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
    window.parent?.postMessage({ type: "CAPTCHA_READY", captchaType: next.type, prompt: next.prompt, sessionId, route, requestNonce }, "*");
  }

  function applySessionContext(context: { route?: string; request_nonce?: string; resource_tag?: string; return_url?: string }) {
    if (context.route) setRoute(context.route);
    if (context.request_nonce) setRequestNonce(context.request_nonce);
    if (context.resource_tag) setResourceTag(context.resource_tag);
    if (context.return_url) setReturnUrl(context.return_url);
  }

  async function verify(snapshot?: { value?: number; points?: ChallengePoint[]; track?: TrackPoint[] }) {
    if (!challenge || !sessionId) return;
    if (verifyInFlight.current || ticketRef.current) return;
    verifyInFlight.current = true;
    setStatus("验证中");
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
        request_nonce: requestNonce
      }
    };
    try {
      const result = await post<VerifyResponse>(`/api/v1/challenge/sessions/${sessionId}/verify`, payload);
      if (result.ok) {
        const issued = String(result.ticket || "");
        const successRoute = result.route || route;
        const successRequestNonce = result.request_nonce || requestNonce;
        const successReturnUrl = result.return_url || returnUrl;
        setTicket(issued);
        ticketRef.current = issued;
        setStatus("验证通过");
        window.parent?.postMessage({ type: "CAPTCHA_SUCCESS", ticket: issued, sessionId, route: successRoute, requestNonce: successRequestNonce, returnUrl: successReturnUrl }, "*");
        redirectIfTopLevel(successReturnUrl, issued, sessionId, successRoute, successRequestNonce);
      } else {
        await refreshAfterFailedVerify(
          result.reason_code || "VERIFY_FAILED",
          result.decision === "challenge_harder" ? "验证升级中" : "验证失败，正在刷新"
        );
      }
    } catch {
      await refreshAfterFailedVerify("NETWORK_ERROR", "验证失败，正在刷新");
    } finally {
      verifyInFlight.current = false;
    }
  }

  async function refreshAfterFailedVerify(reason: string, nextStatus: string) {
    setStatus(nextStatus);
    notifyParentFailure(reason);
    await refresh();
  }

  function onPointer(type: TrackPoint["type"], event: PointerEvent) {
    if (!challenge || !boardRef.current) return;
    const point = challengePointFromEvent(event, challenge, boardRef.current);
    appendTrack(type, point.x, point.y);
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
      appendTrack("start", point.x, point.y);
      return;
    }
    if (usesBoardDragControl(challenge)) {
      event.preventDefault();
      boardRangeTracking.current = true;
      trySetPointerCapture(event.currentTarget as HTMLDivElement, event.pointerId);
      updateValueFromBoard(event, "start");
      return;
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
      appendTrack("move", point.x, point.y);
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
    const nextTrack = appendTrack(type, point.x, point.y);
    const nextPoints = appendPathPoint(point, reset);
    return { points: nextPoints, track: nextTrack, value: valueRef.current };
  }

  function handleJigsawPointerUp(event: PointerEvent) {
    if (!challenge || !boardRef.current || !jigsawDragStart.current) return undefined;
    const start = jigsawDragStart.current;
    const end = challengePointFromEvent(event, challenge, boardRef.current);
    jigsawDragStart.current = null;
    suppressNextBoardClick.current = true;
    const nextTrack = appendTrack("end", end.x, end.y);
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
    const travelWidth = Math.max(1, rect.width - sliderLeadWidth - sliderThumbWidth);
    const ratio = clamp((event.clientX - rect.left - sliderLeadWidth - thumbOffset) / travelWidth, 0, 1);
    const raw = bounds.min + ratio * (bounds.max - bounds.min);
    const next = snapValue(raw, bounds.min, bounds.max, bounds.step);
    const trackY = Math.round(clamp(event.clientY - rect.top, 0, rect.height));
    setCurrentValue(next);
    const nextTrack = appendTrack(type, next, trackY);
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
    const nextTrack = appendTrack(type, next, Math.round(point.y));
    return { value: next, track: nextTrack };
  }

  function onControlPointerDown(event: PointerEvent) {
    if (interactionLocked()) return;
    event.preventDefault();
    rangeTracking.current = true;
    if (challenge) {
      controlDragStart.current = controlThumbDragStart(event, challenge, valueRef.current);
    }
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
      appendTrack("move", snapped, 0);
    }
  }

  function appendTrack(type: TrackPoint["type"], x: number, y: number) {
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

  function onBoardClick(event: MouseEvent) {
    if (!challenge || !isClickCaptcha(challenge)) return;
    if (interactionLocked()) return;
    if (!boardRef.current) return;
    if (suppressNextBoardClick.current) {
      suppressNextBoardClick.current = false;
      return;
    }
    if (isJigsawCaptcha(challenge)) return;
    const point = challengePointFromEvent(event, challenge, boardRef.current);
    const nextTrack = appendTrack("end", point.x, point.y);
    toggleClickPoint(point, nextTrack);
  }

  function interactionLocked() {
    return verifyInFlight.current || Boolean(ticketRef.current);
  }

  function notifyParentFailure(reason: string) {
    window.parent?.postMessage({ type: "CAPTCHA_FAILURE", sessionId, route, requestNonce, reason }, "*");
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

  const verifyDisabled = !challenge || manualVerifyDisabled(challenge, status, ticket, points.length, value, jigsawTiles);
  return (
    <main class="shell">
      <section class="panel">
        {(!challenge || !isCurveCaptcha(challenge)) && (
          <header>
            <strong>{challenge?.prompt || "人机验证"}</strong>
            <RuntimeHeaderActions onRefresh={refresh} onClose={closeCaptcha} />
          </header>
        )}

        {challenge && isCurveCaptcha(challenge) && (
          <div id="tianai-captcha" class="tianai-captcha-slider runtime-curve-captcha" style={{ transform: "translateX(0px)" }}>
            <div class="slider-tip">
              <span id="tianai-captcha-slider-move-track-font">{challenge.prompt}</span>
              <RuntimeHeaderActions onRefresh={refresh} onClose={closeCaptcha} />
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
                <span class="drag-track-text">请向右滑动滑块</span>
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
            {challenge.image && (
              <img
                class={challenge.type === "ROTATE" ? "rotating-image" : ""}
                src={challenge.image}
                alt=""
                draggable={false}
                style={challenge.type === "ROTATE" ? { transform: `rotate(${value}deg)` } : undefined}
              />
            )}
            {isJigsawCaptcha(challenge) && challenge.image && jigsawTiles.length > 0 && (
              <div
                class="jigsaw-tiles"
                style={{
                  gridTemplateColumns: `repeat(${jigsawCols(challenge)}, 1fr)`,
                  gridTemplateRows: `repeat(${jigsawRows(challenge)}, 1fr)`
                }}
              >
                {jigsawTiles.map((sourceIndex, cellIndex) => (
                  <span
                    key={`${cellIndex}-${sourceIndex}`}
                    class={`jigsaw-tile ${isJigsawTileSelected(challenge, cellIndex, points) ? "selected" : ""}`}
                    style={jigsawTileStyle(challenge, sourceIndex)}
                  />
                ))}
              </div>
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
            <span class="drag-track-text">请向右滑动滑块</span>
            <span class="drag-thumb" style={{ left: sliderThumbLeft }} />
          </div>
        )}

        <footer>
          <span>{challenge ? footerStatus(challenge, ticket, status, points.length) : status}</span>
          {challenge && !usesDragControl(challenge) && (
            <button type="button" onClick={() => void verify()} disabled={verifyDisabled}>确认</button>
          )}
        </footer>
      </section>
    </main>
  );
}

function challengeFrameURL(type: CaptchaRequestType, scene: string, nonce: string) {
  const params = new URLSearchParams({
    client_id: "demo",
    scene,
    captcha_type: type,
    route: `/demo/${type.toLowerCase()}`,
    request_nonce: nonce
  });
  return `/?${params.toString()}`;
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
  return { offset: nearThumb ? relativeX - thumbLeft : thumbWidth / 2 };
}

function sliderRatioFromValue(value: number, bounds: { min: number; max: number }) {
  return clamp((value - bounds.min) / Math.max(1, bounds.max - bounds.min), 0, 1);
}

function sliderThumbLeftPx(ratio: number, width: number) {
  return sliderLeadWidth + ratio * Math.max(1, width - sliderLeadWidth - sliderThumbWidth);
}

function sliderThumbLeftStyle(ratio: number) {
  const percentValue = ratio * 100;
  const pixelOffset = sliderLeadWidth - ratio * (sliderLeadWidth + sliderThumbWidth);
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

function jigsawTileStyle(challenge: Challenge, sourceIndex: number) {
  const cols = jigsawCols(challenge);
  const rows = jigsawRows(challenge);
  const sourceCol = sourceIndex % cols;
  const sourceRow = Math.floor(sourceIndex / cols);
  const x = cols <= 1 ? 0 : (sourceCol / (cols - 1)) * 100;
  const y = rows <= 1 ? 0 : (sourceRow / (rows - 1)) * 100;
  return {
    backgroundImage: `url("${challenge.image || ""}")`,
    backgroundPosition: `${x}% ${y}%`,
    backgroundSize: `${cols * 100}% ${rows * 100}%`
  };
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
  if (ticket) return status || "";
  if (status) return status;
  if (isClickCaptcha(challenge) && pointCount > 0) {
    return `已选择 ${pointCount}/${clickTargetCount(challenge)}`;
  }
  return "";
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
  if (isClickCaptcha(challenge)) return pointCount < clickTargetCount(challenge);
  if (isPathCaptcha(challenge)) return pointCount < 4;
  return false;
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
  return challenge.type === "SLIDER" || challenge.type === "SLIDER_V2" || challenge.type === "ROTATE" || challenge.type === "ROTATE_DEGREE";
}

function isClickCaptcha(challenge: Challenge) {
  return challenge.type === "WORD_IMAGE_CLICK" || challenge.type === "IMAGE_CLICK" || challenge.type === "JIGSAW" || challenge.type === "GRID_IMAGE_CLICK";
}

function isJigsawCaptcha(challenge: Challenge) {
  return challenge.type === "JIGSAW";
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

render(<App />, document.getElementById("app")!);

function sessionIDFromPath() {
  const match = window.location.pathname.match(/\/challenge\/([^/?#]+)/);
  return match ? decodeURIComponent(match[1]) : "";
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
