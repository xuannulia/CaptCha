import {
  ApiOutlined,
  AuditOutlined,
  BarChartOutlined,
  DatabaseOutlined,
  ExperimentOutlined,
  PlusOutlined,
  ProjectOutlined,
  SafetyOutlined
} from "@ant-design/icons";
import { QueryClient, QueryClientProvider, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Card, Checkbox, ConfigProvider, Form, Input, InputNumber, Layout, Menu, message, Modal, Select, Space, Statistic, Switch, Table, Tag } from "antd";
import type { ColumnsType } from "antd/es/table";
import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes as RouterRoutes, useLocation, useNavigate } from "react-router-dom";
import "./style.css";

const queryClient = new QueryClient();
const apiBase = import.meta.env.VITE_API_BASE || "http://localhost:8080";
const adminToken = import.meta.env.VITE_ADMIN_TOKEN || "";

type RoutePolicy = {
  id: string;
  client_id: string;
  name: string;
  path_pattern: string;
  method: string;
  scene: string;
  challenge_type: string;
  risk_challenge_type?: string;
  challenge_escalation?: string[];
  mode: string;
  fail_policy: string;
  priority: number;
  enabled: boolean;
  rollout_percent: number;
  token_ttl_seconds: number;
  risk_challenge_score?: number;
  risk_block_score?: number;
  risk_observe_score?: number;
  rate_limit?: {
    window_seconds: number;
    max_requests: number;
    strategy?: string;
  };
  created_at?: string;
  updated_at?: string;
};

type IpPolicy = {
  id: string;
  client_id: string;
  type: string;
  cidr: string;
  action: string;
  reason: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
};

type Resource = {
  id: string;
  client_id: string;
  scene: string;
  resource_type: string;
  captcha_type: string;
  storage_type: string;
  uri: string;
  tag: string;
  checksum?: string;
  metadata?: Record<string, unknown>;
  status: string;
};

type ResourceFormValues = {
  client_id?: string;
  scene?: string;
  tag?: string;
  gallery_type?: "background" | "concatBackground" | "jigsawBackground" | "rotate" | "grid" | "icon";
  category?: string;
  label?: string;
  difficulty?: string;
};

type AuditEvent = {
  id: string;
  client_id: string;
  scene: string;
  route?: string;
  ip_hash?: string;
  account_id_hash?: string;
  device_id_hash?: string;
  action: string;
  result: string;
  decision_reason: string;
  challenge_type: string;
  created_at?: string;
};

type RiskFeatureSnapshot = {
  id: string;
  attempt_id: string;
  client_id: string;
  scene: string;
  challenge_type: string;
  label: string;
  model_trainable: boolean;
  feature_version: string;
};

type RiskModelVersion = {
  id: string;
  name: string;
  version: string;
  feature_version: string;
  training_window: string;
  artifact_uri: string;
  metrics?: Record<string, unknown>;
  mode: string;
  status: string;
  created_at: string;
  activated_at?: string;
};

type PolicyDecision = {
  action: string;
  reason: string;
  scene?: string;
  challenge_type?: string;
  ttl_seconds?: number;
};

type PolicySimulation = {
  dry_run: boolean;
  request: Record<string, unknown>;
  decision: PolicyDecision;
  route?: RoutePolicy;
  rate_limit_evaluated: boolean;
  side_effects: string[];
  notes?: string[];
};

type MetricCount = {
  name: string;
  count: number;
};

type ResourceHit = {
  id: string;
  resource_type?: string;
  captcha_type?: string;
  tag?: string;
  attempts: number;
  pass: number;
  retry: number;
  block: number;
  unknown: number;
  failure_rate: number;
};

type AdminMetrics = {
  generated_at: string;
  totals: {
    applications: number;
    active_applications: number;
    route_policies: number;
    enabled_route_policies: number;
    ip_policies: number;
    enabled_ip_policies: number;
    captcha_resources: number;
    active_captcha_resources: number;
    risk_feature_snapshots: number;
    trainable_risk_features: number;
    risk_model_versions: number;
    active_risk_model_versions: number;
  };
  recent: {
    audit_events: number;
    allow: number;
    challenge: number;
    block: number;
    observe: number;
    pass: number;
    retry: number;
    config_changes: number;
    training_feedback: number;
    pass_rate: number;
    block_rate: number;
  };
  by_challenge_type: Record<string, number>;
  resource_statuses: Record<string, number>;
  risk_labels: Record<string, number>;
  top_scenes: MetricCount[];
  top_reasons: MetricCount[];
  top_resources: ResourceHit[];
};

type Application = {
  id: string;
  client_id: string;
  name: string;
  has_secret: boolean;
  status: string;
  default_fail_policy: string;
  created_at?: string;
  updated_at?: string;
};

type SelectOption = {
  value: string;
  label: string;
};

type ApplicationScopeState = {
  applications?: Application[];
  appOptions: SelectOption[];
  scopeOptions: SelectOption[];
  selectedClientID: string;
  defaultClientID: string;
  setSelectedClientID: (value: string) => void;
};

const ApplicationScopeContext = React.createContext<ApplicationScopeState>({
  appOptions: [],
  scopeOptions: [{ value: "", label: "全部应用" }],
  selectedClientID: "",
  defaultClientID: "demo",
  setSelectedClientID: () => undefined
});

type ListResponse<T> = {
  items: T[];
  limit?: number;
  offset?: number;
  has_more?: boolean;
};

type PagedList<T> = {
  items: T[];
  limit: number;
  offset: number;
  has_more: boolean;
};

const captchaTypes = [
  "GESTURE",
  "CURVE",
  "CURVE_V2",
  "CURVE_V3",
  "SLIDER",
  "SLIDER_V2",
  "ROTATE",
  "CONCAT",
  "ROTATE_DEGREE",
  "WORD_IMAGE_CLICK",
  "IMAGE_CLICK",
  "JIGSAW",
  "GRID_IMAGE_CLICK"
];
const captchaLabels: Record<string, string> = {
  AUTO: "自动",
  GESTURE: "手势描绘",
  CURVE: "滑动曲线 V1",
  CURVE_V2: "滑动曲线 V2",
  CURVE_V3: "滑动曲线 V3",
  SLIDER: "滑块拼图",
  SLIDER_V2: "增强滑块拼图",
  ROTATE: "旋转矫正",
  CONCAT: "滑动还原",
  ROTATE_DEGREE: "角度指针",
  WORD_IMAGE_CLICK: "文字点选",
  IMAGE_CLICK: "图标点选",
  JIGSAW: "乱序拼图",
  GRID_IMAGE_CLICK: "图片格子"
};
const resourceTypeLabels: Record<string, string> = {
  background_image: "单张背景",
  background_library: "背景图库",
  concat_background_image: "滑动还原单张背景",
  concat_background_library: "滑动还原专用图库",
  jigsaw_background_image: "乱序拼图单张背景",
  jigsaw_background_library: "乱序拼图专用图库",
  rotate_library: "旋转校准图库",
  grid_category_library: "图片格子分类图库",
  slider_template: "滑块模板",
  rotate_template: "旋转模板",
  concat_template: "滑动还原模板",
  font: "字体",
  icon: "单个图标",
  icon_library: "图标图库",
  degree_template: "角度模板",
  curve_template: "曲线模板",
  gesture_template: "手势模板",
  jigsaw_template: "拼图模板"
};
const storageLabels: Record<string, string> = {
  embedded: "内置",
  classpath: "类路径",
  file: "本地文件",
  url: "URL",
  object_storage: "对象存储",
  database: "数据库"
};
const statusLabels: Record<string, string> = {
  active: "启用",
  disabled: "停用"
};
const policyModeLabels: Record<string, string> = {
  always: "总是验证",
  risk_based: "风险触发",
  rate_limit: "频率触发",
  observe: "观察",
  silent: "静默",
  manual_bypass: "人工放行"
};
const failPolicyLabels: Record<string, string> = {
  fail_open: "失败放行",
  fail_close: "失败拦截"
};
const ipPolicyTypeLabels: Record<string, string> = {
  allowlist: "白名单",
  blocklist: "黑名单"
};
const actionLabels: Record<string, string> = {
  allow: "放行",
  challenge: "验证",
  block: "拦截",
  observe: "观察"
};
const resultLabels: Record<string, string> = {
  allow: "放行",
  pass: "通过",
  retry: "重试",
  block: "拦截",
  config_changed: "配置变更",
  training_feedback: "训练反馈"
};
const riskLabelLabels: Record<string, string> = {
  unknown: "未标注",
  captcha_pass: "验证通过",
  captcha_retry: "验证重试",
  likely_human: "疑似真人",
  likely_bot: "疑似机器",
  confirmed_human: "真人样本",
  confirmed_bot: "机器样本"
};
const modelModeLabels: Record<string, string> = {
  shadow: "影子",
  observe: "观察",
  enforce: "生效"
};
const modelStatusLabels: Record<string, string> = {
  candidate: "候选",
  active: "启用",
  retired: "退役",
  rolled_back: "已回滚"
};
const rateStrategyLabels: Record<string, string> = {
  fixed_window: "固定窗口",
  sliding_window: "滚动窗口",
  token_bucket: "令牌桶"
};
const optionLabels = {
  ...captchaLabels,
  ...resourceTypeLabels,
  ...storageLabels,
  ...statusLabels,
  ...policyModeLabels,
  ...failPolicyLabels,
  ...ipPolicyTypeLabels,
  ...actionLabels,
  ...resultLabels,
  ...riskLabelLabels,
  ...modelModeLabels,
  ...modelStatusLabels,
  ...rateStrategyLabels
};
const resourceFileFilters = [
  { key: "all", label: "全部文件" },
  { key: "background", label: "背景图库" },
  { key: "concatBackground", label: "滑动还原专用图库" },
  { key: "jigsawBackground", label: "乱序拼图专用图库" },
  { key: "rotate", label: "旋转校准图库" },
  { key: "grid", label: "图片格子图库" },
  { key: "icon", label: "图标图库" }
];
const galleryUploadTypes = [
  { value: "background", label: "背景图库" },
  { value: "concatBackground", label: "滑动还原专用图库" },
  { value: "jigsawBackground", label: "乱序拼图专用图库" },
  { value: "rotate", label: "旋转校准图库" },
  { value: "grid", label: "图片格子图库" },
  { value: "icon", label: "图标图库" }
];
const resourceDifficultyOptions = [
  { value: "easy", label: "简单" },
  { value: "medium", label: "中等" },
  { value: "hard", label: "较难" }
];
const galleryUploadNotes: Record<string, string> = {
  background: "通用背景会用于滑块、点选、手势和曲线类验证码，避免主体过暗、过花或文字密集。",
  concatBackground: "滑动还原只使用本专用图库。素材需要横向连续结构，上下分片后仍能靠纹理自然对齐；避免纯色、重复条纹、文字密集和主体只在一侧的图片。",
  jigsawBackground: "乱序拼图只使用本专用图库。素材需要每个 2x2 / 3x3 切片都有局部特征；避免大面积纯色、重复格纹和主体集中在单个角落的图片。",
  rotate: "旋转校准适合中心主体明显、圆形裁切后仍容易辨认方向的图片。",
  grid: "图片格子图库需要按分类上传，同一分类应保持目标对象清晰且背景差异足够。",
  icon: "图标图库适合轮廓清晰、尺寸接近、含义明确的 SVG 或透明图片。"
};
const adminRoutes = [
  { key: "overview", path: "/overview", icon: <BarChartOutlined />, label: "概览", element: <Overview /> },
  { key: "applications", path: "/applications", icon: <ProjectOutlined />, label: "应用", element: <Applications /> },
  { key: "routes", path: "/routes", icon: <ApiOutlined />, label: "路由策略", element: <Routes /> },
  { key: "ip", path: "/ip-policies", icon: <SafetyOutlined />, label: "IP 策略", element: <IpPolicies /> },
  { key: "simulate", path: "/policy-simulate", icon: <SafetyOutlined />, label: "策略模拟", element: <PolicySimulator /> },
  { key: "resources", path: "/resources", icon: <DatabaseOutlined />, label: "资源", element: <Resources /> },
  { key: "audit", path: "/audit", icon: <AuditOutlined />, label: "审计", element: <Audit /> },
  { key: "features", path: "/risk-features", icon: <ExperimentOutlined />, label: "训练样本", element: <RiskFeatures /> },
  { key: "models", path: "/risk-models", icon: <ExperimentOutlined />, label: "模型管理", element: <RiskModels /> }
];

function App() {
  return (
    <ConfigProvider theme={{ token: { borderRadius: 6, colorPrimary: "#2563eb" } }}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AdminShell />
        </BrowserRouter>
      </QueryClientProvider>
    </ConfigProvider>
  );
}

function AdminShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const active = adminRoutes.find((route) => route.path === location.pathname)?.key || "overview";
  const { data: applications } = useList<Application>("applications", "/api/v1/admin/applications");
  const [selectedClientID, setSelectedClientID] = useState(() => localStorage.getItem("captcha-admin-client-id") || "");
  const appOptions = useMemo(() => applicationOptions(applications), [applications]);
  const scopeOptions = useMemo(() => [{ value: "", label: "全部应用" }, ...appOptions], [appOptions]);
  const defaultClientID = selectedClientID || firstApplicationClientID(applications);

  useEffect(() => {
    if (selectedClientID) {
      localStorage.setItem("captcha-admin-client-id", selectedClientID);
    } else {
      localStorage.removeItem("captcha-admin-client-id");
    }
  }, [selectedClientID]);

  useEffect(() => {
    if (!selectedClientID || !applications?.length) return;
    if (!applications.some((item) => item.client_id === selectedClientID)) {
      setSelectedClientID("");
    }
  }, [applications, selectedClientID]);

  const applicationScope = useMemo(() => ({
    applications,
    appOptions,
    scopeOptions,
    selectedClientID,
    defaultClientID,
    setSelectedClientID
  }), [applications, appOptions, scopeOptions, selectedClientID, defaultClientID]);

  return (
    <ApplicationScopeContext.Provider value={applicationScope}>
        <Layout className="app">
          <Layout.Sider width={224} theme="light" className="sider">
            <div className="brand">CaptCha</div>
            <Menu
              mode="inline"
              selectedKeys={[active]}
              onClick={(item) => navigate(adminRoutes.find((route) => route.key === item.key)?.path || "/overview")}
              items={adminRoutes.map(({ key, icon, label }) => ({ key, icon, label }))}
            />
          </Layout.Sider>
          <Layout>
            <Layout.Header className="header">
              <strong>{titleFor(active)}</strong>
              <Space className="header-actions">
                <Select
                  className="application-scope-select"
                  value={selectedClientID}
                  options={scopeOptions}
                  onChange={setSelectedClientID}
                  optionFilterProp="label"
                  showSearch
                />
                <span className="header-subtitle">管理控制台</span>
              </Space>
            </Layout.Header>
            <Layout.Content className="content">
              <RouterRoutes>
                <Route path="/" element={<Navigate to="/overview" replace />} />
                {adminRoutes.map((route) => <Route key={route.key} path={route.path} element={route.element} />)}
                <Route path="*" element={<Navigate to="/overview" replace />} />
              </RouterRoutes>
            </Layout.Content>
          </Layout>
        </Layout>
    </ApplicationScopeContext.Provider>
  );
}

function Overview() {
  const { selectedClientID } = useApplicationScope();
  const metricsPath = scopedPath("/api/v1/admin/metrics?limit=200", selectedClientID);
  const { data, isLoading, error } = useQuery({
    queryKey: ["metrics", selectedClientID],
    queryFn: async () => {
      const response = await fetch(`${apiBase}${metricsPath}`, { headers: adminHeaders() });
      if (!response.ok) throw new Error(response.statusText);
      return await response.json() as AdminMetrics;
    },
    refetchInterval: 15000
  });
  const totals = data?.totals;
  const recent = data?.recent;
  const topScenes = (data?.top_scenes || []).slice(0, 5);
  const topReasons = (data?.top_reasons || []).slice(0, 5);
  const topResources = (data?.top_resources || [])
    .filter((item) => item.attempts > 0)
    .slice(0, 5);
  const riskLabels = data?.risk_labels || {};

  return (
    <div className="overview-page">
      <div className="metric-grid">
        <Card loading={isLoading}><Statistic title="验证通过率" value={recent?.pass_rate ?? 0} suffix="%" precision={1} /></Card>
        <Card loading={isLoading}><Statistic title="验证请求" value={recent?.challenge ?? 0} /></Card>
        <Card loading={isLoading}><Statistic title="拦截请求" value={recent?.block ?? 0} /></Card>
        <Card loading={isLoading}><Statistic title="活跃资源" value={totals?.active_captcha_resources ?? 0} suffix={`/ ${totals?.captcha_resources ?? 0}`} /></Card>
      </div>
      {error instanceof Error && <Card><div className="error-line">{error.message}</div></Card>}
      <div className="overview-panels">
        <Card title="防护策略" loading={isLoading}>
          <div className="summary-list">
            <SummaryRow label="应用" value={ratioText(totals?.active_applications, totals?.applications)} />
            <SummaryRow label="路由策略" value={ratioText(totals?.enabled_route_policies, totals?.route_policies)} />
            <SummaryRow label="IP 策略" value={ratioText(totals?.enabled_ip_policies, totals?.ip_policies)} />
            <SummaryRow label="配置变更" value={String(recent?.config_changes ?? 0)} muted="近期" />
          </div>
        </Card>
        <Card title="资源健康" loading={isLoading}>
          <div className="summary-list">
            <SummaryRow label="启用素材" value={ratioText(totals?.active_captcha_resources, totals?.captcha_resources)} />
            {topResources.length === 0 ? (
              <div className="empty-line">暂无资源失败样本</div>
            ) : topResources.map((item) => (
              <SummaryRow
                key={item.id}
                label={compactText(item.id, 28)}
                value={`${item.failure_rate.toFixed(1)}%`}
                muted={`${item.attempts} 次`}
                danger={item.failure_rate >= 50}
              />
            ))}
          </div>
        </Card>
        <Card title="样本与模型" loading={isLoading}>
          <div className="summary-list">
            <SummaryRow label="入训样本" value={ratioText(totals?.trainable_risk_features, totals?.risk_feature_snapshots)} />
            <SummaryRow label="启用模型" value={ratioText(totals?.active_risk_model_versions, totals?.risk_model_versions)} />
            <SummaryRow label="真人样本" value={String(riskLabels.confirmed_human || 0)} />
            <SummaryRow label="机器样本" value={String(riskLabels.confirmed_bot || 0)} />
          </div>
        </Card>
        <Card title="业务场景" loading={isLoading}>
          <div className="summary-list">
            {topScenes.length === 0 && topReasons.length === 0 ? (
              <div className="empty-line">暂无近期流量</div>
            ) : (
              <>
                {topScenes.map((item) => <SummaryRow key={`scene-${item.name}`} label={item.name || "-"} value={String(item.count)} muted="场景" />)}
                {topReasons.map((item) => <SummaryRow key={`reason-${item.name}`} label={compactText(item.name, 24)} value={String(item.count)} muted="原因" />)}
              </>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

function SummaryRow({ label, value, muted, danger }: { label: string; value: string; muted?: string; danger?: boolean }) {
  return (
    <div className={danger ? "summary-row danger" : "summary-row"}>
      <span>{label}</span>
      <strong>{value}</strong>
      {muted && <em>{muted}</em>}
    </div>
  );
}

function Applications() {
  const { data, isLoading } = useList<Application>("applications", "/api/v1/admin/applications");
  const [open, setOpen] = useState(false);
  const [editingApplication, setEditingApplication] = useState<Application | null>(null);
  const [secret, setSecret] = useState<{ clientID: string; name: string; value: string } | null>(null);
  const [pendingApplicationID, setPendingApplicationID] = useState("");
  const [form] = Form.useForm();
  const mutation = usePost<Application>("applications");
  const statusMutation = usePost<Application>("applications");
  const secretMutation = usePost<{ client_secret: string; application: Application }>("applications");
  const rotateApplicationSecret = (row: Application) => {
    const hasSecret = Boolean(row.has_secret);
    Modal.confirm({
      title: hasSecret ? "轮换应用密钥" : "生成应用密钥",
      content: (
        <div className="confirm-copy">
          {hasSecret && <p>轮换后旧密钥会立即失效，后端、Gateway 或中间件需要同步替换为新密钥。</p>}
          {!hasSecret && <p>生成后，后端、Gateway 或中间件调用集成接口时需要携带这个应用密钥。</p>}
          <p>新密钥只会显示一次。</p>
        </div>
      ),
      okText: hasSecret ? "确认轮换" : "确认生成",
      cancelText: "取消",
      okButtonProps: { danger: true },
      onOk: async () => {
        setPendingApplicationID(row.id);
        try {
          const result = await secretMutation.mutateAsync({
            path: `/api/v1/admin/applications/${encodeURIComponent(row.client_id)}/secret`,
            body: {}
          });
          setSecret({ clientID: result.application.client_id, name: result.application.name, value: result.client_secret });
        } catch {
          message.error("密钥轮换失败");
        } finally {
          setPendingApplicationID("");
        }
      }
    });
  };
  const columns: ColumnsType<Application> = [
    {
      title: "应用",
      render: (_, row) => (
        <div className="table-primary-cell">
          <strong>{row.name}</strong>
          <span>{row.client_id}</span>
        </div>
      )
    },
    {
      title: "密钥",
      render: (_, row) => (
        <Tag color={row.has_secret ? "green" : "default"}>{row.has_secret ? "已配置" : "未配置"}</Tag>
      )
    },
    {
      title: "状态",
      render: (_, row) => (
        <Switch
          checked={row.status === "active"}
          checkedChildren="启用"
          unCheckedChildren="停用"
          loading={statusMutation.isPending && pendingApplicationID === row.id}
          onChange={async (checked) => {
            setPendingApplicationID(row.id);
            try {
              await statusMutation.mutateAsync({
                path: "/api/v1/admin/applications",
                body: { ...row, status: checked ? "active" : "disabled" }
              });
            } catch {
              message.error("状态保存失败");
            } finally {
              setPendingApplicationID("");
            }
          }}
        />
      )
    },
    { title: "失败策略", render: (_, row) => failPolicyLabel(row.default_fail_policy) },
    {
      title: "操作",
      width: 170,
      render: (_, row) => (
        <Space>
          <Button size="small" onClick={() => {
            setEditingApplication(row);
            form.setFieldsValue(row);
            setOpen(true);
          }}>编辑</Button>
          <Button
            size="small"
            danger
            loading={secretMutation.isPending && pendingApplicationID === row.id}
            onClick={() => rotateApplicationSecret(row)}
          >
            {row.has_secret ? "轮换密钥" : "生成密钥"}
          </Button>
        </Space>
      )
    }
  ];
  const openCreateApplication = () => {
    setEditingApplication(null);
    form.resetFields();
    form.setFieldsValue({ status: "active", default_fail_policy: "fail_open" });
    setOpen(true);
  };
  const closeApplicationModal = () => {
    setOpen(false);
    setEditingApplication(null);
    form.resetFields();
  };
  return (
    <Card title="应用" extra={<Button type="primary" onClick={openCreateApplication}>新增</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal
        title="应用密钥"
        open={Boolean(secret)}
        onCancel={() => setSecret(null)}
        footer={(
          <Space>
            <Button onClick={() => setSecret(null)}>关闭</Button>
            <Button type="primary" onClick={() => secret && copyText(secret.value)}>复制密钥</Button>
          </Space>
        )}
      >
        <div className="secret-result">
          <div className="secret-meta">
            <span>应用</span>
            <strong>{secret ? `${secret.name} (${secret.clientID})` : "-"}</strong>
          </div>
          <Input.TextArea readOnly value={secret?.value || ""} autoSize />
          <div className="secret-warning">关闭窗口后无法再次查看这段明文密钥。</div>
        </div>
      </Modal>
      <Modal
        title={editingApplication ? "编辑应用" : "新增应用"}
        open={open}
        onCancel={closeApplicationModal}
        onOk={() => form.submit()}
        okText="保存"
        confirmLoading={mutation.isPending}
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ status: "active", default_fail_policy: "fail_open" }}
          onFinish={async (values) => {
            try {
              await mutation.mutateAsync({
                path: "/api/v1/admin/applications",
                body: editingApplication ? { ...editingApplication, ...values } : values
              });
              closeApplicationModal();
            } catch {
              message.error("应用保存失败");
            }
          }}
        >
          <Form.Item name="client_id" label="应用标识" rules={[{ required: true }]}><Input disabled={Boolean(editingApplication)} /></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="status" label="状态"><Select options={selectOptions(["active", "disabled"])} /></Form.Item>
          <Form.Item name="default_fail_policy" label="失败策略"><Select options={selectOptions(["fail_open", "fail_close"])} /></Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function Routes() {
  const { applications, appOptions, selectedClientID, defaultClientID } = useApplicationScope();
  const { data, isLoading } = useList<RoutePolicy>("routes", scopedPath("/api/v1/admin/route-policies", selectedClientID));
  const [open, setOpen] = useState(false);
  const [editingRoute, setEditingRoute] = useState<RoutePolicy | null>(null);
  const [pendingRouteID, setPendingRouteID] = useState("");
  const [form] = Form.useForm();
  const mutation = usePost<RoutePolicy>("routes");
  const toggleMutation = usePost<RoutePolicy>("routes");
  const deleteMutation = usePost<{ deleted: number }>("routes");
  const routeMode = Form.useWatch("mode", form) || "always";
  const showChallengeFields = routeIssuesChallenge(routeMode);
  const showRiskFields = routeMode === "risk_based";
  const showRateLimitFields = routeMode === "rate_limit";
  const deleteRoutePolicy = (row: RoutePolicy) => {
    Modal.confirm({
      title: "删除路由策略",
      content: `删除后 ${row.path_pattern} 不再参与策略匹配。`,
      okText: "删除",
      cancelText: "取消",
      okButtonProps: { danger: true },
      onOk: async () => {
        setPendingRouteID(row.id);
        try {
          await deleteMutation.mutateAsync({
            path: "/api/v1/admin/route-policies/delete",
            body: { client_id: row.client_id, ids: [row.id] }
          });
        } catch {
          message.error("路由策略删除失败");
        } finally {
          setPendingRouteID("");
        }
      }
    });
  };
  const columns: ColumnsType<RoutePolicy> = [
    { title: "应用", dataIndex: "client_id", width: 130 },
    { title: "名称", dataIndex: "name" },
    { title: "路径", dataIndex: "path_pattern" },
    { title: "方法", dataIndex: "method", width: 90 },
    { title: "场景", dataIndex: "scene" },
    { title: "验证码", render: (_, row) => routeIssuesChallenge(row.mode) ? routeChallengeLabel(row) : "-" },
    { title: "升级", render: (_, row) => routeIssuesChallenge(row.mode) && row.challenge_escalation?.length ? row.challenge_escalation.map(captchaLabel).join(" > ") : "-" },
    { title: "模式", render: (_, row) => policyModeLabel(row.mode) },
    { title: "灰度", render: (_, row) => `${row.rollout_percent || 100}%` },
    { title: "参数", render: (_, row) => routePolicyParameter(row) },
    {
      title: "启用",
      render: (_, row) => (
        <Switch
          checked={row.enabled}
          size="small"
          loading={toggleMutation.isPending && pendingRouteID === row.id}
          onChange={async (checked) => {
            setPendingRouteID(row.id);
            try {
              await toggleMutation.mutateAsync({
                path: "/api/v1/admin/route-policies",
                body: { ...row, enabled: checked }
              });
            } catch {
              message.error("策略保存失败");
            } finally {
              setPendingRouteID("");
            }
          }}
        />
      )
    },
    {
      title: "操作",
      width: 150,
      render: (_, row) => (
        <Space>
          <Button size="small" onClick={() => {
            setEditingRoute(row);
            form.setFieldsValue({
              ...row,
              challenge_escalation: row.challenge_escalation || [],
              rate_window_seconds: row.rate_limit?.window_seconds,
              rate_max_requests: row.rate_limit?.max_requests,
              rate_strategy: row.rate_limit?.strategy || "fixed_window"
            });
            setOpen(true);
          }}>编辑</Button>
          <Button
            size="small"
            danger
            loading={deleteMutation.isPending && pendingRouteID === row.id}
            onClick={() => deleteRoutePolicy(row)}
          >
            删除
          </Button>
        </Space>
      )
    }
  ];
  const openCreateRoute = () => {
    setEditingRoute(null);
    form.resetFields();
    form.setFieldsValue({
      client_id: defaultClientID,
      method: "POST",
      mode: "always",
      challenge_type: "SLIDER",
      risk_challenge_type: undefined,
      challenge_escalation: [],
      fail_policy: "fail_open",
      priority: 10,
      rollout_percent: 100,
      risk_observe_score: 0,
      risk_challenge_score: 0,
      risk_block_score: 0,
      enabled: true,
      token_ttl_seconds: 120,
      rate_strategy: "fixed_window"
    });
    setOpen(true);
  };
  const closeRouteModal = () => {
    setOpen(false);
    setEditingRoute(null);
    form.resetFields();
  };
  return (
    <Card title="路由策略" extra={<Button type="primary" onClick={openCreateRoute}>新增</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal title={editingRoute ? "编辑路由策略" : "新增路由策略"} open={open} onCancel={closeRouteModal} onOk={() => form.submit()} okText="保存" confirmLoading={mutation.isPending}>
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            client_id: defaultClientID,
            method: "POST",
            mode: "always",
            challenge_type: "SLIDER",
            risk_challenge_type: undefined,
            challenge_escalation: [],
            fail_policy: "fail_open",
            priority: 10,
            rollout_percent: 100,
            risk_observe_score: 0,
            risk_challenge_score: 0,
            risk_block_score: 0,
            enabled: true,
            token_ttl_seconds: 120,
            rate_strategy: "fixed_window"
          }}
          onFinish={async (values) => {
            const issuesChallenge = routeIssuesChallenge(values.mode);
            const body = {
              ...(editingRoute || {}),
              ...values,
              rate_limit: values.mode === "rate_limit" && values.rate_window_seconds && values.rate_max_requests
                ? { window_seconds: values.rate_window_seconds, max_requests: values.rate_max_requests, strategy: values.rate_strategy || "fixed_window" }
                : undefined
            };
            if (values.mode !== "risk_based") {
              body.risk_challenge_type = undefined;
              body.risk_observe_score = 0;
              body.risk_challenge_score = 0;
              body.risk_block_score = 0;
            }
            if (!issuesChallenge) {
              body.risk_challenge_type = undefined;
              body.challenge_escalation = [];
            }
            if (!body.challenge_escalation?.length) {
              delete body.challenge_escalation;
            }
            delete body.rate_window_seconds;
            delete body.rate_max_requests;
            delete body.rate_strategy;
            try {
              await mutation.mutateAsync({ path: "/api/v1/admin/route-policies", body });
              closeRouteModal();
            } catch {
              message.error("路由策略保存失败");
            }
          }}
        >
          <Form.Item name="client_id" label="应用" rules={[{ required: true }]}>
            <Select showSearch disabled={Boolean(editingRoute)} optionFilterProp="label" options={appOptions} />
          </Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="path_pattern" label="路径" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="method" label="方法"><Select options={selectOptions(["GET", "POST", "PUT", "DELETE", "PATCH"])} /></Form.Item>
          <Form.Item name="scene" label="场景" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="mode" label="模式"><Select options={selectOptions(["always", "risk_based", "rate_limit", "observe", "silent", "manual_bypass"])} /></Form.Item>
          {showChallengeFields && (
            <>
              <Form.Item name="challenge_type" label="验证码"><Select options={selectOptions(captchaTypes)} /></Form.Item>
              {showRiskFields && <Form.Item name="risk_challenge_type" label="风险验证码"><Select allowClear options={selectOptions(captchaTypes)} /></Form.Item>}
              <Form.Item name="challenge_escalation" label="升级序列"><Select mode="multiple" allowClear options={selectOptions(captchaTypes)} /></Form.Item>
              <Form.Item name="fail_policy" label="失败策略"><Select options={selectOptions(["fail_open", "fail_close"])} /></Form.Item>
              <Form.Item name="token_ttl_seconds" label="Ticket TTL"><InputNumber className="field-number" /></Form.Item>
            </>
          )}
          <Form.Item name="priority" label="优先级"><InputNumber className="field-number" /></Form.Item>
          <Form.Item name="rollout_percent" label="灰度比例"><InputNumber className="field-number" min={1} max={100} addonAfter="%" /></Form.Item>
          {showRiskFields && (
            <Space.Compact block>
              <Form.Item name="risk_observe_score" label="观察分" style={{ width: "33.33%" }}><InputNumber className="field-number" min={0} max={100} /></Form.Item>
              <Form.Item name="risk_challenge_score" label="挑战分" style={{ width: "33.33%" }}><InputNumber className="field-number" min={0} max={100} /></Form.Item>
              <Form.Item name="risk_block_score" label="阻断分" style={{ width: "33.33%" }}><InputNumber className="field-number" min={0} max={100} /></Form.Item>
            </Space.Compact>
          )}
          {showRateLimitFields && (
            <Space.Compact block>
              <Form.Item name="rate_window_seconds" label="限流窗口" style={{ width: "33.33%" }}><InputNumber className="field-number" /></Form.Item>
              <Form.Item name="rate_max_requests" label="请求上限" style={{ width: "33.33%" }}><InputNumber className="field-number" /></Form.Item>
              <Form.Item name="rate_strategy" label="限流策略" style={{ width: "33.33%" }}><Select allowClear options={selectOptions(["fixed_window", "sliding_window", "token_bucket"])} /></Form.Item>
            </Space.Compact>
          )}
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function IpPolicies() {
  const { appOptions, selectedClientID, defaultClientID } = useApplicationScope();
  const { data, isLoading } = useList<IpPolicy>("ip-policies", scopedPath("/api/v1/admin/ip-policies", selectedClientID));
  const [open, setOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<IpPolicy | null>(null);
  const [pendingPolicyID, setPendingPolicyID] = useState("");
  const [form] = Form.useForm();
  const mutation = usePost<IpPolicy>("ip-policies");
  const toggleMutation = usePost<IpPolicy>("ip-policies");
  const deleteMutation = usePost<{ deleted: number }>("ip-policies");
  const deleteIPPolicy = (row: IpPolicy) => {
    Modal.confirm({
      title: "删除 IP 策略",
      content: `删除后 ${row.cidr} 不再参与 IP 策略匹配。`,
      okText: "删除",
      cancelText: "取消",
      okButtonProps: { danger: true },
      onOk: async () => {
        setPendingPolicyID(row.id);
        try {
          await deleteMutation.mutateAsync({
            path: "/api/v1/admin/ip-policies/delete",
            body: { client_id: row.client_id, ids: [row.id] }
          });
        } catch {
          message.error("IP 策略删除失败");
        } finally {
          setPendingPolicyID("");
        }
      }
    });
  };
  const columns: ColumnsType<IpPolicy> = [
    { title: "应用", dataIndex: "client_id", width: 130 },
    { title: "类型", render: (_, row) => ipPolicyTypeLabel(row.type) },
    { title: "CIDR", dataIndex: "cidr" },
    { title: "动作", render: (_, row) => actionLabel(row.action) },
    { title: "原因", dataIndex: "reason" },
    {
      title: "启用",
      render: (_, row) => (
        <Switch
          checked={row.enabled}
          size="small"
          loading={toggleMutation.isPending && pendingPolicyID === row.id}
          onChange={async (checked) => {
            setPendingPolicyID(row.id);
            try {
              await toggleMutation.mutateAsync({
                path: "/api/v1/admin/ip-policies",
                body: { ...row, enabled: checked }
              });
            } catch {
              message.error("策略保存失败");
            } finally {
              setPendingPolicyID("");
            }
          }}
        />
      )
    },
    {
      title: "操作",
      width: 150,
      render: (_, row) => (
        <Space>
          <Button size="small" onClick={() => {
            setEditingPolicy(row);
            form.setFieldsValue(row);
            setOpen(true);
          }}>编辑</Button>
          <Button
            size="small"
            danger
            loading={deleteMutation.isPending && pendingPolicyID === row.id}
            onClick={() => deleteIPPolicy(row)}
          >
            删除
          </Button>
        </Space>
      )
    }
  ];
  const openCreatePolicy = () => {
    setEditingPolicy(null);
    form.resetFields();
    form.setFieldsValue({ client_id: defaultClientID, type: "blocklist", action: "block", enabled: true });
    setOpen(true);
  };
  const closePolicyModal = () => {
    setOpen(false);
    setEditingPolicy(null);
    form.resetFields();
  };
  return (
    <Card title="IP 策略" extra={<Button type="primary" onClick={openCreatePolicy}>新增</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal title={editingPolicy ? "编辑 IP 策略" : "新增 IP 策略"} open={open} onCancel={closePolicyModal} onOk={() => form.submit()} okText="保存" confirmLoading={mutation.isPending}>
        <Form
          form={form}
          layout="vertical"
          initialValues={{ client_id: defaultClientID, type: "blocklist", action: "block", enabled: true }}
          onFinish={async (values) => {
            try {
              await mutation.mutateAsync({
                path: "/api/v1/admin/ip-policies",
                body: {
                  ...(editingPolicy || {}),
                  ...values,
                  action: ipPolicyAction(values.type)
                }
              });
              closePolicyModal();
            } catch {
              message.error("IP 策略保存失败");
            }
          }}
        >
          <Form.Item name="client_id" label="应用" rules={[{ required: true }]}>
            <Select showSearch disabled={Boolean(editingPolicy)} optionFilterProp="label" options={appOptions} />
          </Form.Item>
          <Form.Item name="type" label="类型" rules={[{ required: true }]}><Select options={selectOptions(["allowlist", "blocklist"])} /></Form.Item>
          <Form.Item name="cidr" label="CIDR" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="reason" label="原因"><Input /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function PolicySimulator() {
  const { appOptions, defaultClientID } = useApplicationScope();
  const [form] = Form.useForm();
  const mutation = usePost<PolicySimulation>("policy-simulate");
  const simulation = mutation.data;

  useEffect(() => {
    form.setFieldValue("client_id", defaultClientID);
    mutation.reset();
  }, [defaultClientID, form]);

  return (
    <Card title="策略模拟">
      <Form
        form={form}
        layout="inline"
        className="filters"
        initialValues={{ client_id: defaultClientID, method: "POST", path: "/api/login" }}
        onFinish={(values) => mutation.mutate({ path: "/api/v1/admin/policy/simulate", body: values })}
      >
        <Form.Item name="client_id" label="应用" rules={[{ required: true }]}>
          <Select showSearch style={{ width: 180 }} optionFilterProp="label" options={appOptions} />
        </Form.Item>
        <Form.Item name="method" label="方法"><Select style={{ width: 110 }} options={selectOptions(["GET", "POST", "PUT", "DELETE", "PATCH"])} /></Form.Item>
        <Form.Item name="path" label="路径" rules={[{ required: true }]}><Input style={{ width: 180 }} /></Form.Item>
        <Form.Item name="scene" label="场景"><Input style={{ width: 120 }} /></Form.Item>
        <Form.Item name="ip" label="IP"><Input style={{ width: 150 }} /></Form.Item>
        <Form.Item name="user_agent" label="UA"><Input style={{ width: 180 }} /></Form.Item>
        <Form.Item name="account_id_hash" label="账号"><Input style={{ width: 150 }} /></Form.Item>
        <Form.Item name="device_id_hash" label="设备"><Input style={{ width: 150 }} /></Form.Item>
        <Form.Item name="request_nonce" label="Nonce"><Input style={{ width: 150 }} /></Form.Item>
        <Form.Item name="resource_tag" label="资源"><Input style={{ width: 120 }} /></Form.Item>
        <Form.Item name="risk_score" label="风险分"><InputNumber min={0} max={100} style={{ width: 110 }} /></Form.Item>
        <Form.Item name="risk_level" label="风险级别"><Select allowClear style={{ width: 120 }} options={[{ value: "low", label: "低" }, { value: "medium", label: "中" }, { value: "high", label: "高" }]} /></Form.Item>
        <Form.Item name="model_score" label="模型分"><InputNumber min={0} max={100} style={{ width: 110 }} /></Form.Item>
        <Form.Item name="model_mode" label="模型模式"><Select allowClear style={{ width: 120 }} options={selectOptions(["shadow", "observe", "enforce"])} /></Form.Item>
        <Button type="primary" htmlType="submit" loading={mutation.isPending}>模拟</Button>
      </Form>
      {mutation.error instanceof Error && <div className="error-line">{mutation.error.message}</div>}
      {simulation && (
        <div className="simulation-result">
          <Space wrap>
            <Tag color={simulation.decision.action === "challenge" ? "orange" : simulation.decision.action === "block" ? "red" : simulation.decision.action === "observe" ? "blue" : "green"}>
              {actionLabel(simulation.decision.action)}
            </Tag>
            <Tag>{simulation.decision.reason}</Tag>
            {simulation.decision.challenge_type && <Tag color="purple">{captchaLabel(simulation.decision.challenge_type)}</Tag>}
            <Tag color={simulation.rate_limit_evaluated ? "green" : "default"}>{simulation.rate_limit_evaluated ? "限流已检查" : "限流未触发"}</Tag>
          </Space>
          <div className="kv-grid">
            <span>路由</span><strong>{simulation.route?.name || simulation.route?.id || "-"}</strong>
            <span>场景</span><strong>{simulation.decision.scene || simulation.route?.scene || "-"}</strong>
            <span>模式</span><strong>{simulation.route?.mode ? policyModeLabel(simulation.route.mode) : "-"}</strong>
            <span>灰度</span><strong>{simulation.route ? `${simulation.route.rollout_percent || 100}%` : "-"}</strong>
            <span>TTL</span><strong>{simulation.decision.ttl_seconds || "-"}</strong>
            <span>风险</span><strong>{unknownText(simulation.request.risk_score)} / {unknownText(simulation.request.risk_level)}</strong>
            <span>模型</span><strong>{unknownText(simulation.request.model_score)} / {unknownText(simulation.request.model_mode)}</strong>
          </div>
          {(simulation.side_effects.length > 0 || (simulation.notes || []).length > 0) && (
            <Space wrap>
              {simulation.side_effects.map((item) => <Tag key={item}>{item}</Tag>)}
              {(simulation.notes || []).map((item) => <Tag key={item} color="blue">{item}</Tag>)}
            </Space>
          )}
        </div>
      )}
    </Card>
  );
}

function resourceLibraryKey(row: Resource) {
  if (row.resource_type === "background_library") return "background";
  if (row.resource_type === "concat_background_image" || row.resource_type === "concat_background_library") return "concatBackground";
  if (row.resource_type === "jigsaw_background_image" || row.resource_type === "jigsaw_background_library") return "jigsawBackground";
  if (row.resource_type === "rotate_library") return "rotate";
  if (row.resource_type === "grid_category_library") return "grid";
  if (row.resource_type === "icon_library") return "icon";
  if (row.resource_type.endsWith("_template") || row.resource_type === "font") return "template";
  if (row.resource_type === "background_image" || row.resource_type === "icon") return "single";
  return "single";
}

function isPrimaryGalleryResource(row: Resource) {
  const key = resourceLibraryKey(row);
  return key === "background" || key === "concatBackground" || key === "jigsawBackground" || key === "rotate" || key === "grid" || key === "icon";
}

function countResourceFileFilters(resources: Resource[]) {
  return resources.reduce<Record<string, number>>((counts, row) => {
    const key = resourceLibraryKey(row);
    counts.all = (counts.all || 0) + 1;
    if (key === "background" || key === "concatBackground" || key === "jigsawBackground" || key === "rotate" || key === "grid" || key === "icon") {
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, { all: 0, background: 0, concatBackground: 0, jigsawBackground: 0, rotate: 0, grid: 0, icon: 0 });
}

function matchesResourceFileFilter(row: Resource, filter: string) {
  return filter === "all" || resourceLibraryKey(row) === filter;
}

function galleryUploadDefaults(galleryType?: string) {
  if (galleryType === "concatBackground") {
    return { captchaType: "CONCAT", resourceType: "concat_background_library", tag: "default" };
  }
  if (galleryType === "jigsawBackground") {
    return { captchaType: "JIGSAW", resourceType: "jigsaw_background_library", tag: "default" };
  }
  if (galleryType === "grid") {
    return { captchaType: "GRID_IMAGE_CLICK", resourceType: "grid_category_library", tag: "default" };
  }
  if (galleryType === "rotate") {
    return { captchaType: "ROTATE", resourceType: "rotate_library", tag: "default" };
  }
  if (galleryType === "icon") {
    return { captchaType: "IMAGE_CLICK", resourceType: "icon_library", tag: "default" };
  }
  return { captchaType: "AUTO", resourceType: "background_library", tag: "default" };
}

function usesMaterialDifficulty(galleryType?: string) {
  return galleryType === "concatBackground" || galleryType === "jigsawBackground";
}

function captchaLabel(value: string) {
  return captchaLabels[value] || value;
}

function policyModeLabel(value: string) {
  return policyModeLabels[value] || value;
}

function routeIssuesChallenge(mode: string) {
  return ["always", "risk_based", "rate_limit"].includes(mode);
}

function routeChallengeLabel(row: RoutePolicy) {
  if (row.mode === "risk_based" && row.risk_challenge_type) {
    return `${captchaLabel(row.challenge_type)} / ${captchaLabel(row.risk_challenge_type)}`;
  }
  return captchaLabel(row.challenge_type);
}

function routePolicyParameter(row: RoutePolicy) {
  if (row.mode === "risk_based") {
    return `${row.risk_observe_score || 0}/${row.risk_challenge_score || 0}/${row.risk_block_score || 0}`;
  }
  if (row.mode === "rate_limit" && row.rate_limit) {
    return `${row.rate_limit.max_requests}/${row.rate_limit.window_seconds}s ${optionLabels[row.rate_limit.strategy || "fixed_window"] || row.rate_limit.strategy || ""}`.trim();
  }
  return "-";
}

function failPolicyLabel(value: string) {
  return failPolicyLabels[value] || value;
}

function ipPolicyTypeLabel(value: string) {
  return ipPolicyTypeLabels[value] || value;
}

function ipPolicyAction(type: string) {
  return type === "allowlist" ? "allow" : "block";
}

function actionLabel(value: string) {
  return actionLabels[value] || value;
}

function resultLabel(value: string) {
  return resultLabels[value] || value;
}

function riskLabel(value: string) {
  return riskLabelLabels[value] || value;
}

function modelModeLabel(value: string) {
  return modelModeLabels[value] || value;
}

function modelStatusLabel(value: string) {
  return modelStatusLabels[value] || value;
}

function ratioText(active?: number, total?: number) {
  return `${active ?? 0}/${total ?? 0}`;
}

function compactText(value: string, maxLength: number) {
  if (!value || value.length <= maxLength) return value || "-";
  return `${value.slice(0, Math.max(0, maxLength - 3))}...`;
}

function unknownText(value: unknown) {
  if (value === undefined || value === null || value === "") return "-";
  return String(value);
}

function formatDateTime(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(date);
}

function resourceTypeLabel(value: string) {
  return resourceTypeLabels[value] || value;
}

function statusLabel(value: string) {
  return statusLabels[value] || value;
}

function useApplicationScope() {
  return React.useContext(ApplicationScopeContext);
}

function applicationOptions(applications?: Application[]) {
  return (applications || []).map((item) => ({
    value: item.client_id,
    label: `${item.name} (${item.client_id})`
  }));
}

function firstApplicationClientID(applications?: Application[]) {
  return applications?.[0]?.client_id || "demo";
}

function scopedPath(path: string, clientID: string) {
  if (!clientID) return path;
  return `${path}${path.includes("?") ? "&" : "?"}client_id=${encodeURIComponent(clientID)}`;
}

function resourceCategory(row: Resource) {
  return metadataText(row, "label") || metadataText(row, "category");
}

function resourceTitle(row: Resource) {
  return resourceCategory(row) || resourceTypeLabel(row.resource_type);
}

function resourcePlaceholder(row: Resource) {
  const title = resourceCategory(row) || resourceTypeLabel(row.resource_type);
  return title.slice(0, 4);
}

function resourceFileName(row: Resource) {
  const name = metadataText(row, "file_name", "filename", "original_name", "name");
  if (name) return name;
  const uri = row.uri || "";
  const cleanURI = uri.split("?")[0].split("#")[0];
  const basename = cleanURI.split("/").filter(Boolean).pop();
  return basename || resourceTitle(row);
}

function resourcePreviewSrc(row: Resource) {
  const dataURL = metadataText(row, "thumbnail_data_url", "data_url", "data_uri");
  if (dataURL?.startsWith("data:image/")) return dataURL;
  if (/^https?:\/\//i.test(row.uri)) return row.uri;
  if (/^data:image\//i.test(row.uri)) return row.uri;
  return "";
}

function metadataText(row: Resource, ...keys: string[]) {
  for (const key of keys) {
    const value = row.metadata?.[key];
    if (typeof value === "string") return value.trim();
    if (typeof value === "number") return String(value);
  }
  return "";
}

function ResourceFileItem({
  row,
  selected,
  onSelect
}: {
  row: Resource;
  selected: boolean;
  onSelect: (checked: boolean) => void;
}) {
  const preview = resourcePreviewSrc(row);
  const name = resourceFileName(row);
  return (
    <article className={selected ? "resource-file-item selected" : "resource-file-item"}>
      <Checkbox className="resource-file-check" checked={selected} onChange={(event) => onSelect(event.target.checked)} />
      <div className="resource-file-thumb">
        {preview ? <img alt="" src={preview} /> : <span>{resourcePlaceholder(row)}</span>}
      </div>
      <div className="resource-file-name" title={name}>{name}</div>
      <span className={row.status === "active" ? "resource-file-status active" : "resource-file-status"}>{statusLabel(row.status)}</span>
    </article>
  );
}

function Resources() {
  const { appOptions, selectedClientID, defaultClientID } = useApplicationScope();
  const { data, isLoading } = useList<Resource>("resources", scopedPath("/api/v1/admin/resources", selectedClientID));
  const [open, setOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [fileFilter, setFileFilter] = useState("all");
  const [selectedResourceIds, setSelectedResourceIds] = useState<string[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [uploadError, setUploadError] = useState("");
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const deleteMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      const response = await fetch(`${apiBase}/api/v1/admin/resources/delete`, {
        method: "POST",
        headers: { ...adminHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ client_id: deleteClientID, ids })
      });
      if (!response.ok) throw new Error(response.statusText);
      return await response.json() as { deleted: number };
    },
    onSuccess: async () => {
      setSelectedResourceIds([]);
      setDeleteOpen(false);
      await queryClient.invalidateQueries({ queryKey: ["resources"] });
      await queryClient.invalidateQueries({ queryKey: ["metrics"] });
    }
  });
  const statusMutation = useMutation({
    mutationFn: async ({ items, status }: { items: Resource[]; status: string }) => {
      await Promise.all(items.map(async (item) => {
        const response = await fetch(`${apiBase}/api/v1/admin/resources`, {
          method: "POST",
          headers: { ...adminHeaders(), "Content-Type": "application/json" },
          body: JSON.stringify({ ...item, status })
        });
        if (!response.ok) throw new Error(response.statusText);
      }));
    },
    onSuccess: async () => {
      setSelectedResourceIds([]);
      await queryClient.invalidateQueries({ queryKey: ["resources"] });
      await queryClient.invalidateQueries({ queryKey: ["metrics"] });
    },
    onError: () => {
      message.error("资源状态保存失败");
    }
  });
  const resources = data || [];
  const galleryResources = useMemo(() => resources.filter(isPrimaryGalleryResource), [resources]);
  const visibleGalleryResources = useMemo(
    () => galleryResources.filter((item) => matchesResourceFileFilter(item, fileFilter)),
    [fileFilter, galleryResources]
  );
  const fileFilterCounts = useMemo(() => countResourceFileFilters(galleryResources), [galleryResources]);
  const visibleResourceIDs = useMemo(() => new Set(visibleGalleryResources.map((item) => item.id)), [visibleGalleryResources]);
  const selectedGalleryResources = useMemo(
    () => galleryResources.filter((item) => selectedResourceIds.includes(item.id)),
    [galleryResources, selectedResourceIds]
  );
  const selectedResourceClientIDs = useMemo(
    () => Array.from(new Set(selectedGalleryResources.map((item) => item.client_id).filter(Boolean))),
    [selectedGalleryResources]
  );
  const deleteClientID = selectedClientID || (selectedResourceClientIDs.length === 1 ? selectedResourceClientIDs[0] : "");
  const selectedGalleryCount = selectedResourceIds.filter((id) => galleryResources.some((item) => item.id === id)).length;
  const selectedVisibleCount = selectedResourceIds.filter((id) => visibleResourceIDs.has(id)).length;
  const allGallerySelected = visibleGalleryResources.length > 0 && selectedVisibleCount === visibleGalleryResources.length;
  const partiallySelected = selectedVisibleCount > 0 && selectedVisibleCount < visibleGalleryResources.length;
  const toggleAllGallery = (checked: boolean) => {
    setSelectedResourceIds((current) => {
      if (checked) return Array.from(new Set([...current, ...visibleGalleryResources.map((item) => item.id)]));
      return current.filter((id) => !visibleResourceIDs.has(id));
    });
  };
  const toggleResource = (id: string, checked: boolean) => {
    setSelectedResourceIds((current) => checked ? Array.from(new Set([...current, id])) : current.filter((item) => item !== id));
  };
  const deleteSelectedResources = () => {
    if (selectedGalleryCount === 0 || deleteMutation.isPending) return;
    if (!deleteClientID) {
      message.error("删除需要单一应用范围");
      return;
    }
    setDeleteOpen(true);
  };
  const updateSelectedResourceStatus = (status: string) => {
    if (selectedGalleryResources.length === 0 || statusMutation.isPending) return;
    statusMutation.mutate({ items: selectedGalleryResources, status });
  };
  const uploadGalleryType = Form.useWatch("gallery_type", form) || "background";

  useEffect(() => {
    setSelectedResourceIds([]);
  }, [selectedClientID]);

  const openCreate = () => {
    form.resetFields();
    setSelectedFiles([]);
    setUploadError("");
    form.setFieldsValue({
      client_id: defaultClientID,
      scene: "",
      tag: "default",
      gallery_type: "background",
      category: "",
      label: "",
      difficulty: "medium"
    });
    setOpen(true);
  };
  return (
    <Card
      title="资源图库"
      extra={(
        <Button icon={<PlusOutlined />} type="primary" onClick={() => openCreate()}>新增</Button>
      )}
    >
      <div className="resource-file-bar">
        <Checkbox checked={allGallerySelected} indeterminate={partiallySelected} onChange={(event) => toggleAllGallery(event.target.checked)} />
        <Select
          showSearch
          className="resource-file-filter"
          value={fileFilter}
          optionFilterProp="label"
          onChange={(value) => {
            setFileFilter(value);
          }}
          options={resourceFileFilters.map((item) => ({
            value: item.key,
            label: `${item.label} ${fileFilterCounts[item.key] || 0}`
          }))}
        />
        <span>{visibleGalleryResources.length} 个</span>
        {selectedGalleryCount > 0 && <em>已选 {selectedGalleryCount} 个</em>}
        <Button disabled={selectedGalleryCount === 0} loading={statusMutation.isPending} onClick={() => updateSelectedResourceStatus("active")}>启用</Button>
        <Button disabled={selectedGalleryCount === 0} loading={statusMutation.isPending} onClick={() => updateSelectedResourceStatus("disabled")}>停用</Button>
        <Button danger disabled={selectedGalleryCount === 0 || !deleteClientID} loading={deleteMutation.isPending} onClick={deleteSelectedResources}>删除</Button>
      </div>
      {isLoading ? (
        <div className="resource-gallery-empty">加载中</div>
      ) : visibleGalleryResources.length === 0 ? (
        <div className="resource-file-empty">
          <strong>还没有上传图库资源</strong>
          <p>上传背景、图片格子或图标素材后，这里会像文件夹一样显示图片缩略图。</p>
          <Space wrap>
            <Button icon={<PlusOutlined />} type="primary" onClick={() => openCreate()}>新增</Button>
          </Space>
        </div>
      ) : (
        <div className="resource-file-grid">
          {visibleGalleryResources.map((row) => (
            <ResourceFileItem
              key={row.id}
              row={row}
              selected={selectedResourceIds.includes(row.id)}
              onSelect={(checked) => toggleResource(row.id, checked)}
            />
          ))}
        </div>
      )}
      <Modal
        title={`删除 ${selectedGalleryCount} 个资源？`}
        open={deleteOpen}
        onCancel={() => setDeleteOpen(false)}
        onOk={() => deleteMutation.mutateAsync(selectedResourceIds)}
        okText="删除"
        okButtonProps={{ danger: true }}
        cancelText="取消"
        confirmLoading={deleteMutation.isPending}
      >
        <p>删除后这些图库素材不会再被验证码抽样使用。</p>
      </Modal>
      <Modal
        title="新增图片"
        open={open}
        onCancel={() => {
          setOpen(false);
          form.resetFields();
          setSelectedFiles([]);
          setUploadError("");
        }}
        onOk={() => form.submit()}
        okText="保存资源"
        cancelText="取消"
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            client_id: defaultClientID,
            scene: "",
            tag: "default",
            gallery_type: "background",
            category: "",
            label: "",
            difficulty: "medium"
          }}
          onFinish={async (values: ResourceFormValues) => {
            if (selectedFiles.length === 0) {
              setUploadError("请选择图片或 ZIP");
              return;
            }
            const defaults = galleryUploadDefaults(values.gallery_type);
            const formData = new FormData();
            for (const file of selectedFiles) {
              formData.append("files", file);
            }
            formData.set("client_id", values.client_id || defaultClientID);
            formData.set("scene", values.scene || "");
            formData.set("captcha_type", defaults.captchaType);
            formData.set("resource_type", defaults.resourceType);
            formData.set("tag", values.tag || defaults.tag);
            formData.set("status", "active");
            if (usesMaterialDifficulty(values.gallery_type)) {
              formData.set("difficulty", values.difficulty || "medium");
            }
            if (values.category) formData.set("category", values.category);
            if (values.label) formData.set("label", values.label);
            const response = await fetch(`${apiBase}/api/v1/admin/resources/upload`, {
              method: "POST",
              headers: adminHeaders(),
              body: formData
            });
            if (!response.ok) {
              setUploadError("上传失败");
              return;
            }
            await queryClient.invalidateQueries({ queryKey: ["resources"] });
            await queryClient.invalidateQueries({ queryKey: ["metrics"] });
            form.resetFields();
            setSelectedFiles([]);
            setUploadError("");
            setOpen(false);
          }}
        >
          <Form.Item name="client_id" label="应用" rules={[{ required: true }]}>
            <Select showSearch optionFilterProp="label" options={appOptions} />
          </Form.Item>
          <Form.Item name="gallery_type" label="图库" rules={[{ required: true }]}>
            <Select options={galleryUploadTypes} />
          </Form.Item>
          <div className="gallery-upload-note">{galleryUploadNotes[uploadGalleryType] || galleryUploadNotes.background}</div>
          {usesMaterialDifficulty(uploadGalleryType) && (
            <Form.Item name="difficulty" label="素材难度">
              <Select options={resourceDifficultyOptions} />
            </Form.Item>
          )}
          <Space.Compact block>
            <Form.Item name="scene" label="场景" style={{ width: "50%" }}>
              <Input placeholder="全场景" />
            </Form.Item>
            <Form.Item name="tag" label="标签" style={{ width: "50%" }}>
              <Input placeholder="default" />
            </Form.Item>
          </Space.Compact>
          {uploadGalleryType === "grid" && (
            <Space.Compact block>
              <Form.Item name="category" label="分类" rules={[{ required: true, message: "请输入分类" }]} style={{ width: "50%" }}>
                <Input placeholder="car" />
              </Form.Item>
              <Form.Item name="label" label="显示名" style={{ width: "50%" }}>
                <Input placeholder="汽车" />
              </Form.Item>
            </Space.Compact>
          )}
          <Form.Item label="上传图片或 ZIP" validateStatus={uploadError ? "error" : undefined} help={uploadError || undefined}>
            <div className="upload-box">
              <input
                type="file"
                multiple
                accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml,.zip"
                onChange={(event) => {
                  setUploadError("");
                  setSelectedFiles(Array.from(event.currentTarget.files || []));
                }}
              />
              <div className="upload-hint">
                {selectedFiles.length > 0 ? `已选择 ${selectedFiles.length} 个文件` : "支持多张图片或一个 ZIP 包"}
              </div>
              {selectedFiles.length > 0 && (
                <div className="upload-file-list">
                  {selectedFiles.slice(0, 8).map((file) => <span key={`${file.name}-${file.size}`}>{file.name}</span>)}
                  {selectedFiles.length > 8 && <span>还有 {selectedFiles.length - 8} 个</span>}
                </div>
              )}
            </div>
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function Audit() {
  const { selectedClientID } = useApplicationScope();
  const [filters, setFilters] = useState({ action: "", result: "", scene: "", decision_reason: "", account_id_hash: "", device_id_hash: "" });
  const [pageState, setPageState] = useState({ page: 1, pageSize: 20 });
  const [form] = Form.useForm();

  useEffect(() => {
    setPageState((prev) => ({ ...prev, page: 1 }));
  }, [selectedClientID]);

  const path = useMemo(() => {
    const params = new URLSearchParams({
      limit: String(pageState.pageSize),
      offset: String((pageState.page - 1) * pageState.pageSize)
    });
    if (selectedClientID) params.set("client_id", selectedClientID);
    if (filters.scene) params.set("scene", filters.scene);
    if (filters.action) params.set("action", filters.action);
    if (filters.result) params.set("result", filters.result);
    if (filters.decision_reason) params.set("decision_reason", filters.decision_reason);
    if (filters.account_id_hash) params.set("account_id_hash", filters.account_id_hash);
    if (filters.device_id_hash) params.set("device_id_hash", filters.device_id_hash);
    return `/api/v1/admin/audit-events?${params.toString()}`;
  }, [filters, pageState.page, pageState.pageSize, selectedClientID]);
  const { data, isLoading } = usePagedList<AuditEvent>("audit", path);
  const rows = data?.items || [];
  const total = (pageState.page - 1) * pageState.pageSize + rows.length + (data?.has_more ? 1 : 0);
  const columns: ColumnsType<AuditEvent> = [
    { title: "时间", width: 170, render: (_, row) => formatDateTime(row.created_at) },
    { title: "应用", dataIndex: "client_id", width: 130 },
    { title: "路由", render: (_, row) => <span title={row.route || ""}>{compactText(row.route || "", 28)}</span> },
    { title: "场景", dataIndex: "scene" },
    {
      title: "主体",
      render: (_, row) => (
        <Space wrap>
          {row.ip_hash && <Tag title={row.ip_hash}>IP {compactText(row.ip_hash, 14)}</Tag>}
          {row.account_id_hash && <Tag title={row.account_id_hash}>账号 {compactText(row.account_id_hash, 14)}</Tag>}
          {row.device_id_hash && <Tag title={row.device_id_hash}>设备 {compactText(row.device_id_hash, 14)}</Tag>}
          {!row.ip_hash && !row.account_id_hash && !row.device_id_hash && "-"}
        </Space>
      )
    },
    { title: "动作", render: (_, row) => actionLabel(row.action) },
    { title: "验证码", render: (_, row) => row.challenge_type ? captchaLabel(row.challenge_type) : "-" },
    { title: "结果", render: (_, row) => resultLabel(row.result) },
    { title: "原因", render: (_, row) => <span title={row.decision_reason}>{compactText(row.decision_reason, 26)}</span> }
  ];
  return (
    <Card title="审计">
      <Form
        form={form}
        layout="inline"
        className="filters"
        onFinish={(values) => {
          setFilters({
            action: values.action || "",
            result: values.result || "",
            scene: values.scene || "",
            decision_reason: values.decision_reason || "",
            account_id_hash: values.account_id_hash || "",
            device_id_hash: values.device_id_hash || ""
          });
          setPageState((prev) => ({ ...prev, page: 1 }));
        }}
        onReset={() => {
          form.resetFields();
          setFilters({ action: "", result: "", scene: "", decision_reason: "", account_id_hash: "", device_id_hash: "" });
          setPageState((prev) => ({ ...prev, page: 1 }));
        }}
      >
        <Form.Item name="scene" label="场景"><Input placeholder="login" /></Form.Item>
        <Form.Item name="decision_reason" label="原因"><Input placeholder="RISK_BASED" /></Form.Item>
        <Form.Item name="account_id_hash" label="账号"><Input placeholder="account hash" /></Form.Item>
        <Form.Item name="device_id_hash" label="设备"><Input placeholder="device hash" /></Form.Item>
        <Form.Item name="action" label="动作"><Select allowClear style={{ width: 140 }} options={selectOptions(["allow", "challenge", "block", "observe"])} /></Form.Item>
        <Form.Item name="result" label="结果"><Select allowClear style={{ width: 140 }} options={selectOptions(["allow", "pass", "retry", "block", "config_changed", "training_feedback"])} /></Form.Item>
        <Button htmlType="submit">查询</Button>
        <Button htmlType="reset">重置</Button>
      </Form>
      <Table
        rowKey="id"
        loading={isLoading}
        columns={columns}
        dataSource={rows}
        pagination={{
          current: pageState.page,
          pageSize: pageState.pageSize,
          pageSizeOptions: [20, 50, 100],
          showSizeChanger: true,
          total,
          onChange: (page, pageSize) => {
            setPageState((prev) => pageSize !== prev.pageSize ? { page: 1, pageSize } : { page, pageSize });
          }
        }}
      />
    </Card>
  );
}

function RiskFeatures() {
  const { selectedClientID } = useApplicationScope();
  const [filters, setFilters] = useState({ challenge_type: "", label: "", model_trainable: "", scene: "" });
  const [pageState, setPageState] = useState({ page: 1, pageSize: 20 });
  const [exporting, setExporting] = useState(false);
  const [actingFeatureID, setActingFeatureID] = useState("");
  const [form] = Form.useForm();

  useEffect(() => {
    setPageState((prev) => ({ ...prev, page: 1 }));
  }, [selectedClientID]);

  const path = useMemo(() => {
    const params = new URLSearchParams({
      limit: String(pageState.pageSize),
      offset: String((pageState.page - 1) * pageState.pageSize)
    });
    if (selectedClientID) params.set("client_id", selectedClientID);
    if (filters.scene) params.set("scene", filters.scene);
    if (filters.challenge_type) params.set("challenge_type", filters.challenge_type);
    if (filters.label) params.set("label", filters.label);
    if (filters.model_trainable) params.set("model_trainable", filters.model_trainable);
    return `/api/v1/admin/risk-feature-snapshots?${params.toString()}`;
  }, [filters, pageState.page, pageState.pageSize, selectedClientID]);
  const { data, isLoading } = usePagedList<RiskFeatureSnapshot>("risk-features", path);
  const rows = data?.items || [];
  const total = (pageState.page - 1) * pageState.pageSize + rows.length + (data?.has_more ? 1 : 0);
  const mutation = usePost<RiskFeatureSnapshot>("risk-features");
  const exportTrainingData = async () => {
    const params = new URLSearchParams({ limit: "1000" });
    if (selectedClientID) params.set("client_id", selectedClientID);
    if (filters.scene) params.set("scene", filters.scene);
    if (filters.challenge_type) params.set("challenge_type", filters.challenge_type);
    if (filters.label) params.set("label", filters.label);
    if (filters.model_trainable) {
      params.set("model_trainable", filters.model_trainable);
    } else {
      params.set("trainable_only", "true");
    }
    setExporting(true);
    try {
      const response = await fetch(`${apiBase}/api/v1/admin/risk-feature-snapshots/export?${params.toString()}`, { headers: adminHeaders() });
      if (!response.ok) throw new Error(response.statusText);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `captcha-risk-features-${Date.now()}.jsonl`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch {
      message.error("训练数据导出失败");
    } finally {
      setExporting(false);
    }
  };
  const confirmLabelUpdate = (row: RiskFeatureSnapshot, label: string, modelTrainable: boolean) => {
    const resetting = label === "unknown";
    const labelText = riskLabel(label);
    Modal.confirm({
      title: resetting ? "撤销训练标注" : `确认${labelText}`,
      content: (
        <div className="confirm-copy">
          <p>样本 {compactText(row.attempt_id, 28)}</p>
          <p>{resetting ? "撤销后该样本会回到候选状态，不再进入默认训练导出。" : "确认后该样本会被标记为可训练，后续离线训练导出会默认包含它。"}</p>
        </div>
      ),
      okText: resetting ? "确认撤销" : "确认标注",
      cancelText: "取消",
      okButtonProps: { danger: label === "confirmed_bot" || resetting },
      onOk: async () => {
        setActingFeatureID(row.id);
        try {
          await mutation.mutateAsync({
            path: `/api/v1/admin/risk-feature-snapshots/${row.id}/label`,
            body: {
              label,
              label_source: resetting ? "" : "manual_review",
              model_trainable: modelTrainable
            }
          });
          message.success(resetting ? "训练标注已撤销" : "训练标注已保存");
        } catch {
          message.error(resetting ? "训练标注撤销失败" : "训练标注保存失败");
          throw new Error("risk feature label update failed");
        } finally {
          setActingFeatureID("");
        }
      }
    });
  };
  const columns: ColumnsType<RiskFeatureSnapshot> = [
    { title: "应用", dataIndex: "client_id", width: 130 },
    { title: "样本", render: (_, row) => <span title={row.attempt_id}>{compactText(row.attempt_id, 24)}</span> },
    { title: "场景", dataIndex: "scene" },
    { title: "验证码", render: (_, row) => captchaLabel(row.challenge_type) },
    { title: "标签", render: (_, row) => riskLabel(row.label) },
    { title: "特征集", dataIndex: "feature_version" },
    { title: "状态", render: (_, row) => <Tag color={row.model_trainable ? "green" : "default"}>{row.model_trainable ? "入训样本" : "候选样本"}</Tag> },
    {
      title: "操作",
      render: (_, row) => (
        <Space>
          <Button size="small" loading={actingFeatureID === row.id} disabled={row.label === "confirmed_human" && row.model_trainable} onClick={() => confirmLabelUpdate(row, "confirmed_human", true)}>真人</Button>
          <Button size="small" danger loading={actingFeatureID === row.id} disabled={row.label === "confirmed_bot" && row.model_trainable} onClick={() => confirmLabelUpdate(row, "confirmed_bot", true)}>机器</Button>
          <Button size="small" loading={actingFeatureID === row.id} disabled={row.label === "unknown" && !row.model_trainable} onClick={() => confirmLabelUpdate(row, "unknown", false)}>撤销</Button>
        </Space>
      )
    }
  ];
  return (
    <Card title="训练样本" extra={<Button onClick={exportTrainingData} loading={exporting}>导出样本</Button>}>
      <Form
        form={form}
        layout="inline"
        className="filters"
        onFinish={(values) => {
          setFilters({
            challenge_type: values.challenge_type || "",
            label: values.label || "",
            model_trainable: values.model_trainable || "",
            scene: values.scene || ""
          });
          setPageState((prev) => ({ ...prev, page: 1 }));
        }}
        onReset={() => {
          form.resetFields();
          setFilters({ challenge_type: "", label: "", model_trainable: "", scene: "" });
          setPageState((prev) => ({ ...prev, page: 1 }));
        }}
      >
        <Form.Item name="scene" label="场景"><Input placeholder="login" /></Form.Item>
        <Form.Item name="challenge_type" label="验证码"><Select allowClear style={{ width: 170 }} options={selectOptions(captchaTypes)} /></Form.Item>
        <Form.Item name="label" label="标签"><Select allowClear style={{ width: 170 }} options={selectOptions(["unknown", "captcha_pass", "captcha_retry", "likely_human", "likely_bot", "confirmed_human", "confirmed_bot"])} /></Form.Item>
        <Form.Item name="model_trainable" label="状态"><Select allowClear style={{ width: 130 }} options={[{ value: "true", label: "入训样本" }, { value: "false", label: "候选样本" }]} /></Form.Item>
        <Button htmlType="submit">查询</Button>
        <Button htmlType="reset">重置</Button>
      </Form>
      <Table
        rowKey="id"
        loading={isLoading}
        columns={columns}
        dataSource={rows}
        pagination={{
          current: pageState.page,
          pageSize: pageState.pageSize,
          pageSizeOptions: [20, 50, 100],
          showSizeChanger: true,
          total,
          onChange: (page, pageSize) => {
            setPageState((prev) => pageSize !== prev.pageSize ? { page: 1, pageSize } : { page, pageSize });
          }
        }}
      />
    </Card>
  );
}

function RiskModels() {
  const { data, isLoading } = useList<RiskModelVersion>("risk-models", "/api/v1/admin/risk-model-versions?limit=100");
  const [open, setOpen] = useState(false);
  const [actingModelID, setActingModelID] = useState("");
  const [form] = Form.useForm();
  const mutation = usePost<RiskModelVersion>("risk-models");
  const actionMutation = usePost<RiskModelVersion>("risk-models");
  const openCreateModel = () => {
    form.resetFields();
    setOpen(true);
  };
  const closeCreateModel = () => {
    form.resetFields();
    setOpen(false);
  };
  const confirmModelAction = (row: RiskModelVersion, action: "activate" | "rollback") => {
    const activating = action === "activate";
    Modal.confirm({
      title: activating ? "激活模型" : "回滚模型",
      content: (
        <div className="confirm-copy">
          <p>{row.name} / {row.version}</p>
          <p>{activating ? "激活后同名模型的当前 active 版本会退役，observe/enforce 模式可能参与风险决策。" : "回滚会将当前 active 标记为已回滚，并恢复最近一个退役版本。"}</p>
        </div>
      ),
      okText: activating ? "确认激活" : "确认回滚",
      cancelText: "取消",
      okButtonProps: { danger: activating && row.mode === "enforce" },
      onOk: async () => {
        setActingModelID(row.id);
        try {
          await actionMutation.mutateAsync({ path: `/api/v1/admin/risk-model-versions/${row.id}/${action}`, body: {} });
          message.success(activating ? "模型已激活" : "模型已回滚");
        } catch {
          message.error(activating ? "模型激活失败" : "模型回滚失败");
          throw new Error(activating ? "activate model failed" : "rollback model failed");
        } finally {
          setActingModelID("");
        }
      }
    });
  };
  const columns: ColumnsType<RiskModelVersion> = [
    { title: "名称", dataIndex: "name" },
    { title: "版本", dataIndex: "version" },
    { title: "特征集", dataIndex: "feature_version" },
    { title: "窗口", dataIndex: "training_window" },
    { title: "模式", render: (_, row) => <Tag color={row.mode === "enforce" ? "red" : row.mode === "observe" ? "blue" : "default"}>{modelModeLabel(row.mode)}</Tag> },
    { title: "状态", render: (_, row) => <Tag color={row.status === "active" ? "green" : row.status === "rolled_back" ? "orange" : "default"}>{modelStatusLabel(row.status)}</Tag> },
    {
      title: "操作",
      render: (_, row) => (
        <Space>
          <Button size="small" loading={actingModelID === row.id} disabled={row.status === "active"} onClick={() => confirmModelAction(row, "activate")}>激活</Button>
          <Button size="small" loading={actingModelID === row.id} disabled={row.status !== "active"} onClick={() => confirmModelAction(row, "rollback")}>回滚</Button>
        </Space>
      )
    }
  ];
  return (
    <Card title="模型管理" extra={<Button type="primary" onClick={openCreateModel}>登记模型</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal title="登记模型" open={open} onCancel={closeCreateModel} onOk={() => form.submit()} okText="保存">
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            name: "track-baseline",
            feature_version: "track-v1",
            mode: "shadow"
          }}
          onFinish={async (values) => {
            const metrics: Record<string, unknown> = {};
            if (values.auc !== undefined) metrics.auc = values.auc;
            if (values.false_positive_rate !== undefined) metrics.false_positive_rate = values.false_positive_rate;
            const { auc, false_positive_rate, ...body } = values;
            try {
              await mutation.mutateAsync({
                path: "/api/v1/admin/risk-model-versions",
                body: { ...body, status: "candidate", metrics: Object.keys(metrics).length > 0 ? metrics : undefined }
              });
              closeCreateModel();
              message.success("模型已登记");
            } catch {
              message.error("模型登记失败");
            }
          }}
        >
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="version" label="版本" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="feature_version" label="特征集" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="training_window" label="训练窗口" rules={[{ required: true }]}><Input placeholder="2026-06-01/2026-06-20" /></Form.Item>
          <Form.Item name="artifact_uri" label="模型包地址" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="mode" label="模式"><Select options={selectOptions(["shadow", "observe", "enforce"])} /></Form.Item>
          <Space.Compact block>
            <Form.Item name="auc" label="AUC" style={{ width: "50%" }}><InputNumber min={0} max={1} step={0.01} style={{ width: "100%" }} /></Form.Item>
            <Form.Item name="false_positive_rate" label="误伤率" style={{ width: "50%" }}><InputNumber min={0} max={1} step={0.01} style={{ width: "100%" }} /></Form.Item>
          </Space.Compact>
        </Form>
      </Modal>
    </Card>
  );
}

function useList<T>(key: string, path: string) {
  return useQuery({
    queryKey: [key, path],
    queryFn: async () => {
      const response = await fetch(`${apiBase}${path}`, { headers: adminHeaders() });
      if (!response.ok) throw new Error(response.statusText);
      const body = await response.json() as ListResponse<T>;
      return body.items || [];
    }
  });
}

function usePagedList<T>(key: string, path: string) {
  return useQuery({
    queryKey: [key, path],
    queryFn: async (): Promise<PagedList<T>> => {
      const response = await fetch(`${apiBase}${path}`, { headers: adminHeaders() });
      if (!response.ok) throw new Error(response.statusText);
      const body = await response.json() as ListResponse<T>;
      return {
        items: body.items || [],
        limit: body.limit || 100,
        offset: body.offset || 0,
        has_more: Boolean(body.has_more)
      };
    }
  });
}

function usePost<T>(invalidateKey: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async ({ path, body }: { path: string; body: unknown }) => {
      const response = await fetch(`${apiBase}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...adminHeaders() },
        body: JSON.stringify(body)
      });
      if (!response.ok) throw new Error(response.statusText);
      return await response.json() as T;
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: [invalidateKey] });
      await client.invalidateQueries({ queryKey: ["metrics"] });
    }
  });
}

function selectOptions(values: string[]) {
  return values.map((value) => ({ value, label: optionLabels[value] || value }));
}

async function copyText(value: string) {
  try {
    await navigator.clipboard.writeText(value);
    message.success("已复制");
  } catch {
    message.error("复制失败");
  }
}

function adminHeaders(): Record<string, string> {
  return adminToken ? { Authorization: `Bearer ${adminToken}` } : {};
}

function titleFor(key: string) {
  const titles: Record<string, string> = {
    overview: "概览",
    applications: "应用",
    routes: "路由策略",
    ip: "IP 策略",
    simulate: "策略模拟",
    resources: "资源",
    audit: "审计",
    features: "训练样本",
    models: "模型管理"
  };
  return titles[key] || "概览";
}

createRoot(document.getElementById("root")!).render(<App />);
