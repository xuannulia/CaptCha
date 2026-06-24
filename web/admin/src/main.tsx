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
import { Badge, Button, Card, Checkbox, ConfigProvider, Form, Input, InputNumber, Layout, Menu, Modal, Select, Space, Statistic, Switch, Table, Tag } from "antd";
import type { ColumnsType } from "antd/es/table";
import React, { useMemo, useState } from "react";
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
};

type IpPolicy = {
  id: string;
  client_id: string;
  type: string;
  cidr: string;
  action: string;
  reason: string;
  enabled: boolean;
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
  gallery_type?: "background" | "rotate" | "grid" | "icon";
  category?: string;
  label?: string;
};

type AuditEvent = {
  id: string;
  scene: string;
  account_id_hash?: string;
  device_id_hash?: string;
  action: string;
  result: string;
  decision_reason: string;
  challenge_type: string;
};

type RiskFeatureSnapshot = {
  id: string;
  attempt_id: string;
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
  status: string;
  default_fail_policy: string;
};

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
  "PROOF_OF_WORK",
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
  PROOF_OF_WORK: "工作量验证",
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
  jigsaw_template: "拼图模板",
  pow_challenge: "工作量素材"
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
const optionLabels = { ...captchaLabels, ...resourceTypeLabels, ...storageLabels, ...statusLabels };
const resourceLibraryTitles: Record<string, string> = {
  background: "背景图库",
  rotate: "旋转校准图库",
  grid: "图片格子图库",
  icon: "图标图库",
  template: "系统模板",
  single: "单图资源"
};
const resourceFileFilters = [
  { key: "all", label: "全部文件" },
  { key: "background", label: "背景图库" },
  { key: "rotate", label: "旋转校准图库" },
  { key: "grid", label: "图片格子图库" },
  { key: "icon", label: "图标图库" }
];
const galleryUploadTypes = [
  { value: "background", label: "背景图库" },
  { value: "rotate", label: "旋转校准图库" },
  { value: "grid", label: "图片格子图库" },
  { value: "icon", label: "图标图库" }
];
const adminRoutes = [
  { key: "overview", path: "/overview", icon: <BarChartOutlined />, label: "概览", element: <Overview /> },
  { key: "applications", path: "/applications", icon: <ProjectOutlined />, label: "应用", element: <Applications /> },
  { key: "routes", path: "/routes", icon: <ApiOutlined />, label: "路由策略", element: <Routes /> },
  { key: "ip", path: "/ip-policies", icon: <SafetyOutlined />, label: "IP 策略", element: <IpPolicies /> },
  { key: "simulate", path: "/policy-simulate", icon: <SafetyOutlined />, label: "策略模拟", element: <PolicySimulator /> },
  { key: "resources", path: "/resources", icon: <DatabaseOutlined />, label: "资源", element: <Resources /> },
  { key: "audit", path: "/audit", icon: <AuditOutlined />, label: "审计", element: <Audit /> },
  { key: "features", path: "/risk-features", icon: <ExperimentOutlined />, label: "训练特征", element: <RiskFeatures /> },
  { key: "models", path: "/risk-models", icon: <ExperimentOutlined />, label: "模型版本", element: <RiskModels /> }
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

  return (
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
              <Space>
                <Badge status="success" text="运行中" />
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
  );
}

function Overview() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["metrics"],
    queryFn: async () => {
      const response = await fetch(`${apiBase}/api/v1/admin/metrics?limit=200`, { headers: adminHeaders() });
      if (!response.ok) throw new Error(response.statusText);
      return await response.json() as AdminMetrics;
    },
    refetchInterval: 15000
  });
  const totals = data?.totals;
  const recent = data?.recent;

  return (
    <div className="grid">
      <Card loading={isLoading}><Statistic title="验证通过率" value={recent?.pass_rate || 0} suffix="%" precision={1} /></Card>
      <Card loading={isLoading}><Statistic title="近期策略事件" value={recent?.audit_events || 0} /></Card>
      <Card loading={isLoading}><Statistic title="启用路由策略" value={totals?.enabled_route_policies || 0} /></Card>
      <Card loading={isLoading}><Statistic title="阻断请求" value={recent?.block || 0} /></Card>
      {error instanceof Error && <Card className="wide"><div className="error-line">{error.message}</div></Card>}
      <Card className="wide" title="运行状态" loading={isLoading}>
        <div className="kv-grid">
          <span>应用</span><strong>{totals ? `${totals.active_applications}/${totals.applications}` : "0/0"}</strong>
          <span>IP 策略</span><strong>{totals ? `${totals.enabled_ip_policies}/${totals.ip_policies}` : "0/0"}</strong>
          <span>资源</span><strong>{totals ? `${totals.active_captcha_resources}/${totals.captcha_resources}` : "0/0"}</strong>
          <span>训练</span><strong>{totals ? `${totals.trainable_risk_features}/${totals.risk_feature_snapshots}` : "0/0"}</strong>
          <span>模型</span><strong>{totals ? `${totals.active_risk_model_versions}/${totals.risk_model_versions}` : "0/0"}</strong>
          <span>配置</span><strong>{recent?.config_changes || 0}</strong>
        </div>
      </Card>
      <Card className="wide" title="验证码类型">
        <Space wrap>
          {captchaTypes.map((type) => <Tag key={type} color="green">{type} {data?.by_challenge_type[type] || 0}</Tag>)}
        </Space>
      </Card>
      <Card className="wide" title="高频场景" loading={isLoading}>
        <Space wrap>
          {(data?.top_scenes || []).map((item) => <Tag key={item.name} color="blue">{item.name} {item.count}</Tag>)}
          {(data?.top_reasons || []).map((item) => <Tag key={item.name}>{item.name} {item.count}</Tag>)}
        </Space>
      </Card>
      <Card className="wide" title="资源命中" loading={isLoading}>
        <Space wrap>
          {(data?.top_resources || []).map((item) => (
            <Tag key={item.id} color={item.failure_rate > 50 ? "red" : "purple"}>
              {item.id} {item.attempts}/{item.failure_rate.toFixed(1)}%
            </Tag>
          ))}
        </Space>
      </Card>
      <Card className="wide" title="训练标签" loading={isLoading}>
        <Space wrap>
          {Object.entries(data?.risk_labels || {}).map(([label, count]) => <Tag key={label}>{label} {count}</Tag>)}
          {Object.entries(data?.resource_statuses || {}).map(([status, count]) => <Tag key={status} color={status === "active" ? "green" : "default"}>{status} {count}</Tag>)}
        </Space>
      </Card>
    </div>
  );
}

function Applications() {
  const { data, isLoading } = useList<Application>("applications", "/api/v1/admin/applications");
  const [open, setOpen] = useState(false);
  const [secret, setSecret] = useState("");
  const [form] = Form.useForm();
  const mutation = usePost<Application>("applications");
  const secretMutation = usePost<{ client_secret: string; application: Application }>("applications");
  const columns: ColumnsType<Application> = [
    { title: "Client ID", dataIndex: "client_id" },
    { title: "名称", dataIndex: "name" },
    { title: "状态", render: (_, row) => <Tag color={row.status === "active" ? "green" : "default"}>{row.status}</Tag> },
    { title: "失败策略", dataIndex: "default_fail_policy" },
    {
      title: "密钥",
      width: 120,
      render: (_, row) => (
        <Button
          size="small"
          onClick={async () => {
            const result = await secretMutation.mutateAsync({
              path: `/api/v1/admin/applications/${encodeURIComponent(row.client_id)}/secret`,
              body: {}
            });
            setSecret(result.client_secret);
          }}
        >
          轮换
        </Button>
      )
    }
  ];
  return (
    <Card title="应用" extra={<Button type="primary" onClick={() => setOpen(true)}>新增</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal title="Client Secret" open={secret !== ""} onCancel={() => setSecret("")} onOk={() => setSecret("")} okText="关闭">
        <Input.TextArea readOnly value={secret} autoSize />
      </Modal>
      <Modal
        title="新增应用"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => form.submit()}
        okText="保存"
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ status: "active", default_fail_policy: "fail_open" }}
          onFinish={async (values) => {
            await mutation.mutateAsync({ path: "/api/v1/admin/applications", body: values });
            form.resetFields();
            setOpen(false);
          }}
        >
          <Form.Item name="client_id" label="Client ID" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="status" label="状态"><Select options={selectOptions(["active", "disabled"])} /></Form.Item>
          <Form.Item name="default_fail_policy" label="失败策略"><Select options={selectOptions(["fail_open", "fail_close"])} /></Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function Routes() {
  const { data, isLoading } = useList<RoutePolicy>("routes", "/api/v1/admin/route-policies");
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm();
  const mutation = usePost<RoutePolicy>("routes");
  const columns: ColumnsType<RoutePolicy> = [
    { title: "名称", dataIndex: "name" },
    { title: "路径", dataIndex: "path_pattern" },
    { title: "方法", dataIndex: "method", width: 90 },
    { title: "场景", dataIndex: "scene" },
    { title: "验证码", render: (_, row) => row.risk_challenge_type ? `${row.challenge_type}/${row.risk_challenge_type}` : row.challenge_type },
    { title: "升级", render: (_, row) => row.challenge_escalation?.length ? row.challenge_escalation.join(" > ") : "-" },
    { title: "模式", dataIndex: "mode" },
    { title: "灰度", render: (_, row) => `${row.rollout_percent || 100}%` },
    { title: "风险", render: (_, row) => `${row.risk_observe_score || 0}/${row.risk_challenge_score || 0}/${row.risk_block_score || 0}` },
    { title: "启用", render: (_, row) => <Switch checked={row.enabled} size="small" /> }
  ];
  return (
    <Card title="路由策略" extra={<Button type="primary" onClick={() => setOpen(true)}>新增</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal title="新增路由策略" open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} okText="保存">
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            client_id: "demo",
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
            const body = {
              ...values,
              rate_limit: values.rate_window_seconds && values.rate_max_requests
                ? { window_seconds: values.rate_window_seconds, max_requests: values.rate_max_requests, strategy: values.rate_strategy || "fixed_window" }
                : undefined
            };
            if (!body.challenge_escalation?.length) {
              delete body.challenge_escalation;
            }
            delete body.rate_window_seconds;
            delete body.rate_max_requests;
            delete body.rate_strategy;
            await mutation.mutateAsync({ path: "/api/v1/admin/route-policies", body });
            form.resetFields();
            setOpen(false);
          }}
        >
          <Form.Item name="client_id" label="Client ID" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="path_pattern" label="路径" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="method" label="方法"><Select options={selectOptions(["GET", "POST", "PUT", "DELETE", "PATCH"])} /></Form.Item>
          <Form.Item name="scene" label="场景" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="mode" label="模式"><Select options={selectOptions(["always", "risk_based", "rate_limit", "observe", "silent", "manual_bypass"])} /></Form.Item>
          <Form.Item name="challenge_type" label="验证码"><Select options={selectOptions(captchaTypes)} /></Form.Item>
          <Form.Item name="risk_challenge_type" label="风险验证码"><Select allowClear options={selectOptions(captchaTypes)} /></Form.Item>
          <Form.Item name="challenge_escalation" label="升级序列"><Select mode="multiple" allowClear options={selectOptions(captchaTypes)} /></Form.Item>
          <Form.Item name="fail_policy" label="失败策略"><Select options={selectOptions(["fail_open", "fail_close"])} /></Form.Item>
          <Form.Item name="priority" label="优先级"><InputNumber className="field-number" /></Form.Item>
          <Form.Item name="rollout_percent" label="灰度比例"><InputNumber className="field-number" min={1} max={100} addonAfter="%" /></Form.Item>
          <Form.Item name="token_ttl_seconds" label="Ticket TTL"><InputNumber className="field-number" /></Form.Item>
          <Form.Item name="risk_observe_score" label="观察分"><InputNumber className="field-number" min={0} max={100} /></Form.Item>
          <Form.Item name="risk_challenge_score" label="挑战分"><InputNumber className="field-number" min={0} max={100} /></Form.Item>
          <Form.Item name="risk_block_score" label="阻断分"><InputNumber className="field-number" min={0} max={100} /></Form.Item>
          <Form.Item name="rate_window_seconds" label="限流窗口"><InputNumber className="field-number" /></Form.Item>
          <Form.Item name="rate_max_requests" label="请求上限"><InputNumber className="field-number" /></Form.Item>
          <Form.Item name="rate_strategy" label="限流策略"><Select allowClear options={selectOptions(["fixed_window", "sliding_window", "token_bucket"])} /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function IpPolicies() {
  const { data, isLoading } = useList<IpPolicy>("ip-policies", "/api/v1/admin/ip-policies");
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm();
  const mutation = usePost<IpPolicy>("ip-policies");
  const columns: ColumnsType<IpPolicy> = [
    { title: "CIDR", dataIndex: "cidr" },
    { title: "动作", dataIndex: "action" },
    { title: "原因", dataIndex: "reason" },
    { title: "启用", render: (_, row) => <Switch checked={row.enabled} size="small" /> }
  ];
  return (
    <Card title="IP 策略" extra={<Button type="primary" onClick={() => setOpen(true)}>新增</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal title="新增 IP 策略" open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} okText="保存">
        <Form
          form={form}
          layout="vertical"
          initialValues={{ client_id: "demo", type: "blocklist", action: "block", enabled: true }}
          onFinish={async (values) => {
            await mutation.mutateAsync({ path: "/api/v1/admin/ip-policies", body: values });
            form.resetFields();
            setOpen(false);
          }}
        >
          <Form.Item name="client_id" label="Client ID" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="type" label="类型"><Select options={selectOptions(["allowlist", "blocklist"])} /></Form.Item>
          <Form.Item name="cidr" label="CIDR" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="action" label="动作"><Select options={selectOptions(["allow", "block", "challenge"])} /></Form.Item>
          <Form.Item name="reason" label="原因"><Input /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function PolicySimulator() {
  const [form] = Form.useForm();
  const mutation = usePost<PolicySimulation>("policy-simulate");
  const simulation = mutation.data;
  return (
    <Card title="策略模拟">
      <Form
        form={form}
        layout="inline"
        className="filters"
        initialValues={{ client_id: "demo", method: "POST", path: "/api/login" }}
        onFinish={(values) => mutation.mutate({ path: "/api/v1/admin/policy/simulate", body: values })}
      >
        <Form.Item name="client_id" label="Client ID" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="method" label="方法"><Select style={{ width: 110 }} options={selectOptions(["GET", "POST", "PUT", "DELETE", "PATCH"])} /></Form.Item>
        <Form.Item name="path" label="路径" rules={[{ required: true }]}><Input style={{ width: 180 }} /></Form.Item>
        <Form.Item name="scene" label="场景"><Input style={{ width: 120 }} /></Form.Item>
        <Form.Item name="ip" label="IP"><Input style={{ width: 150 }} /></Form.Item>
        <Form.Item name="account_id_hash" label="账号"><Input style={{ width: 150 }} /></Form.Item>
        <Form.Item name="device_id_hash" label="设备"><Input style={{ width: 150 }} /></Form.Item>
        <Form.Item name="resource_tag" label="资源"><Input style={{ width: 120 }} /></Form.Item>
        <Button type="primary" htmlType="submit" loading={mutation.isPending}>模拟</Button>
      </Form>
      {mutation.error instanceof Error && <div className="error-line">{mutation.error.message}</div>}
      {simulation && (
        <div className="simulation-result">
          <Space wrap>
            <Tag color={simulation.decision.action === "challenge" ? "orange" : simulation.decision.action === "block" ? "red" : simulation.decision.action === "observe" ? "blue" : "green"}>
              {simulation.decision.action}
            </Tag>
            <Tag>{simulation.decision.reason}</Tag>
            {simulation.decision.challenge_type && <Tag color="purple">{simulation.decision.challenge_type}</Tag>}
            <Tag color={simulation.rate_limit_evaluated ? "green" : "default"}>{simulation.rate_limit_evaluated ? "rate checked" : "rate dry-run"}</Tag>
          </Space>
          <div className="kv-grid">
            <span>Route</span><strong>{simulation.route?.name || simulation.route?.id || "-"}</strong>
            <span>Scene</span><strong>{simulation.decision.scene || simulation.route?.scene || "-"}</strong>
            <span>Mode</span><strong>{simulation.route?.mode || "-"}</strong>
            <span>Rollout</span><strong>{simulation.route ? `${simulation.route.rollout_percent || 100}%` : "-"}</strong>
            <span>TTL</span><strong>{simulation.decision.ttl_seconds || "-"}</strong>
          </div>
          <Space wrap>
            {simulation.side_effects.map((item) => <Tag key={item}>{item}</Tag>)}
            {(simulation.notes || []).map((item) => <Tag key={item} color="blue">{item}</Tag>)}
          </Space>
        </div>
      )}
    </Card>
  );
}

function resourceLibraryKey(row: Resource) {
  if (row.resource_type === "background_library") return "background";
  if (row.resource_type === "rotate_library") return "rotate";
  if (row.resource_type === "grid_category_library") return "grid";
  if (row.resource_type === "icon_library") return "icon";
  if (row.resource_type.endsWith("_template") || row.resource_type === "font" || row.resource_type === "pow_challenge") return "template";
  if (row.resource_type === "background_image" || row.resource_type === "icon") return "single";
  return "single";
}

function groupGalleryResources(resources: Resource[]) {
  const groups = new Map<string, { key: string; title: string; items: Resource[] }>();
  for (const row of resources) {
    const library = resourceLibraryKey(row);
    const category = resourceCategory(row);
    const title = library === "grid" && category
      ? `图片格子 / ${category}`
      : `${resourceLibraryTitle(library)} / ${captchaLabel(row.captcha_type || "AUTO")}`;
    const key = `${library}:${row.captcha_type || "AUTO"}:${category || row.tag || "default"}`;
    const group = groups.get(key) || { key, title, items: [] };
    group.items.push(row);
    groups.set(key, group);
  }
  return Array.from(groups.values()).sort((a, b) => a.title.localeCompare(b.title, "zh-Hans-CN"));
}

function resourceLibraryTitle(key: string) {
  return resourceLibraryTitles[key] || "资源";
}

function isPrimaryGalleryResource(row: Resource) {
  const key = resourceLibraryKey(row);
  return key === "background" || key === "rotate" || key === "grid" || key === "icon";
}

function countResourceFileFilters(resources: Resource[]) {
  return resources.reduce<Record<string, number>>((counts, row) => {
    const key = resourceLibraryKey(row);
    counts.all = (counts.all || 0) + 1;
    if (key === "background" || key === "rotate" || key === "grid" || key === "icon") {
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, { all: 0, background: 0, rotate: 0, grid: 0, icon: 0 });
}

function matchesResourceFileFilter(row: Resource, filter: string) {
  return filter === "all" || resourceLibraryKey(row) === filter;
}

function galleryUploadDefaults(galleryType?: string) {
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

function captchaLabel(value: string) {
  return captchaLabels[value] || value;
}

function resourceTypeLabel(value: string) {
  return resourceTypeLabels[value] || value;
}

function storageLabel(value: string) {
  return storageLabels[value] || value;
}

function statusLabel(value: string) {
  return statusLabels[value] || value;
}

function resourceCategory(row: Resource) {
  return metadataText(row, "label") || metadataText(row, "category");
}

function resourceTitle(row: Resource) {
  return resourceCategory(row) || resourceTypeLabel(row.resource_type);
}

function resourceDimensions(row: Resource) {
  const width = metadataText(row, "width");
  const height = metadataText(row, "height");
  return width && height ? `${width}x${height}` : "未声明尺寸";
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

function compactURI(uri: string) {
  if (!uri) return "-";
  if (uri.length <= 42) return uri;
  return `${uri.slice(0, 24)}...${uri.slice(-12)}`;
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

function ResourceTile({ row }: { row: Resource }) {
  const preview = resourcePreviewSrc(row);
  return (
    <article className="resource-tile">
      <div className="resource-thumb">
        {preview ? <img alt="" src={preview} /> : <span>{resourcePlaceholder(row)}</span>}
      </div>
      <div className="resource-tile-body">
        <div className="resource-tile-title">
          <strong>{resourceTitle(row)}</strong>
          <Tag color={row.status === "active" ? "green" : "default"}>{statusLabel(row.status)}</Tag>
        </div>
        <div className="resource-tile-meta">
          <span>{captchaLabel(row.captcha_type || "AUTO")}</span>
          <span>{storageLabel(row.storage_type)}</span>
          <span>{resourceDimensions(row)}</span>
        </div>
        <div className="resource-tile-meta">
          <span>{row.scene || "全场景"}</span>
          <span>{row.tag || "default"}</span>
        </div>
        <div className="resource-uri" title={row.uri}>{compactURI(row.uri)}</div>
      </div>
    </article>
  );
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
    </article>
  );
}

function Resources() {
  const { data, isLoading } = useList<Resource>("resources", "/api/v1/admin/resources");
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
        body: JSON.stringify({ ids })
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
  const resources = data || [];
  const galleryResources = useMemo(() => resources.filter(isPrimaryGalleryResource), [resources]);
  const visibleGalleryResources = useMemo(
    () => galleryResources.filter((item) => matchesResourceFileFilter(item, fileFilter)),
    [fileFilter, galleryResources]
  );
  const fileFilterCounts = useMemo(() => countResourceFileFilters(galleryResources), [galleryResources]);
  const systemResources = useMemo(() => resources.filter((item) => !isPrimaryGalleryResource(item)), [resources]);
  const visibleResourceIDs = useMemo(() => new Set(visibleGalleryResources.map((item) => item.id)), [visibleGalleryResources]);
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
    setDeleteOpen(true);
  };
  const uploadGalleryType = Form.useWatch("gallery_type", form) || "background";
  const openCreate = () => {
    form.resetFields();
    setSelectedFiles([]);
    setUploadError("");
    form.setFieldsValue({
      gallery_type: "background",
      category: "",
      label: ""
    });
    setOpen(true);
  };
  const columns: ColumnsType<Resource> = [
    { title: "图库", render: (_, row) => resourceTypeLabel(row.resource_type) },
    { title: "验证码类别", render: (_, row) => captchaLabel(row.captcha_type || "AUTO") },
    { title: "来源", render: (_, row) => storageLabel(row.storage_type) },
    { title: "场景", dataIndex: "scene", render: (value) => value || "-" },
    { title: "标签", dataIndex: "tag" },
    {
      title: "分类",
      render: (_, row) => {
        const category = row.metadata?.category;
        const label = row.metadata?.label;
        return category || label ? `${label || category}` : "-";
      }
    },
    {
      title: "规格",
      render: (_, row) => {
        const width = row.metadata?.width;
        const height = row.metadata?.height;
        return width && height ? `${width}x${height}` : "-";
      }
    },
    { title: "状态", render: (_, row) => <Tag color={row.status === "active" ? "green" : "default"}>{statusLabel(row.status)}</Tag> }
  ];
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
        <Button danger disabled={selectedGalleryCount === 0} loading={deleteMutation.isPending} onClick={deleteSelectedResources}>删除</Button>
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
      <details className="system-resource-panel">
        <summary>
          <span>系统资源</span>
          <strong>{systemResources.length} 条</strong>
        </summary>
        {isLoading ? (
          <div className="resource-gallery-empty">加载中</div>
        ) : systemResources.length === 0 ? (
          <div className="resource-gallery-empty">暂无系统资源</div>
        ) : (
          <div className="resource-gallery">
            {groupGalleryResources(systemResources).map((group) => (
              <section className="resource-library-section" key={group.key}>
                <div className="resource-library-heading">
                  <h3>{group.title}</h3>
                  <span>{group.items.length} 张</span>
                </div>
                <div className="resource-gallery-grid">
                  {group.items.map((row) => <ResourceTile key={row.id} row={row} />)}
                </div>
              </section>
            ))}
          </div>
        )}
      </details>
      <details className="resource-table-wrap">
        <summary>明细列表</summary>
        <Table rowKey="id" loading={isLoading} columns={columns} dataSource={resources} pagination={false} size="small" />
      </details>
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
            gallery_type: "background",
            category: "",
            label: ""
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
            formData.set("client_id", "demo");
            formData.set("scene", "");
            formData.set("captcha_type", defaults.captchaType);
            formData.set("resource_type", defaults.resourceType);
            formData.set("tag", defaults.tag);
            formData.set("status", "active");
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
          <Form.Item name="gallery_type" label="图库" rules={[{ required: true }]}>
            <Select options={galleryUploadTypes} />
          </Form.Item>
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
  const [filters, setFilters] = useState({ action: "", result: "", scene: "", account_id_hash: "", device_id_hash: "" });
  const [pageState, setPageState] = useState({ page: 1, pageSize: 20 });
  const [form] = Form.useForm();
  const path = useMemo(() => {
    const params = new URLSearchParams({
      limit: String(pageState.pageSize),
      offset: String((pageState.page - 1) * pageState.pageSize)
    });
    if (filters.scene) params.set("scene", filters.scene);
    if (filters.action) params.set("action", filters.action);
    if (filters.result) params.set("result", filters.result);
    if (filters.account_id_hash) params.set("account_id_hash", filters.account_id_hash);
    if (filters.device_id_hash) params.set("device_id_hash", filters.device_id_hash);
    return `/api/v1/admin/audit-events?${params.toString()}`;
  }, [filters, pageState.page, pageState.pageSize]);
  const { data, isLoading } = usePagedList<AuditEvent>("audit", path);
  const rows = data?.items || [];
  const total = (pageState.page - 1) * pageState.pageSize + rows.length + (data?.has_more ? 1 : 0);
  const columns: ColumnsType<AuditEvent> = [
    { title: "场景", dataIndex: "scene" },
    { title: "账号", dataIndex: "account_id_hash" },
    { title: "设备", dataIndex: "device_id_hash" },
    { title: "动作", dataIndex: "action" },
    { title: "验证码", dataIndex: "challenge_type" },
    { title: "结果", dataIndex: "result" },
    { title: "原因", dataIndex: "decision_reason" }
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
            account_id_hash: values.account_id_hash || "",
            device_id_hash: values.device_id_hash || ""
          });
          setPageState((prev) => ({ ...prev, page: 1 }));
        }}
        onReset={() => {
          form.resetFields();
          setFilters({ action: "", result: "", scene: "", account_id_hash: "", device_id_hash: "" });
          setPageState((prev) => ({ ...prev, page: 1 }));
        }}
      >
        <Form.Item name="scene" label="场景"><Input placeholder="login" /></Form.Item>
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
  const [filters, setFilters] = useState({ challenge_type: "", label: "", model_trainable: "", scene: "" });
  const [pageState, setPageState] = useState({ page: 1, pageSize: 20 });
  const [exporting, setExporting] = useState(false);
  const [form] = Form.useForm();
  const path = useMemo(() => {
    const params = new URLSearchParams({
      limit: String(pageState.pageSize),
      offset: String((pageState.page - 1) * pageState.pageSize)
    });
    if (filters.scene) params.set("scene", filters.scene);
    if (filters.challenge_type) params.set("challenge_type", filters.challenge_type);
    if (filters.label) params.set("label", filters.label);
    if (filters.model_trainable) params.set("model_trainable", filters.model_trainable);
    return `/api/v1/admin/risk-feature-snapshots?${params.toString()}`;
  }, [filters, pageState.page, pageState.pageSize]);
  const { data, isLoading } = usePagedList<RiskFeatureSnapshot>("risk-features", path);
  const rows = data?.items || [];
  const total = (pageState.page - 1) * pageState.pageSize + rows.length + (data?.has_more ? 1 : 0);
  const mutation = usePost<RiskFeatureSnapshot>("risk-features");
  const exportTrainingData = async () => {
    const params = new URLSearchParams({ limit: "1000" });
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
    } finally {
      setExporting(false);
    }
  };
  const updateLabel = (row: RiskFeatureSnapshot, label: string, modelTrainable: boolean) => {
    mutation.mutate({
      path: `/api/v1/admin/risk-feature-snapshots/${row.id}/label`,
      body: {
        label,
        label_source: label === "unknown" ? "" : "manual_review",
        model_trainable: modelTrainable
      }
    });
  };
  const columns: ColumnsType<RiskFeatureSnapshot> = [
    { title: "会话", dataIndex: "attempt_id" },
    { title: "场景", dataIndex: "scene" },
    { title: "验证码", dataIndex: "challenge_type" },
    { title: "标签", dataIndex: "label" },
    { title: "版本", dataIndex: "feature_version" },
    { title: "训练", render: (_, row) => <Tag color={row.model_trainable ? "green" : "default"}>{row.model_trainable ? "ready" : "candidate"}</Tag> },
    {
      title: "操作",
      render: (_, row) => (
        <Space>
          <Button size="small" onClick={() => updateLabel(row, "confirmed_human", true)}>标人</Button>
          <Button size="small" onClick={() => updateLabel(row, "confirmed_bot", true)}>标机</Button>
          <Button size="small" onClick={() => updateLabel(row, "unknown", false)}>重置</Button>
        </Space>
      )
    }
  ];
  return (
    <Card title="训练特征" extra={<Button onClick={exportTrainingData} loading={exporting}>导出 JSONL</Button>}>
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
        <Form.Item name="model_trainable" label="训练"><Select allowClear style={{ width: 130 }} options={[{ value: "true", label: "ready" }, { value: "false", label: "candidate" }]} /></Form.Item>
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
  const [form] = Form.useForm();
  const mutation = usePost<RiskModelVersion>("risk-models");
  const actionMutation = usePost<RiskModelVersion>("risk-models");
  const columns: ColumnsType<RiskModelVersion> = [
    { title: "名称", dataIndex: "name" },
    { title: "版本", dataIndex: "version" },
    { title: "特征", dataIndex: "feature_version" },
    { title: "窗口", dataIndex: "training_window" },
    { title: "模式", render: (_, row) => <Tag color={row.mode === "enforce" ? "red" : row.mode === "observe" ? "blue" : "default"}>{row.mode}</Tag> },
    { title: "状态", render: (_, row) => <Tag color={row.status === "active" ? "green" : row.status === "rolled_back" ? "orange" : "default"}>{row.status}</Tag> },
    {
      title: "操作",
      render: (_, row) => (
        <Space>
          <Button size="small" disabled={row.status === "active"} onClick={() => actionMutation.mutate({ path: `/api/v1/admin/risk-model-versions/${row.id}/activate`, body: {} })}>激活</Button>
          <Button size="small" disabled={row.status !== "active"} onClick={() => actionMutation.mutate({ path: `/api/v1/admin/risk-model-versions/${row.id}/rollback`, body: {} })}>回滚</Button>
        </Space>
      )
    }
  ];
  return (
    <Card title="模型版本" extra={<Button type="primary" onClick={() => setOpen(true)}>登记</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal title="登记模型版本" open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} okText="保存">
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            name: "track-baseline",
            feature_version: "track-v1",
            mode: "shadow",
            status: "candidate"
          }}
          onFinish={async (values) => {
            const metrics: Record<string, unknown> = {};
            if (values.auc !== undefined) metrics.auc = values.auc;
            if (values.false_positive_rate !== undefined) metrics.false_positive_rate = values.false_positive_rate;
            const { auc, false_positive_rate, ...body } = values;
            await mutation.mutateAsync({
              path: "/api/v1/admin/risk-model-versions",
              body: { ...body, metrics: Object.keys(metrics).length > 0 ? metrics : undefined }
            });
            form.resetFields();
            setOpen(false);
          }}
        >
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="version" label="版本" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="feature_version" label="特征版本" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="training_window" label="训练窗口" rules={[{ required: true }]}><Input placeholder="2026-06-01/2026-06-20" /></Form.Item>
          <Form.Item name="artifact_uri" label="Artifact URI" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="mode" label="模式"><Select options={selectOptions(["shadow", "observe", "enforce"])} /></Form.Item>
          <Form.Item name="status" label="状态"><Select options={selectOptions(["candidate", "retired", "rolled_back"])} /></Form.Item>
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
    features: "训练特征",
    models: "模型版本"
  };
  return titles[key] || "概览";
}

createRoot(document.getElementById("root")!).render(<App />);
