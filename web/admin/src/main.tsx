import {
  ApiOutlined,
  AuditOutlined,
  BarChartOutlined,
  DatabaseOutlined,
  ExperimentOutlined,
  ProjectOutlined,
  SafetyOutlined
} from "@ant-design/icons";
import { QueryClient, QueryClientProvider, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Button, Card, ConfigProvider, Form, Input, InputNumber, Layout, Menu, Modal, Select, Space, Statistic, Switch, Table, Tag } from "antd";
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

type ResourceFormValues = Omit<Resource, "id" | "metadata"> & {
  width?: number;
  height?: number;
  mime_type?: string;
  size_bytes?: number;
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
const resourceTypes = [
  "background_image",
  "slider_template",
  "rotate_template",
  "concat_template",
  "font",
  "icon",
  "degree_template",
  "curve_template",
  "gesture_template",
  "jigsaw_template",
  "pow_challenge"
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

function Resources() {
  const { data, isLoading } = useList<Resource>("resources", "/api/v1/admin/resources");
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm();
  const mutation = usePost<Resource>("resources");
  const columns: ColumnsType<Resource> = [
    { title: "类型", dataIndex: "resource_type" },
    { title: "验证码", dataIndex: "captcha_type" },
    { title: "来源", dataIndex: "storage_type" },
    { title: "场景", dataIndex: "scene", render: (value) => value || "-" },
    { title: "标签", dataIndex: "tag" },
    {
      title: "规格",
      render: (_, row) => {
        const width = row.metadata?.width;
        const height = row.metadata?.height;
        return width && height ? `${width}x${height}` : "-";
      }
    },
    { title: "状态", render: (_, row) => <Tag color={row.status === "active" ? "green" : "default"}>{row.status}</Tag> }
  ];
  return (
    <Card title="资源" extra={<Button type="primary" onClick={() => setOpen(true)}>新增</Button>}>
      <Table rowKey="id" loading={isLoading} columns={columns} dataSource={data || []} pagination={false} />
      <Modal title="新增资源" open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} okText="保存">
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            client_id: "demo",
            scene: "",
            captcha_type: "AUTO",
            resource_type: "background_image",
            storage_type: "embedded",
            tag: "default",
            status: "active"
          }}
          onFinish={async (values: ResourceFormValues) => {
            const { width, height, mime_type, size_bytes, ...resourceValues } = values;
            const metadata: Record<string, unknown> = {};
            if (width !== undefined) metadata.width = width;
            if (height !== undefined) metadata.height = height;
            if (mime_type) metadata.mime_type = mime_type;
            if (size_bytes !== undefined) metadata.size_bytes = size_bytes;
            const body = {
              ...resourceValues,
              metadata: Object.keys(metadata).length > 0 ? metadata : undefined
            };
            await mutation.mutateAsync({ path: "/api/v1/admin/resources", body });
            form.resetFields();
            setOpen(false);
          }}
        >
          <Form.Item name="client_id" label="Client ID" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="scene" label="场景"><Input /></Form.Item>
          <Form.Item name="captcha_type" label="验证码"><Select options={selectOptions(["AUTO", ...captchaTypes])} /></Form.Item>
          <Form.Item name="resource_type" label="资源类型" rules={[{ required: true }]}><Select options={selectOptions(resourceTypes)} /></Form.Item>
          <Form.Item name="storage_type" label="存储"><Select options={selectOptions(["embedded", "classpath", "file", "url", "object_storage", "database"])} /></Form.Item>
          <Form.Item name="uri" label="URI" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="tag" label="标签"><Input /></Form.Item>
          <Space.Compact block>
            <Form.Item name="width" label="宽" style={{ width: "50%" }}><InputNumber min={1} max={4096} style={{ width: "100%" }} /></Form.Item>
            <Form.Item name="height" label="高" style={{ width: "50%" }}><InputNumber min={1} max={4096} style={{ width: "100%" }} /></Form.Item>
          </Space.Compact>
          <Form.Item name="mime_type" label="MIME"><Input placeholder="image/png" /></Form.Item>
          <Form.Item name="size_bytes" label="大小"><InputNumber min={1} max={20971520} style={{ width: "100%" }} /></Form.Item>
          <Form.Item name="checksum" label="SHA-256"><Input /></Form.Item>
          <Form.Item name="status" label="状态"><Select options={selectOptions(["active", "disabled"])} /></Form.Item>
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
  return values.map((value) => ({ value, label: value }));
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
