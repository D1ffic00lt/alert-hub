import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  FormEvent,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useLocation, useNavigate as useRouterNavigate } from "react-router-dom";

import {
  applicationServerKeyMatches,
  blockedPermissionHelp,
  currentPushClientEnvironment,
  currentPushDeviceName,
  decodeApplicationServerKey,
  withPushTimeout,
} from "./push";

const API_BASE = "/api/v1";
const AppNameContext = createContext("Alert Hub");
let memoryAccessToken: string | null = null;
let memorySessionId: string | null = null;
let memoryAccessExpiresAt = 0;
let refreshInFlight: Promise<boolean> | null = null;
let authGeneration = 0;
let refreshBlocked = false;
let bootstrapSuggested = false;
let demoModeActive = false;
let offlineReadOnlyActive = false;
const verifiedPeerBases = new Set<string>();
const SESSION_EXPIRED_EVENT = "alert-hub:session-expired";
const SESSION_RESTORED_EVENT = "alert-hub:session-restored";
const SESSION_HINT_KEY = "alert-hub-session-partition-v1";
const LOGOUT_TOMBSTONE_KEY = "alert-hub-local-logout-v1";
const AUTH_BROADCAST_CHANNEL = "alert-hub-auth-v1";
const SESSION_HINT_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

class PushSetupCancelledError extends Error {
  constructor() {
    super("Push setup was cancelled because the active session changed.");
    this.name = "PushSetupCancelledError";
  }
}

type Severity = "critical" | "warning" | "info" | "unknown";
type IncidentStatus = "open" | "acknowledged" | "resolved" | "silenced";
type Health = "healthy" | "degraded" | "offline" | "paused" | "unknown" | "not_exercised";

type IncidentEvent = {
  id: string;
  type: string;
  label: string;
  detail: string;
  at: string;
  node: string;
  actor?: string;
};

type Incident = {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  source: string;
  region: string;
  target: string;
  startsAt: string;
  lastEventAt: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  events: IncidentEvent[];
};

type ClusterNode = {
  id: string;
  name: string;
  city: string;
  region: string;
  health: Health;
  version: string;
  syncLag: number | null;
  queue: number | null;
  lastSeen: string;
  roles: string[];
  publicApiUrl: string | null;
};

type Source = {
  id: string;
  name: string;
  kind: "alertmanager" | "generic_json" | "heartbeat";
  region: string;
  enabled: boolean;
  health: Health;
  lastEvent: string;
  events24h: number | null;
  allowedCidrs: string[];
};

type SourceCredential = {
  id: string;
  kind: Source["kind"];
  token: string;
  webhookUrl: string;
  example: string;
};

type Channel = {
  id: string;
  name: string;
  kind: "web_push" | "telegram" | "smtp" | "generic_webhook";
  health: Health;
  enabled: boolean;
  delivered24h: number;
  deliveryAttempts24h: number;
  successRate: number | null;
  eligible: string;
  eligibleRegions: string[];
  eligibleNodeIds: string[];
  configuredFields: string[];
  configAvailable: boolean;
};

type NotificationRoute = {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  sourceFilter: string[];
  severityFilter: string[];
  labelMatchers: Array<{ name: string; operator: string; value: string }>;
  channelIds: string[];
  continueMatching: boolean;
};

type PrometheusDatasource = {
  id: string;
  name: string;
  url: string;
  nodeId: string | null;
  region: string | null;
  enabled: boolean;
  authType: "none" | "bearer" | "basic" | "unknown";
  credentialsConfigured: boolean;
  credentialsAvailable: boolean;
};

type Device = {
  id: string;
  name: string;
  platform: string;
  current: boolean;
  push: boolean;
  lastUsed: string;
  location: string;
};

type AuditItem = {
  id: string;
  action: string;
  actionCode?: string;
  detail: string;
  actor: string;
  node: string;
  at: string;
  tone: "neutral" | "success" | "warning" | "danger";
  raw?: Record<string, unknown>;
};

type AuditGroup = AuditItem & {
  count: number;
  oldestAt: string;
};

type ReachabilityCell = {
  source: string;
  target: string;
  success: boolean;
  latency: number | null;
  checkedAt: string;
  datasourceId?: string | null;
  datasourceName?: string | null;
};

type ReachabilityMeta = {
  status: "ok" | "partial" | "unavailable" | "empty" | "not_configured" | "unknown";
  detail: string;
  datasources: number | null;
  errors: Array<{ datasourceId: string; datasourceName: string; code: string; detail: string }>;
};

type ClusterMeta = {
  cursor: Record<string, number>;
  eventCount: number | null;
};

type FixedMetricSample = {
  datasourceId: string;
  datasourceName: string;
  metric: Record<string, string>;
  value: number;
  timestamp: string;
};

type FixedMetricResult = {
  status: "ok" | "partial" | "unavailable" | "not_configured" | "unknown";
  datasources: number | null;
  samples: FixedMetricSample[];
  errors: Array<{ datasourceId: string; datasourceName: string; code: string; detail: string }>;
};

type FixedMetricPanels = {
  firingAlerts: FixedMetricResult;
  keyJobsUp: FixedMetricResult;
  alertHubHealth: FixedMetricResult;
};

type HubSummary = {
  open: number;
  acknowledged: number;
  critical: number;
  deliveryRate: number | null;
  deliveries24h: number | null;
  deliverySuccess24h: number | null;
  outboxPending: number | null;
  channelsEnabled: number | null;
  grafanaUrl: string | null;
};

type HubData = {
  incidents: Incident[];
  nodes: ClusterNode[];
  sources: Source[];
  channels: Channel[];
  routes: NotificationRoute[];
  datasources: PrometheusDatasource[];
  devices: Device[];
  audit: AuditItem[];
  // This is the exclusive offset consumed from one coherent server ordering.
  // It must not be inferred from the de-duplicated client-side row count.
  auditNextOffset: number;
  auditTotal: number;
  reachability: ReachabilityCell[];
  reachabilityMeta: ReachabilityMeta;
  clusterMeta: ClusterMeta;
  fixedMetrics: FixedMetricPanels;
  summary: HubSummary;
};

type DataMode = "demo" | "live" | "cached";

const EMPTY_DATA: HubData = {
  incidents: [],
  nodes: [],
  sources: [],
  channels: [],
  routes: [],
  datasources: [],
  devices: [],
  audit: [],
  auditNextOffset: 0,
  auditTotal: 0,
  reachability: [],
  reachabilityMeta: { status: "unknown", detail: "", datasources: null, errors: [] },
  clusterMeta: { cursor: {}, eventCount: null },
  fixedMetrics: {
    firingAlerts: { status: "unknown", datasources: null, samples: [], errors: [] },
    keyJobsUp: { status: "unknown", datasources: null, samples: [], errors: [] },
    alertHubHealth: { status: "unknown", datasources: null, samples: [], errors: [] },
  },
  summary: {
    open: 0,
    acknowledged: 0,
    critical: 0,
    deliveryRate: null,
    deliveries24h: null,
    deliverySuccess24h: null,
    outboxPending: null,
    channelsEnabled: null,
    grafanaUrl: null,
  },
};

const timelineA: IncidentEvent[] = [
  {
    id: "evt-a4",
    type: "delivery_succeeded",
    label: "Push delivered",
    detail: "Primary delivery owner eu-nl-01 completed on attempt 1.",
    at: "2026-09-01T12:44:11Z",
    node: "eu-nl-01",
  },
  {
    id: "evt-a3",
    type: "replicated",
    label: "Replicated to 3 nodes",
    detail: "Cluster event converged; vector cursors match for this incident.",
    at: "2026-09-01T12:44:08Z",
    node: "ru-msk-01",
  },
  {
    id: "evt-a2",
    type: "firing",
    label: "Threshold still exceeded",
    detail: "p95 latency 2.84 s for 5 consecutive minutes.",
    at: "2026-09-01T12:44:02Z",
    node: "eu-nl-01",
  },
  {
    id: "evt-a1",
    type: "firing",
    label: "Incident opened",
    detail: "Alertmanager normalized a firing event from prometheus-nl.",
    at: "2026-09-01T12:39:02Z",
    node: "eu-nl-01",
  },
];

const DEMO_DATA: HubData = {
  incidents: [
    {
      id: "inc-01J7ZQ4K8W8AWMRV77B9",
      title: "Core API latency breach",
      description: "Checkout API p95 is above 2.5 s from two probe regions.",
      severity: "critical",
      status: "open",
      source: "Prometheus EU",
      region: "NL",
      target: "api-core",
      startsAt: "2026-09-01T12:39:02Z",
      lastEventAt: "2026-09-01T12:44:11Z",
      labels: {
        alertname: "ApiLatencyHigh",
        source_region: "nl",
        target_region: "global",
        target_name: "api-core",
        service: "checkout",
      },
      annotations: {
        summary: "Checkout API p95 latency exceeds SLO",
        runbook_url: "https://runbooks.example.net/api-latency",
      },
      events: timelineA,
    },
    {
      id: "inc-01J7ZNRQBGCQKD0NN06T",
      title: "VLESS endpoint unreachable",
      description: "nl-edge-02 is unreachable from the Moscow probe node.",
      severity: "critical",
      status: "acknowledged",
      source: "Blackbox RU",
      region: "RU",
      target: "nl-edge-02",
      startsAt: "2026-09-01T12:31:25Z",
      lastEventAt: "2026-09-01T12:42:52Z",
      labels: {
        alertname: "VlessEndpointUnreachable",
        source_region: "ru",
        target_region: "eu",
        target_name: "nl-edge-02",
      },
      annotations: { summary: "Probe failed from ru-msk-01" },
      events: [
        {
          id: "evt-b3",
          type: "acknowledged",
          label: "Acknowledged by operator",
          detail: "Investigating upstream route changes.",
          at: "2026-09-01T12:42:52Z",
          node: "ru-msk-01",
          actor: "ops@local",
        },
        {
          id: "evt-b2",
          type: "delivery_succeeded",
          label: "Telegram delivered",
          detail: "EU-only delivery policy selected eu-de-01.",
          at: "2026-09-01T12:31:34Z",
          node: "eu-de-01",
        },
        {
          id: "evt-b1",
          type: "firing",
          label: "Incident opened",
          detail: "probe_success returned 0 from ru-msk-01.",
          at: "2026-09-01T12:31:25Z",
          node: "ru-msk-01",
        },
      ],
    },
    {
      id: "inc-01J7ZHW5D6W2C66RJ2EM",
      title: "TLS certificate expires in 12 days",
      description: "portal.example.net certificate is inside the warning window.",
      severity: "warning",
      status: "open",
      source: "Prometheus DE",
      region: "DE",
      target: "portal.example.net",
      startsAt: "2026-09-01T11:58:00Z",
      lastEventAt: "2026-09-01T12:38:00Z",
      labels: {
        alertname: "TlsCertificateExpiringSoon",
        source_region: "de",
        target_name: "portal.example.net",
      },
      annotations: { summary: "Certificate validity below 14 days" },
      events: [
        {
          id: "evt-c1",
          type: "firing",
          label: "Incident opened",
          detail: "Certificate has 12.4 days remaining.",
          at: "2026-09-01T11:58:00Z",
          node: "eu-de-01",
        },
      ],
    },
    {
      id: "inc-01J7Z9P2ZVM3A1NNDKWB",
      title: "Peer sync lag recovered",
      description: "eu-de-01 caught up after a transient WireGuard interruption.",
      severity: "info",
      status: "resolved",
      source: "Alert Hub health",
      region: "DE",
      target: "eu-de-01",
      startsAt: "2026-09-01T10:42:00Z",
      lastEventAt: "2026-09-01T11:07:19Z",
      labels: {
        alertname: "PeerSyncLagHigh",
        source_region: "nl",
        target_name: "eu-de-01",
      },
      annotations: { summary: "Peer recovered without manual action" },
      events: [
        {
          id: "evt-d2",
          type: "resolved",
          label: "Incident resolved",
          detail: "Sync lag returned below 5 seconds.",
          at: "2026-09-01T11:07:19Z",
          node: "eu-nl-01",
        },
        {
          id: "evt-d1",
          type: "firing",
          label: "Incident opened",
          detail: "Peer cursor lag reached 184 seconds.",
          at: "2026-09-01T10:42:00Z",
          node: "eu-nl-01",
        },
      ],
    },
  ],
  nodes: [
    {
      id: "node-ru-01",
      name: "ru-msk-01",
      city: "Moscow",
      region: "RU",
      health: "healthy",
      version: "v0.3.0",
      syncLag: 0.8,
      queue: 0,
      lastSeen: "2026-09-01T12:45:20Z",
      roles: ["ingest", "notify", "sync", "ui"],
      publicApiUrl: "https://ru.demo.invalid",
    },
    {
      id: "node-nl-01",
      name: "eu-nl-01",
      city: "Amsterdam",
      region: "NL",
      health: "healthy",
      version: "v0.3.0",
      syncLag: 1.2,
      queue: 1,
      lastSeen: "2026-09-01T12:45:20Z",
      roles: ["ingest", "notify", "sync", "ui"],
      publicApiUrl: "https://nl.demo.invalid",
    },
    {
      id: "node-de-01",
      name: "eu-de-01",
      city: "Frankfurt",
      region: "DE",
      health: "degraded",
      version: "v0.3.0",
      syncLag: 12.4,
      queue: 3,
      lastSeen: "2026-09-01T12:45:08Z",
      roles: ["ingest", "notify", "sync", "ui"],
      publicApiUrl: "https://de.demo.invalid",
    },
  ],
  sources: [
    {
      id: "src-am-nl",
      name: "Prometheus EU",
      kind: "alertmanager",
      region: "NL",
      enabled: true,
      health: "healthy",
      lastEvent: "2026-09-01T12:44:02Z",
      events24h: 186,
      allowedCidrs: [],
    },
    {
      id: "src-am-ru",
      name: "Blackbox RU",
      kind: "alertmanager",
      region: "RU",
      enabled: true,
      health: "healthy",
      lastEvent: "2026-09-01T12:31:25Z",
      events24h: 92,
      allowedCidrs: [],
    },
    {
      id: "src-heart-de",
      name: "Billing heartbeat",
      kind: "heartbeat",
      region: "DE",
      enabled: true,
      health: "degraded",
      lastEvent: "2026-09-01T12:40:04Z",
      events24h: 1438,
      allowedCidrs: [],
    },
    {
      id: "src-deploy",
      name: "Deploy events",
      kind: "generic_json",
      region: "Global",
      enabled: false,
      health: "paused",
      lastEvent: "2026-08-28T17:02:11Z",
      events24h: 0,
      allowedCidrs: [],
    },
  ],
  channels: [
    {
      id: "ch-push",
      name: "Operator Web Push",
      kind: "web_push",
      health: "healthy",
      enabled: true,
      delivered24h: 48,
      deliveryAttempts24h: 49,
      successRate: 98.7,
      eligible: "All nodes",
      eligibleRegions: [],
      eligibleNodeIds: [],
      configuredFields: [],
      configAvailable: true,
    },
    {
      id: "ch-tg",
      name: "EU on-call Telegram",
      kind: "telegram",
      health: "healthy",
      enabled: true,
      delivered24h: 16,
      deliveryAttempts24h: 16,
      successRate: 100,
      eligible: "NL, DE",
      eligibleRegions: ["NL", "DE"],
      eligibleNodeIds: [],
      configuredFields: ["bot_token", "chat_id"],
      configAvailable: true,
    },
    {
      id: "ch-mail",
      name: "Incident digest",
      kind: "smtp",
      health: "degraded",
      enabled: true,
      delivered24h: 7,
      deliveryAttempts24h: 8,
      successRate: 92.1,
      eligible: "All nodes",
      eligibleRegions: [],
      eligibleNodeIds: [],
      configuredFields: ["host", "port", "from", "to", "tls"],
      configAvailable: true,
    },
    {
      id: "ch-hook",
      name: "Ticketing webhook",
      kind: "generic_webhook",
      health: "paused",
      enabled: false,
      delivered24h: 0,
      deliveryAttempts24h: 0,
      successRate: null,
      eligible: "NL only",
      eligibleRegions: ["NL"],
      eligibleNodeIds: [],
      configuredFields: ["url", "hmac_secret"],
      configAvailable: true,
    },
  ],
  routes: [
    {
      id: "route-demo-critical",
      name: "Critical fan-out",
      enabled: true,
      priority: 10,
      sourceFilter: [],
      severityFilter: ["critical"],
      labelMatchers: [],
      channelIds: ["ch-push", "ch-tg"],
      continueMatching: false,
    },
  ],
  datasources: [
    {
      id: "prom-demo",
      name: "Demo Prometheus",
      url: "https://prometheus.demo.invalid",
      nodeId: null,
      region: "DEMO",
      enabled: true,
      authType: "none",
      credentialsConfigured: false,
      credentialsAvailable: true,
    },
  ],
  devices: [
    {
      id: "dev-iphone",
      name: "Dmitry’s iPhone",
      platform: "iOS PWA · Safari",
      current: true,
      push: true,
      lastUsed: "2026-09-01T12:45:20Z",
      location: "Moscow, RU",
    },
    {
      id: "dev-mac",
      name: "Operations MacBook",
      platform: "macOS · Chrome",
      current: false,
      push: true,
      lastUsed: "2026-09-01T09:13:08Z",
      location: "Moscow, RU",
    },
    {
      id: "dev-ipad",
      name: "On-call iPad",
      platform: "iPadOS PWA · Safari",
      current: false,
      push: false,
      lastUsed: "2026-08-29T18:21:42Z",
      location: "Amsterdam, NL",
    },
  ],
  audit: [
    {
      id: "aud-1",
      action: "Incident acknowledged",
      detail: "VLESS endpoint unreachable · investigation started",
      actor: "ops@local",
      node: "ru-msk-01",
      at: "2026-09-01T12:42:52Z",
      tone: "warning",
    },
    {
      id: "aud-2",
      action: "Delivery failover",
      detail: "Telegram delivery moved from eu-nl-01 to eu-de-01",
      actor: "system",
      node: "eu-de-01",
      at: "2026-09-01T12:31:34Z",
      tone: "success",
    },
    {
      id: "aud-3",
      action: "Source configuration changed",
      detail: "Billing heartbeat grace period changed from 60s to 90s",
      actor: "ops@local",
      node: "eu-nl-01",
      at: "2026-09-01T11:28:02Z",
      tone: "neutral",
    },
    {
      id: "aud-4",
      action: "Peer connection restored",
      detail: "eu-de-01 completed resync; 286 events applied",
      actor: "system",
      node: "eu-de-01",
      at: "2026-09-01T11:07:19Z",
      tone: "success",
    },
    {
      id: "aud-5",
      action: "Channel test failed",
      detail: "SMTP provider returned 451; retry queued",
      actor: "ops@local",
      node: "ru-msk-01",
      at: "2026-09-01T09:44:38Z",
      tone: "danger",
    },
  ],
  auditNextOffset: 5,
  auditTotal: 5,
  reachability: [
    {
      source: "Moscow",
      target: "api-core",
      success: true,
      latency: 182,
      checkedAt: "2026-09-01T12:45:18Z",
    },
    {
      source: "Moscow",
      target: "nl-edge-02",
      success: false,
      latency: null,
      checkedAt: "2026-09-01T12:45:16Z",
    },
    {
      source: "Moscow",
      target: "portal",
      success: true,
      latency: 211,
      checkedAt: "2026-09-01T12:45:17Z",
    },
    {
      source: "Moscow",
      target: "billing",
      success: true,
      latency: 238,
      checkedAt: "2026-09-01T12:45:14Z",
    },
    {
      source: "Amsterdam",
      target: "api-core",
      success: true,
      latency: 44,
      checkedAt: "2026-09-01T12:45:19Z",
    },
    {
      source: "Amsterdam",
      target: "nl-edge-02",
      success: true,
      latency: 18,
      checkedAt: "2026-09-01T12:45:19Z",
    },
    {
      source: "Amsterdam",
      target: "portal",
      success: true,
      latency: 26,
      checkedAt: "2026-09-01T12:45:18Z",
    },
    {
      source: "Amsterdam",
      target: "billing",
      success: true,
      latency: 73,
      checkedAt: "2026-09-01T12:45:16Z",
    },
    {
      source: "Frankfurt",
      target: "api-core",
      success: true,
      latency: 61,
      checkedAt: "2026-09-01T12:45:08Z",
    },
    {
      source: "Frankfurt",
      target: "nl-edge-02",
      success: true,
      latency: 33,
      checkedAt: "2026-09-01T12:45:08Z",
    },
    {
      source: "Frankfurt",
      target: "portal",
      success: true,
      latency: 17,
      checkedAt: "2026-09-01T12:45:07Z",
    },
    {
      source: "Frankfurt",
      target: "billing",
      success: false,
      latency: null,
      checkedAt: "2026-09-01T12:45:04Z",
    },
  ],
  reachabilityMeta: {
    status: "ok",
    detail: "Demo reachability fixture",
    datasources: 1,
    errors: [],
  },
  clusterMeta: {
    cursor: { "node-ru-01": 1520, "node-nl-01": 1509, "node-de-01": 1498 },
    eventCount: 4527,
  },
  fixedMetrics: {
    firingAlerts: {
      status: "ok",
      datasources: 1,
      samples: [
        {
          datasourceId: "prom-demo",
          datasourceName: "Demo Prometheus",
          metric: { alertname: "CheckoutLatency", severity: "critical" },
          value: 1,
          timestamp: "2026-09-01T12:45:20Z",
        },
      ],
      errors: [],
    },
    keyJobsUp: {
      status: "ok",
      datasources: 1,
      samples: [
        {
          datasourceId: "prom-demo",
          datasourceName: "Demo Prometheus",
          metric: { instance: "prometheus:9090", job: "prometheus" },
          value: 1,
          timestamp: "2026-09-01T12:45:20Z",
        },
        {
          datasourceId: "prom-demo",
          datasourceName: "Demo Prometheus",
          metric: { instance: "alertmanager:9093", job: "alertmanager" },
          value: 1,
          timestamp: "2026-09-01T12:45:20Z",
        },
      ],
      errors: [],
    },
    alertHubHealth: {
      status: "ok",
      datasources: 1,
      samples: [
        {
          datasourceId: "prom-demo",
          datasourceName: "Demo Prometheus",
          metric: { instance: "alert-hub:8000", job: "alert-hub" },
          value: 1,
          timestamp: "2026-09-01T12:45:20Z",
        },
      ],
      errors: [],
    },
  },
  summary: {
    open: 2,
    acknowledged: 1,
    critical: 2,
    deliveryRate: 98.7,
    deliveries24h: 71,
    deliverySuccess24h: 70,
    outboxPending: 1,
    channelsEnabled: 3,
    grafanaUrl: null,
  },
};

const NAV_ITEMS = [
  { id: "overview", label: "Overview", path: "/", icon: "◫" },
  { id: "incidents", label: "Incidents", path: "/incidents", icon: "!" },
  { id: "reachability", label: "Regional reachability", path: "/reachability", icon: "∿" },
  { id: "sources", label: "Sources", path: "/sources", icon: "→" },
  { id: "channels", label: "Channels", path: "/channels", icon: "≫" },
  { id: "devices", label: "Devices", path: "/devices", icon: "▣" },
  { id: "cluster", label: "Cluster", path: "/cluster", icon: "⌘" },
  { id: "audit", label: "Audit log", path: "/audit", icon: "≡" },
  { id: "settings", label: "Settings", path: "/settings", icon: "⚙" },
] as const;

type RouteId = (typeof NAV_ITEMS)[number]["id"] | "incident";

function titleCase(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatRelative(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || "Never";
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${Math.max(1, seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function formatDate(value: string, includeDate = false) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || "—";
  return (
    new Intl.DateTimeFormat("en-GB", {
      ...(includeDate ? { day: "2-digit", month: "short" } : {}),
      hour: "2-digit",
      minute: "2-digit",
      second: includeDate ? undefined : "2-digit",
      hour12: false,
      timeZone: "UTC",
    }).format(date) + " UTC"
  );
}

function formatDay(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Audit trail";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  }).format(date);
}

function compactId(value: string) {
  return value.length > 18 ? `${value.slice(0, 9)}…${value.slice(-5)}` : value;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

const GENERIC_JSON_SCHEMA_EXAMPLE = JSON.stringify(
  {
    schema_version: 1,
    external_event_id: "deploy-2026-09-02T10:15:00Z",
    dedup_key: "checkout-api-latency",
    status: "firing",
    title: "Checkout API latency is high",
    description: "p95 exceeded 800 ms for 10 minutes",
    severity: "critical",
    starts_at: "2026-09-02T10:15:00Z",
    labels: { service: "checkout", region: "eu-west" },
    annotations: { runbook: "https://docs.example.test/runbooks/checkout" },
    source_url: "https://monitoring.example.test/alerts/42",
  },
  null,
  2,
);

function absoluteSourceWebhook(value: string) {
  const resolved = new URL(value, window.location.origin);
  if (resolved.origin !== window.location.origin) {
    throw new Error("The source endpoint must use this Alert Hub origin.");
  }
  return resolved.href;
}

function readySourceExample(example: string) {
  return example.replaceAll("https://YOUR_HOST", window.location.origin);
}

function sourceWebhookUrl(source: Pick<Source, "id" | "kind">) {
  const endpoint =
    source.kind === "alertmanager"
      ? "alertmanager"
      : source.kind === "heartbeat"
        ? "heartbeat"
        : "events";
  return absoluteSourceWebhook(`/ingest/v1/${endpoint}/${encodeURIComponent(source.id)}`);
}

function sourceCredential(payload: unknown, kind: Source["kind"]): SourceCredential {
  const body = asRecord(payload);
  const id = typeof body.id === "string" ? body.id : "";
  const token = typeof body.token === "string" ? body.token : "";
  const webhook = typeof body.webhook_url === "string" ? body.webhook_url : "";
  const example = typeof body.example === "string" ? body.example : "";
  if (!id || !token || !webhook || !example) {
    throw new Error("The API did not return the required one-time source credential fields.");
  }
  return {
    id,
    kind,
    token,
    webhookUrl: absoluteSourceWebhook(webhook),
    example: readySourceExample(example),
  };
}

function asStringRecord(value: unknown): Record<string, string> {
  const record = asRecord(value);
  return Object.fromEntries(Object.entries(record).map(([key, item]) => [key, String(item ?? "")]));
}

function asStringList(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item).trim()).filter(Boolean) : [];
}

function asFiniteNumber(value: unknown): number | null {
  if (value == null || value === "") return null;
  const result = Number(value);
  return Number.isFinite(result) ? result : null;
}

function normalizePeerBase(value: unknown): string | null {
  if (typeof value !== "string" || !value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
      return null;
    }
    return url.href.replace(/\/$/, "");
  } catch {
    return null;
  }
}

function rememberVerifiedPeerBase(value: unknown): string | null {
  const normalized = normalizePeerBase(value);
  if (normalized) verifiedPeerBases.add(normalized);
  return normalized;
}

function listFrom(payload: unknown, key: string): unknown[] {
  if (Array.isArray(payload)) return payload;
  const record = asRecord(payload);
  if (Array.isArray(record[key])) return record[key] as unknown[];
  if (Array.isArray(record.items)) return record.items as unknown[];
  if (Array.isArray(record.data)) return record.data as unknown[];
  return [];
}

function normalizeIncident(item: unknown, index: number): Incident {
  const row = asRecord(item);
  const rawEvents = listFrom(row.events ?? row.timeline, "events");
  return {
    id: String(row.id ?? `incident-${index}`),
    title: String(row.title ?? row.name ?? "Untitled incident"),
    description: String(row.description ?? row.summary ?? "No description provided."),
    severity: (["critical", "warning", "info", "unknown"].includes(String(row.severity))
      ? String(row.severity)
      : "unknown") as Severity,
    status: (["open", "acknowledged", "resolved", "silenced"].includes(String(row.status))
      ? String(row.status)
      : "open") as IncidentStatus,
    source: String(asRecord(row.source).name ?? row.source_name ?? row.source ?? "Unknown source"),
    region: String(row.region ?? asRecord(row.labels).source_region ?? "Global").toUpperCase(),
    target: String(row.target ?? asRecord(row.labels).target_name ?? "—"),
    startsAt: String(row.starts_at ?? row.startsAt ?? row.created_at ?? ""),
    lastEventAt: String(
      row.last_event_at ?? row.lastEventAt ?? row.updated_at ?? row.starts_at ?? "",
    ),
    labels: asStringRecord(row.labels_json ?? row.labels),
    annotations: asStringRecord(row.annotations_json ?? row.annotations),
    events: rawEvents.map((event, eventIndex) => {
      const entry = asRecord(event);
      const eventPayload = asRecord(entry.payload);
      const eventType = String(entry.event_type ?? entry.type ?? "event");
      return {
        id: String(entry.id ?? `${row.id}-event-${eventIndex}`),
        type: eventType,
        label: String(entry.label ?? titleCase(eventType)),
        detail: String(
          entry.detail ??
            entry.description ??
            eventPayload.body ??
            eventPayload.reason ??
            eventPayload.description ??
            eventPayload.title ??
            "No event detail supplied.",
        ),
        at: String(entry.occurred_at ?? entry.at ?? entry.created_at ?? ""),
        node: String(entry.origin_node_id ?? entry.node ?? "unknown"),
        actor:
          entry.actor || eventPayload.actor ? String(entry.actor ?? eventPayload.actor) : undefined,
      };
    }),
  };
}

function normalizeNode(item: unknown, index: number): ClusterNode {
  const row = asRecord(item);
  const state = String(row.health ?? row.status ?? "unknown").toLowerCase();
  return {
    id: String(row.id ?? row.node_id ?? `node-${index}`),
    name: String(row.name ?? row.node_id ?? `node-${index + 1}`),
    city: String(row.city ?? row.location ?? row.region ?? "Unknown region"),
    region: String(row.region ?? "—").toUpperCase(),
    health: (["healthy", "degraded", "offline", "paused"].includes(state)
      ? state
      : state === "online"
        ? "healthy"
        : "unknown") as Health,
    version: String(row.software_version ?? row.version ?? "unknown"),
    syncLag: asFiniteNumber(row.sync_lag_seconds ?? row.sync_lag ?? row.lag),
    queue: asFiniteNumber(row.outbox_pending ?? row.queue),
    lastSeen: String(row.last_seen_at ?? row.last_seen ?? ""),
    roles: asStringList(row.enabled_roles),
    publicApiUrl: typeof row.public_api_url === "string" ? row.public_api_url : null,
  };
}

function unavailableNodeTelemetry(nodes: ClusterNode[]): ClusterNode[] {
  return nodes.map((node) => ({ ...node, health: "unknown", syncLag: null }));
}

function normalizeClusterSnapshot(payload: unknown, telemetryFresh: boolean) {
  const cluster = asRecord(payload);
  const rawNodes = listFrom(cluster, "nodes");
  const normalizedNodes = rawNodes.map(normalizeNode);
  return {
    rawNodes,
    nodes: telemetryFresh ? normalizedNodes : unavailableNodeTelemetry(normalizedNodes),
    meta: {
      cursor: Object.fromEntries(
        Object.entries(asRecord(cluster.cursor)).flatMap(([origin, value]) => {
          const sequence = asFiniteNumber(value);
          return sequence == null ? [] : [[origin, sequence]];
        }),
      ),
      eventCount: asFiniteNumber(cluster.cluster_event_count),
    } satisfies ClusterMeta,
  };
}

function normalizeSource(item: unknown, index: number): Source {
  const row = asRecord(item);
  const kind = String(row.kind ?? "generic_json") as Source["kind"];
  return {
    id: String(row.id ?? `source-${index}`),
    name: String(row.name ?? `Source ${index + 1}`),
    kind: ["alertmanager", "generic_json", "heartbeat"].includes(kind) ? kind : "generic_json",
    region: String(row.region ?? "Global").toUpperCase(),
    enabled: row.enabled !== false,
    health: (row.enabled === false ? "paused" : String(row.health ?? "unknown")) as Health,
    lastEvent: String(row.last_event_at ?? row.last_event ?? ""),
    events24h: asFiniteNumber(row.events_24h ?? row.event_count),
    allowedCidrs: asStringList(row.allowed_cidrs),
  };
}

function normalizeChannel(item: unknown, index: number): Channel {
  const row = asRecord(item);
  const kind = String(row.kind ?? "generic_webhook") as Channel["kind"];
  return {
    id: String(row.id ?? `channel-${index}`),
    name: String(row.name ?? `Channel ${index + 1}`),
    kind: ["web_push", "telegram", "smtp", "generic_webhook"].includes(kind)
      ? kind
      : "generic_webhook",
    health: (row.enabled === false ? "paused" : String(row.health ?? "unknown")) as Health,
    enabled: row.enabled !== false,
    delivered24h: Number(row.delivered_24h ?? row.delivery_success_24h ?? 0),
    deliveryAttempts24h: Number(row.deliveries_24h ?? row.delivery_count ?? 0),
    successRate: asFiniteNumber(row.success_rate),
    eligible: String(row.eligible ?? "All nodes"),
    eligibleRegions: asStringList(row.eligible_regions),
    eligibleNodeIds: asStringList(row.eligible_node_ids),
    configuredFields: asStringList(row.configured_fields),
    configAvailable: row.config_available !== false,
  };
}

function normalizeRoute(item: unknown, index: number): NotificationRoute {
  const row = asRecord(item);
  return {
    id: String(row.id ?? `route-${index}`),
    name: String(row.name ?? `Route ${index + 1}`),
    enabled: row.enabled !== false,
    priority: asFiniteNumber(row.priority) ?? 0,
    sourceFilter: asStringList(row.source_filter),
    severityFilter: asStringList(row.severity_filter),
    labelMatchers: listFrom(row.label_matchers, "items").map((item) => {
      const matcher = asRecord(item);
      return {
        name: String(matcher.name ?? ""),
        operator: String(matcher.operator ?? "equals"),
        value: String(matcher.value ?? ""),
      };
    }),
    channelIds: asStringList(row.channel_ids),
    continueMatching: Boolean(row.continue_matching),
  };
}

function normalizeDatasource(item: unknown, index: number): PrometheusDatasource {
  const row = asRecord(item);
  const authType = String(row.auth_type ?? "unknown");
  return {
    id: String(row.id ?? `datasource-${index}`),
    name: String(row.name ?? `Datasource ${index + 1}`),
    url: String(row.url ?? ""),
    nodeId: typeof row.node_id === "string" && row.node_id ? row.node_id : null,
    region: typeof row.region === "string" && row.region ? row.region : null,
    enabled: row.enabled !== false,
    authType: (["none", "bearer", "basic", "unknown"].includes(authType)
      ? authType
      : "unknown") as PrometheusDatasource["authType"],
    credentialsConfigured: Boolean(row.credentials_configured),
    credentialsAvailable: row.credentials_available !== false,
  };
}

function normalizeAudit(item: unknown, index: number): AuditItem {
  const row = asRecord(item);
  const actionCode = String(row.action_code ?? "audit_event");
  const tone = String(row.tone ?? "neutral");
  return {
    id: String(row.id ?? `audit-${index}`),
    action: String(row.action ?? titleCase(actionCode)),
    actionCode,
    detail: String(row.detail ?? row.description ?? "System operation"),
    actor: String(row.actor ?? row.username ?? "system"),
    node: String(row.node_id ?? row.node ?? "local-node"),
    at: String(row.occurred_at ?? row.at ?? ""),
    tone: (["neutral", "success", "warning", "danger"].includes(tone)
      ? tone
      : "neutral") as AuditItem["tone"],
    raw: row,
  };
}

const AUDIT_PAGE_SIZE = 100;

type AuditWindow = Pick<HubData, "audit" | "auditNextOffset" | "auditTotal">;

function auditIdsMatch(left: AuditItem[], right: AuditItem[]): boolean {
  return left.length === right.length && left.every((item, index) => item.id === right[index]?.id);
}

function auditWindowFromHead(head: AuditItem[], reportedTotal: number | null): AuditWindow {
  const auditNextOffset = head.length;
  return {
    audit: head,
    auditNextOffset,
    auditTotal: Math.max(reportedTotal ?? 0, auditNextOffset),
  };
}

function rebaseAuditHead(
  current: AuditWindow,
  head: AuditItem[],
  reportedTotal: number | null,
): AuditWindow {
  if (
    !current.audit.length ||
    current.auditNextOffset !== current.audit.length ||
    reportedTotal == null
  ) {
    return auditWindowFromHead(head, reportedTotal);
  }
  const addedRows = reportedTotal - current.auditTotal;
  const previousFirstIndex = head.findIndex((item) => item.id === current.audit[0]?.id);
  const overlap = previousFirstIndex < 0 ? [] : head.slice(previousFirstIndex);
  if (
    addedRows < 0 ||
    previousFirstIndex !== addedRows ||
    !auditIdsMatch(overlap, current.audit.slice(0, overlap.length))
  ) {
    // Offset pagination remains contiguous only when every new row is a pure
    // prepend. A late/out-of-order insertion, deletion, or different
    // authoritative ordering must restart from a known page-zero prefix.
    return auditWindowFromHead(head, reportedTotal);
  }
  const headIds = new Set(head.map((item) => item.id));
  const audit = [...head, ...current.audit.filter((item) => !headIds.has(item.id))];
  const auditNextOffset = current.auditNextOffset + addedRows;
  return {
    audit,
    auditNextOffset,
    auditTotal: Math.max(reportedTotal ?? 0, auditNextOffset, audit.length),
  };
}

function mergeAuditPageWithFreshHead(
  current: AuditWindow,
  page: AuditItem[],
  requestOffset: number,
  pageTotal: number | null,
  head: AuditItem[],
  headTotal: number | null,
): AuditWindow {
  const boundaryId = current.audit.at(-1)?.id;
  const previousFirstId = current.audit[0]?.id;
  if (
    !boundaryId ||
    !previousFirstId ||
    current.auditNextOffset !== current.audit.length ||
    requestOffset !== Math.max(0, current.auditNextOffset - 1) ||
    pageTotal == null ||
    headTotal == null
  ) {
    return auditWindowFromHead(head, headTotal);
  }

  const boundaryIndex = page.findIndex((item) => item.id === boundaryId);
  const previousFirstIndex = head.findIndex((item) => item.id === previousFirstId);
  const addedBeforePage = pageTotal - current.auditTotal;
  const addedBeforeHead = headTotal - current.auditTotal;
  const expectedBeforeBoundary =
    boundaryIndex < 0
      ? []
      : current.audit.slice(current.audit.length - boundaryIndex - 1, current.audit.length - 1);
  const headOverlap = previousFirstIndex < 0 ? [] : head.slice(previousFirstIndex);
  if (
    addedBeforePage < 0 ||
    addedBeforeHead < addedBeforePage ||
    boundaryIndex !== addedBeforePage ||
    previousFirstIndex !== addedBeforeHead ||
    !auditIdsMatch(page.slice(0, Math.max(0, boundaryIndex)), expectedBeforeBoundary) ||
    !auditIdsMatch(headOverlap, current.audit.slice(0, headOverlap.length))
  ) {
    // The overlap no longer proves continuity. Keeping older rows while
    // guessing an offset could skip an unseen range, so restart at page zero.
    return auditWindowFromHead(head, headTotal);
  }

  const knownIds = new Set(current.audit.map((item) => item.id));
  const olderRows = page.slice(boundaryIndex + 1).filter((item) => !knownIds.has(item.id));
  const extended = [...current.audit, ...olderRows];
  const headIds = new Set(head.map((item) => item.id));
  const audit = [...head, ...extended.filter((item) => !headIds.has(item.id))];

  // `requestOffset + page.length` is the server-consumed offset for the older
  // response. Exact totals prove how many pure prepends arrived before the
  // second head read; any other insertion shape reset above.
  const auditNextOffset = requestOffset + page.length + (headTotal - pageTotal);
  if (auditNextOffset !== audit.length) return auditWindowFromHead(head, headTotal);
  return {
    audit,
    auditNextOffset,
    auditTotal: Math.max(headTotal, auditNextOffset, audit.length),
  };
}

const AUDIT_BURST_WINDOW_MS = 10 * 60 * 1000;

function groupAuditBursts(items: AuditItem[]): AuditGroup[] {
  const groups: AuditGroup[] = [];
  const latestByFingerprint = new Map<string, AuditGroup>();
  for (const item of items) {
    const itemTime = Date.parse(item.at);
    const fingerprint = JSON.stringify([
      item.actionCode,
      item.action,
      item.detail,
      item.actor,
      item.node,
      item.tone,
    ]);
    const matching = latestByFingerprint.get(fingerprint);
    const newestTime = matching ? Date.parse(matching.at) : Number.NaN;
    if (
      matching &&
      Number.isFinite(itemTime) &&
      Number.isFinite(newestTime) &&
      Math.abs(newestTime - itemTime) <= AUDIT_BURST_WINDOW_MS
    ) {
      matching.count += 1;
      matching.oldestAt = item.at;
    } else {
      const group = { ...item, count: 1, oldestAt: item.at };
      groups.push(group);
      latestByFingerprint.set(fingerprint, group);
    }
  }
  return groups;
}

function aggregateNodeHealth(nodes: ClusterNode[]): Health {
  if (!nodes.length) return "unknown";
  if (nodes.some((node) => node.health === "offline")) return "offline";
  if (nodes.some((node) => node.health === "degraded")) return "degraded";
  if (nodes.some((node) => node.health === "unknown")) return "unknown";
  return nodes.every((node) => node.health === "paused") ? "paused" : "healthy";
}

function normalizeReachability(item: unknown): ReachabilityCell {
  const row = asRecord(item);
  return {
    source: String(row.source ?? row.source_region ?? "Unknown"),
    target: String(row.target ?? row.target_name ?? "Unknown"),
    success: Boolean(row.success ?? row.probe_success),
    latency:
      row.latency_ms == null && row.latency == null ? null : Number(row.latency_ms ?? row.latency),
    checkedAt: String(row.checked_at ?? row.timestamp ?? ""),
    datasourceId: typeof row.datasource_id === "string" ? row.datasource_id : null,
    datasourceName: typeof row.datasource_name === "string" ? row.datasource_name : null,
  };
}

function normalizeFixedMetricResult(payload: unknown): FixedMetricResult {
  const body = asRecord(payload);
  const status = String(body.status ?? "unknown");
  return {
    status: (["ok", "partial", "unavailable", "not_configured", "unknown"].includes(status)
      ? status
      : "unknown") as FixedMetricResult["status"],
    datasources: asFiniteNumber(body.datasources),
    samples: listFrom(body.samples, "samples").map((item) => {
      const sample = asRecord(item);
      return {
        datasourceId: String(sample.datasource_id ?? ""),
        datasourceName: String(sample.datasource_name ?? "Unknown datasource"),
        metric: asStringRecord(sample.metric),
        value: Number(sample.value ?? 0),
        timestamp: String(sample.timestamp ?? ""),
      };
    }),
    errors: listFrom(body.errors, "errors").map((item) => {
      const error = asRecord(item);
      return {
        datasourceId: String(error.datasource_id ?? ""),
        datasourceName: String(error.datasource_name ?? "Unknown datasource"),
        code: String(error.code ?? "unknown"),
        detail: String(error.detail ?? "No detail supplied"),
      };
    }),
  };
}

function normalizeGrafanaUrl(value: unknown): string | null {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    const url = new URL(value);
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

function readCookie(name: string) {
  if (typeof document === "undefined") return "";
  const pair = document.cookie.split("; ").find((item) => item.startsWith(`${name}=`));
  return pair ? decodeURIComponent(pair.slice(name.length + 1)) : "";
}

function postReadCacheMessage(message: Record<string, unknown>) {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  if (navigator.serviceWorker.controller) {
    navigator.serviceWorker.controller.postMessage(message);
    return;
  }
  void navigator.serviceWorker.ready
    .then((registration) => registration.active?.postMessage(message))
    .catch(() => undefined);
}

function pruneReadCaches(partition: string | null) {
  postReadCacheMessage(
    partition ? { type: "PRUNE_READ_CACHES", keep: partition } : { type: "CLEAR_READ_CACHE" },
  );
}

function cacheLoadedShellAssets(registration: ServiceWorkerRegistration) {
  const urls = [
    ...[...document.querySelectorAll<HTMLScriptElement>("script[src]")].map(
      (element) => element.src,
    ),
    ...[...document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"][href]')].map(
      (element) => element.href,
    ),
  ]
    .map((value) => new URL(value, window.location.origin))
    .filter((url) => url.origin === window.location.origin && url.pathname.startsWith("/assets/"))
    .map((url) => url.href);
  registration.active?.postMessage({ type: "CACHE_SHELL_ASSETS", urls });
}

function forgetAccessToken(clearCachedData = false) {
  memoryAccessToken = null;
  memorySessionId = null;
  memoryAccessExpiresAt = 0;
  offlineReadOnlyActive = false;
  if (clearCachedData) {
    verifiedPeerBases.clear();
    pruneReadCaches(null);
    if (typeof localStorage !== "undefined") localStorage.removeItem(SESSION_HINT_KEY);
  }
}

function persistSessionPartition() {
  if (
    !memorySessionId ||
    !/^[a-zA-Z0-9_-]{8,128}$/.test(memorySessionId) ||
    typeof localStorage === "undefined"
  )
    return;
  localStorage.setItem(
    SESSION_HINT_KEY,
    JSON.stringify({ partition: memorySessionId, savedAt: Date.now(), version: 1 }),
  );
}

function hasLogoutTombstone() {
  return typeof localStorage !== "undefined" && localStorage.getItem(LOGOUT_TOMBSTONE_KEY) !== null;
}

function markLocalLogout() {
  if (typeof localStorage !== "undefined") {
    localStorage.setItem(LOGOUT_TOMBSTONE_KEY, String(Date.now()));
  }
  if (typeof BroadcastChannel !== "undefined") {
    const channel = new BroadcastChannel(AUTH_BROADCAST_CHANNEL);
    channel.postMessage({ type: "logout" });
    channel.close();
  }
}

function clearLocalLogout() {
  if (typeof localStorage !== "undefined") localStorage.removeItem(LOGOUT_TOMBSTONE_KEY);
}

function restoreOfflineSession(): Record<string, unknown> | null {
  if (typeof localStorage === "undefined") return null;
  try {
    const hint = asRecord(JSON.parse(localStorage.getItem(SESSION_HINT_KEY) ?? "null"));
    const partition = typeof hint.partition === "string" ? hint.partition : "";
    const savedAt = Number(hint.savedAt);
    if (
      hint.version !== 1 ||
      !/^[a-zA-Z0-9_-]{8,128}$/.test(partition) ||
      !Number.isFinite(savedAt) ||
      savedAt > Date.now() + 60_000 ||
      Date.now() - savedAt > SESSION_HINT_MAX_AGE_MS
    ) {
      localStorage.removeItem(SESSION_HINT_KEY);
      pruneReadCaches(null);
      return null;
    }
    memoryAccessToken = null;
    memoryAccessExpiresAt = 0;
    memorySessionId = partition;
    offlineReadOnlyActive = true;
    demoModeActive = false;
    verifiedPeerBases.clear();
    pruneReadCaches(partition);
    return { username: "offline-operator", offline: true };
  } catch {
    localStorage.removeItem(SESSION_HINT_KEY);
    pruneReadCaches(null);
    return null;
  }
}

function rememberAccessToken(payload: unknown) {
  const body = asRecord(payload);
  const token = body.access_token ?? body.accessToken ?? body.token;
  memoryAccessToken = typeof token === "string" && token ? token : null;
  memorySessionId = null;
  memoryAccessExpiresAt = 0;
  if (memoryAccessToken) {
    offlineReadOnlyActive = false;
    try {
      const encoded = memoryAccessToken.split(".")[1] ?? "";
      const padding = "=".repeat((4 - (encoded.length % 4)) % 4);
      const claims = JSON.parse(atob((encoded + padding).replace(/-/g, "+").replace(/_/g, "/")));
      if (typeof claims.sid === "string" && /^[a-zA-Z0-9_-]{8,128}$/.test(claims.sid)) {
        memorySessionId = claims.sid;
      }
      if (typeof claims.exp === "number" && Number.isFinite(claims.exp)) {
        memoryAccessExpiresAt = claims.exp * 1000;
      }
    } catch {
      // The server remains the authority for token validity; this claim only partitions a local cache.
    }
    if (!memoryAccessExpiresAt) {
      const expiresIn = Number(body.expires_in ?? body.expiresIn ?? 0);
      if (Number.isFinite(expiresIn) && expiresIn > 0) {
        memoryAccessExpiresAt = Date.now() + expiresIn * 1000;
      }
    }
    pruneReadCaches(memorySessionId);
    persistSessionPartition();
  }
  return memoryAccessToken;
}

async function refreshAccessToken(): Promise<boolean> {
  if (refreshBlocked) return false;
  if (refreshInFlight) return refreshInFlight;
  const generation = authGeneration;
  const pending = (async () => {
    const headers = new Headers({ Accept: "application/json" });
    const csrf = readCookie("alert_hub_csrf") || readCookie("csrf_token") || readCookie("csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        credentials: "include",
        headers,
        signal: controller.signal,
      });
      if (refreshBlocked || generation !== authGeneration) return false;
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          forgetAccessToken(true);
          window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT));
        }
        return false;
      }
      const payload = await response.json();
      if (refreshBlocked || generation !== authGeneration) return false;
      const restored = Boolean(rememberAccessToken(payload));
      if (restored) window.dispatchEvent(new Event(SESSION_RESTORED_EVENT));
      return restored;
    } catch {
      return false;
    } finally {
      window.clearTimeout(timer);
    }
  })();
  refreshInFlight = pending;
  try {
    return await pending;
  } finally {
    if (refreshInFlight === pending) refreshInFlight = null;
  }
}

async function apiFetch(
  path: string,
  init: RequestInit = {},
  expectedAuthGeneration?: number,
  expectedSessionId?: string | null,
) {
  const assertExpectedAuthContext = () => {
    if (
      (expectedAuthGeneration !== undefined && expectedAuthGeneration !== authGeneration) ||
      (expectedSessionId !== undefined && expectedSessionId !== memorySessionId)
    ) {
      throw new PushSetupCancelledError();
    }
  };
  assertExpectedAuthContext();
  const method = (init.method ?? "GET").toUpperCase();
  if (demoModeActive && method !== "GET" && method !== "HEAD") {
    throw new Error("Live mutations are disabled in demo mode.");
  }
  if (offlineReadOnlyActive && method !== "GET" && method !== "HEAD") {
    throw new Error("Live mutations are disabled while using an offline cached session.");
  }
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  const attemptedToken = memoryAccessToken;
  if (attemptedToken) headers.set("Authorization", `Bearer ${attemptedToken}`);
  if (memorySessionId) headers.set("X-Alert-Hub-Cache-Partition", memorySessionId);
  const csrf = readCookie("alert_hub_csrf") || readCookie("csrf_token") || readCookie("csrf");
  if (csrf && !headers.has("X-CSRF-Token")) headers.set("X-CSRF-Token", csrf);
  if (typeof init.body === "string" && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  const requestInit = { ...init, credentials: "include" as RequestCredentials, headers };
  let primary: Response | null = null;
  let primaryError: unknown = null;
  try {
    primary = await fetch(`${API_BASE}${path}`, requestInit);
    assertExpectedAuthContext();
    if (primary.status === 401 && !path.startsWith("/auth/")) {
      const refreshed =
        Boolean(memoryAccessToken && memoryAccessToken !== attemptedToken) ||
        (await refreshAccessToken());
      assertExpectedAuthContext();
      if (refreshed && memoryAccessToken) {
        headers.set("Authorization", `Bearer ${memoryAccessToken}`);
        if (memorySessionId) headers.set("X-Alert-Hub-Cache-Partition", memorySessionId);
        primary = await fetch(`${API_BASE}${path}`, requestInit);
        assertExpectedAuthContext();
      }
    }
  } catch (error) {
    primaryError = error;
  }
  assertExpectedAuthContext();
  const failoverEnabled =
    typeof localStorage === "undefined" ||
    localStorage.getItem("alert-hub-auto-failover") !== "false";
  const canFailOver =
    method === "GET" && !path.startsWith("/auth/") && failoverEnabled && Boolean(memoryAccessToken);
  const shouldFailOver =
    !primary || primary.status >= 500 || primary.headers.get("X-Alert-Hub-Cache") === "hit";
  if (canFailOver && shouldFailOver && typeof localStorage !== "undefined") {
    let saved: unknown;
    try {
      saved = JSON.parse(localStorage.getItem("alert-hub-api-endpoints") ?? "[]");
    } catch {
      saved = [];
    }
    for (const value of Array.isArray(saved) ? saved.slice(0, 8) : []) {
      try {
        assertExpectedAuthContext();
        const normalized = normalizePeerBase(value);
        if (!normalized || !verifiedPeerBases.has(normalized)) continue;
        const base = new URL(normalized);
        const response = await fetch(
          `${base.href.replace(/\/$/, "")}${API_BASE}${path}`,
          requestInit,
        );
        assertExpectedAuthContext();
        if (response.ok) return response;
      } catch {
        assertExpectedAuthContext();
        // Move to the next saved peer without hiding the original response.
      }
    }
  }
  if (primary) return primary;
  throw primaryError instanceof Error ? primaryError : new Error("No API node responded");
}

async function apiError(response: Response, fallback: string) {
  const body = asRecord(await response.json().catch(() => ({})));
  const detail = body.detail;
  if (typeof detail === "string" && detail) return detail;
  if (detail && typeof detail === "object") {
    const record = asRecord(detail);
    return String(record.message ?? record.detail ?? record.code ?? fallback);
  }
  return String(body.message ?? fallback);
}

async function mutationJson(path: string, init: RequestInit) {
  const response = await apiFetch(path, init);
  if (!response.ok)
    throw new Error(await apiError(response, `Request failed (${response.status})`));
  if (response.status === 204) return null;
  return (await response.json()) as unknown;
}

async function getJson(path: string, signal?: AbortSignal) {
  const response = await apiFetch(path, { signal });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return {
    payload: (await response.json()) as unknown,
    cached: response.headers.get("X-Alert-Hub-Cache") === "hit",
  };
}

type AuthState =
  | { status: "checking"; user: null }
  | { status: "required"; user: null }
  | { status: "authenticated"; user: Record<string, unknown> }
  | { status: "offline"; user: Record<string, unknown> }
  | { status: "demo"; user: null };

function useAuthSession() {
  const queryClient = useQueryClient();
  const [state, setState] = useState<AuthState>({ status: "checking", user: null });
  const stateRef = useRef(state);
  useEffect(() => {
    stateRef.current = state;
  }, [state]);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 4500);
    const sessionExpired = () => {
      refreshBlocked = true;
      authGeneration += 1;
      forgetAccessToken(true);
      demoModeActive = false;
      verifiedPeerBases.clear();
      bootstrapSuggested = false;
      queryClient.clear();
      setState({ status: "required", user: null });
    };
    const recoverOfflineIdentity = async () => {
      if (stateRef.current.status !== "offline") return;
      try {
        const me = await apiFetch("/auth/me");
        if (me.status === 401 || me.status === 403) {
          sessionExpired();
          return;
        }
        if (!me.ok) throw new Error("identity unavailable");
        const user = asRecord(await me.json());
        offlineReadOnlyActive = false;
        if (active) setState({ status: "authenticated", user });
      } catch {
        offlineReadOnlyActive = true;
      }
    };
    const sessionRestored = () => void recoverOfflineIdentity();
    const reconnectOfflineSession = () => {
      if (stateRef.current.status === "offline") void refreshAccessToken();
    };
    const storageChanged = (event: StorageEvent) => {
      if (event.key === LOGOUT_TOMBSTONE_KEY && event.newValue !== null) sessionExpired();
    };
    const channel =
      typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(AUTH_BROADCAST_CHANNEL);
    if (channel) {
      channel.onmessage = (event) => {
        if (asRecord(event.data).type === "logout") sessionExpired();
      };
    }
    window.addEventListener(SESSION_EXPIRED_EVENT, sessionExpired);
    window.addEventListener(SESSION_RESTORED_EVENT, sessionRestored);
    window.addEventListener("storage", storageChanged);
    window.addEventListener("online", reconnectOfflineSession);
    const restore = async () => {
      try {
        forgetAccessToken(false);
        if (hasLogoutTombstone()) {
          refreshBlocked = true;
          forgetAccessToken(true);
          if (active) setState({ status: "required", user: null });
          return;
        }
        refreshBlocked = false;
        const refresh = await apiFetch("/auth/refresh", {
          method: "POST",
          signal: controller.signal,
        });
        if (refresh.ok) {
          const payload = await refresh.json();
          rememberAccessToken(payload);
          const me = await apiFetch("/auth/me", { signal: controller.signal });
          if (!me.ok) {
            if (me.status === 401 || me.status === 403) forgetAccessToken(true);
            else forgetAccessToken(false);
            throw new Error("session rejected");
          }
          if (active) setState({ status: "authenticated", user: asRecord(await me.json()) });
          return;
        }
        if (refresh.status === 401 || refresh.status === 403) {
          forgetAccessToken(true);
          try {
            const statusResponse = await apiFetch("/auth/bootstrap/status", {
              signal: controller.signal,
            });
            if (statusResponse.ok) {
              const statusBody = asRecord(await statusResponse.json());
              bootstrapSuggested = Boolean(
                statusBody.required ??
                statusBody.bootstrap_required ??
                statusBody.needs_bootstrap ??
                statusBody.enabled,
              );
            }
          } catch {
            bootstrapSuggested = false;
          }
          if (active) setState({ status: "required", user: null });
          return;
        }
        throw new Error(`session refresh unavailable (${refresh.status})`);
      } catch {
        forgetAccessToken(false);
        const offlineUser = restoreOfflineSession();
        if (active) {
          setState(
            offlineUser
              ? { status: "offline", user: offlineUser }
              : { status: "required", user: null },
          );
        }
      } finally {
        window.clearTimeout(timer);
      }
    };
    void restore();
    return () => {
      active = false;
      controller.abort();
      window.clearTimeout(timer);
      window.removeEventListener(SESSION_EXPIRED_EVENT, sessionExpired);
      window.removeEventListener(SESSION_RESTORED_EVENT, sessionRestored);
      window.removeEventListener("storage", storageChanged);
      window.removeEventListener("online", reconnectOfflineSession);
      channel?.close();
    };
  }, [queryClient]);
  return {
    state,
    recover: async () => {
      if (stateRef.current.status !== "offline") return false;
      return refreshAccessToken();
    },
    authenticate: (payload: unknown, user: Record<string, unknown> = {}) => {
      authGeneration += 1;
      refreshBlocked = false;
      clearLocalLogout();
      demoModeActive = false;
      bootstrapSuggested = false;
      verifiedPeerBases.clear();
      queryClient.clear();
      rememberAccessToken(payload);
      setState({ status: "authenticated", user });
    },
    useDemo: () => {
      demoModeActive = true;
      verifiedPeerBases.clear();
      queryClient.clear();
      forgetAccessToken(true);
      setState({ status: "demo", user: null });
    },
    logout: async () => {
      const hadLiveSession = !demoModeActive;
      markLocalLogout();
      refreshBlocked = true;
      authGeneration += 1;
      try {
        const pendingRefresh = refreshInFlight;
        if (pendingRefresh) await pendingRefresh.catch(() => false);
        if (hadLiveSession && (typeof navigator === "undefined" || navigator.onLine)) {
          const headers = new Headers({ Accept: "application/json" });
          const csrf =
            readCookie("alert_hub_csrf") || readCookie("csrf_token") || readCookie("csrf");
          if (csrf) headers.set("X-CSRF-Token", csrf);
          const controller = new AbortController();
          const timer = window.setTimeout(() => controller.abort(), 5000);
          try {
            await fetch(`${API_BASE}/auth/logout`, {
              method: "POST",
              credentials: "include",
              headers,
              signal: controller.signal,
            });
          } catch {
            // The local tombstone prevents an offline or failed logout from
            // silently restoring the HttpOnly session on the next startup.
          } finally {
            window.clearTimeout(timer);
          }
        }
      } finally {
        demoModeActive = false;
        verifiedPeerBases.clear();
        queryClient.clear();
        forgetAccessToken(true);
        setState({ status: "required", user: null });
      }
    },
  };
}

function useHubData(enabled: boolean, demo: boolean) {
  const queryClient = useQueryClient();
  const [data, setData] = useState<HubData>(EMPTY_DATA);
  const [mode, setMode] = useState<DataMode>("live");
  const [online, setOnline] = useState(() =>
    typeof navigator === "undefined" ? true : navigator.onLine,
  );
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveUpdates, setLiveUpdates] = useState(false);
  const [auditLoadingMore, setAuditLoadingMore] = useState(false);
  const [auditLoadError, setAuditLoadError] = useState<string | null>(null);
  const mounted = useRef(true);
  const verifiedData = useRef<HubData | null>(null);
  const verifiedPartition = useRef<string | null>(null);
  const fullRefreshEpoch = useRef(0);
  const clusterRequestEpoch = useRef(0);
  const auditDataEpoch = useRef(0);
  const auditLoadController = useRef<AbortController | null>(null);

  const refresh = useCallback(
    async (quiet = false) => {
      if (!enabled || demo) {
        setRefreshing(false);
        return;
      }
      if (!quiet) setRefreshing(true);
      const refreshEpoch = ++fullRefreshEpoch.current;
      const clusterEpoch = ++clusterRequestEpoch.current;
      const sessionGeneration = authGeneration;
      const sessionPartition = memorySessionId;
      const isCurrentRequest = () =>
        mounted.current &&
        refreshEpoch === fullRefreshEpoch.current &&
        authGeneration === sessionGeneration &&
        memorySessionId === sessionPartition &&
        verifiedPartition.current === sessionPartition;
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), 6500);
      try {
        const requests = await queryClient.fetchQuery({
          queryKey: ["hub-snapshot", memorySessionId ?? "unpartitioned"],
          queryFn: () =>
            Promise.allSettled([
              getJson("/incidents?limit=100", controller.signal),
              getJson("/cluster/status", controller.signal),
              getJson("/sources", controller.signal),
              getJson("/channels", controller.signal),
              getJson("/routes", controller.signal),
              getJson("/prometheus-datasources", controller.signal),
              getJson("/devices", controller.signal),
              getJson("/audit?limit=100", controller.signal),
              getJson("/metrics/reachability", controller.signal),
              getJson("/metrics/queries/firing_alerts", controller.signal),
              getJson("/metrics/queries/key_jobs_up", controller.signal),
              getJson("/metrics/queries/alert_hub_health", controller.signal),
              getJson("/metrics/summary", controller.signal),
            ]),
          staleTime: 0,
        });
        if (!isCurrentRequest()) return;
        const successful = requests.filter((result) => result.status === "fulfilled").length;
        if (successful === 0) throw new Error("No API node responded");
        const cachedResponses = requests.filter(
          (result) => result.status === "fulfilled" && result.value.cached,
        ).length;
        if (requests[7]?.status === "fulfilled") setAuditLoadError(null);

        setData(() => {
          const next: HubData = { ...(verifiedData.current ?? EMPTY_DATA) };
          const [
            incidents,
            nodes,
            sources,
            channels,
            routes,
            datasources,
            devices,
            audit,
            reachability,
            firingAlerts,
            keyJobsUp,
            alertHubHealth,
            summary,
          ] = requests;
          if (incidents.status === "fulfilled") {
            next.incidents = listFrom(incidents.value.payload, "incidents").map(normalizeIncident);
          }
          if (clusterEpoch === clusterRequestEpoch.current) {
            if (nodes.status === "fulfilled") {
              const cluster = normalizeClusterSnapshot(nodes.value.payload, !nodes.value.cached);
              next.nodes = cluster.nodes;
              next.clusterMeta = cluster.meta;
              const discovered = cluster.rawNodes
                .map((item) => rememberVerifiedPeerBase(asRecord(item).public_api_url))
                .filter((item): item is string => Boolean(item));
              if (discovered.length) {
                try {
                  const current = JSON.parse(
                    localStorage.getItem("alert-hub-api-endpoints") ?? "[]",
                  );
                  const disabled = JSON.parse(
                    localStorage.getItem("alert-hub-disabled-api-endpoints") ?? "[]",
                  );
                  const disabledSet = new Set(Array.isArray(disabled) ? disabled : []);
                  localStorage.setItem(
                    "alert-hub-api-endpoints",
                    JSON.stringify(
                      [
                        ...new Set([
                          ...(Array.isArray(current) ? current : []),
                          ...discovered.filter((item) => !disabledSet.has(item)),
                        ]),
                      ].slice(0, 8),
                    ),
                  );
                } catch {
                  // Endpoint discovery is a device-local optimization only.
                }
              }
            } else {
              next.nodes = unavailableNodeTelemetry(next.nodes);
            }
          }
          if (sources.status === "fulfilled") {
            next.sources = listFrom(sources.value.payload, "sources").map(normalizeSource);
          }
          if (channels.status === "fulfilled") {
            next.channels = listFrom(channels.value.payload, "channels").map(normalizeChannel);
          }
          if (routes.status === "fulfilled") {
            next.routes = listFrom(routes.value.payload, "routes").map(normalizeRoute);
          }
          if (datasources.status === "fulfilled") {
            next.datasources = listFrom(datasources.value.payload, "datasources").map(
              normalizeDatasource,
            );
          }
          if (devices.status === "fulfilled") {
            next.devices = listFrom(devices.value.payload, "devices").map((item, index) => {
              const row = asRecord(item);
              return {
                id: String(row.id ?? `device-${index}`),
                name: String(row.device_name ?? row.name ?? `Device ${index + 1}`),
                platform: String(row.platform ?? row.user_agent ?? "Browser session"),
                current: Boolean(row.current ?? row.is_current),
                push: Boolean(row.push_enabled ?? row.push ?? false),
                lastUsed: String(row.last_used_at ?? row.last_used ?? ""),
                location: String(row.location ?? "Unknown location"),
              };
            });
          }
          if (audit.status === "fulfilled") {
            const auditBody = asRecord(audit.value.payload);
            const firstPage = listFrom(auditBody, "items").map(normalizeAudit);
            Object.assign(next, rebaseAuditHead(next, firstPage, asFiniteNumber(auditBody.total)));
            auditDataEpoch.current += 1;
          }
          if (reachability.status === "fulfilled") {
            const reachabilityBody = asRecord(reachability.value.payload);
            next.reachability = listFrom(reachabilityBody, "cells").map(normalizeReachability);
            const statusValue = String(reachabilityBody.status ?? "unknown");
            next.reachabilityMeta = {
              status: ([
                "ok",
                "partial",
                "unavailable",
                "empty",
                "not_configured",
                "unknown",
              ].includes(statusValue)
                ? statusValue
                : "unknown") as ReachabilityMeta["status"],
              detail: String(reachabilityBody.detail ?? ""),
              datasources: asFiniteNumber(reachabilityBody.datasources),
              errors: listFrom(reachabilityBody.errors, "items").map((item) => {
                const row = asRecord(item);
                return {
                  datasourceId: String(row.datasource_id ?? ""),
                  datasourceName: String(row.datasource_name ?? "Unknown datasource"),
                  code: String(row.code ?? "unknown"),
                  detail: String(row.detail ?? "No detail supplied"),
                };
              }),
            };
          }
          next.fixedMetrics = {
            firingAlerts:
              firingAlerts.status === "fulfilled"
                ? normalizeFixedMetricResult(firingAlerts.value.payload)
                : next.fixedMetrics.firingAlerts,
            keyJobsUp:
              keyJobsUp.status === "fulfilled"
                ? normalizeFixedMetricResult(keyJobsUp.value.payload)
                : next.fixedMetrics.keyJobsUp,
            alertHubHealth:
              alertHubHealth.status === "fulfilled"
                ? normalizeFixedMetricResult(alertHubHealth.value.payload)
                : next.fixedMetrics.alertHubHealth,
          };
          if (summary.status === "fulfilled") {
            const row = asRecord(summary.value.payload);
            const deliveryAttempts = asFiniteNumber(row.deliveries_24h);
            next.summary = {
              open: Number(
                row.open ??
                  row.incidents_open ??
                  next.incidents.filter((item) => item.status === "open").length,
              ),
              acknowledged: Number(
                row.acknowledged ??
                  row.incidents_acknowledged ??
                  next.incidents.filter((item) => item.status === "acknowledged").length,
              ),
              critical: Number(
                row.critical ??
                  row.incidents_critical ??
                  next.incidents.filter(
                    (item) => item.severity === "critical" && item.status !== "resolved",
                  ).length,
              ),
              deliveryRate:
                deliveryAttempts === 0
                  ? null
                  : asFiniteNumber(row.delivery_rate ?? row.delivery_success_rate),
              deliveries24h: deliveryAttempts,
              deliverySuccess24h: asFiniteNumber(row.delivery_success_24h),
              outboxPending: asFiniteNumber(row.outbox_pending),
              channelsEnabled: asFiniteNumber(row.channels_enabled),
              grafanaUrl: normalizeGrafanaUrl(row.grafana_url),
            };
          } else {
            next.summary = {
              open: next.incidents.filter((item) => item.status === "open").length,
              acknowledged: next.incidents.filter((item) => item.status === "acknowledged").length,
              critical: next.incidents.filter(
                (item) => item.severity === "critical" && item.status !== "resolved",
              ).length,
              deliveryRate: next.summary.deliveryRate,
              deliveries24h: next.summary.deliveries24h,
              deliverySuccess24h: next.summary.deliverySuccess24h,
              outboxPending: next.summary.outboxPending,
              channelsEnabled: next.summary.channelsEnabled,
              grafanaUrl: next.summary.grafanaUrl,
            };
          }
          verifiedData.current = next;
          return next;
        });
        if (cachedResponses > 0 || !navigator.onLine) {
          setMode("cached");
          setError(
            "The live API is unavailable for some requests. Showing verified on-device data.",
          );
        } else {
          setMode("live");
          setError(
            successful < requests.length ? "Some cluster data is temporarily unavailable." : null,
          );
        }
      } catch {
        if (!isCurrentRequest()) return;
        const snapshot = verifiedData.current;
        const unavailableSnapshot = snapshot
          ? {
              ...snapshot,
              nodes:
                clusterEpoch === clusterRequestEpoch.current
                  ? unavailableNodeTelemetry(snapshot.nodes)
                  : snapshot.nodes,
            }
          : null;
        verifiedData.current = unavailableSnapshot;
        setData(unavailableSnapshot ?? EMPTY_DATA);
        setMode("cached");
        if (snapshot) {
          setError(
            navigator.onLine
              ? "API nodes are unavailable. Showing the last verified operational snapshot."
              : "You are offline. Showing the last verified on-device snapshot.",
          );
        } else {
          setError(
            navigator.onLine
              ? "API nodes are unavailable. No verified operational data is available."
              : "You are offline and no verified on-device snapshot is available.",
          );
        }
      } finally {
        window.clearTimeout(timer);
        if (isCurrentRequest()) setRefreshing(false);
      }
    },
    [demo, enabled, queryClient],
  );

  const refreshClusterTelemetry = useCallback(async () => {
    if (!enabled || demo) return;
    const requestEpoch = ++clusterRequestEpoch.current;
    const sessionGeneration = authGeneration;
    const sessionPartition = memorySessionId;
    const isCurrentRequest = () =>
      mounted.current &&
      requestEpoch === clusterRequestEpoch.current &&
      authGeneration === sessionGeneration &&
      memorySessionId === sessionPartition &&
      verifiedPartition.current === sessionPartition;
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 6500);
    try {
      const response = await getJson("/cluster/status", controller.signal);
      if (!isCurrentRequest()) return;
      const cluster = normalizeClusterSnapshot(response.payload, !response.cached);
      setData((current) => {
        const next = { ...current, nodes: cluster.nodes, clusterMeta: cluster.meta };
        verifiedData.current = next;
        return next;
      });
    } catch {
      if (!isCurrentRequest()) return;
      setData((current) => {
        const next = { ...current, nodes: unavailableNodeTelemetry(current.nodes) };
        verifiedData.current = next;
        return next;
      });
    } finally {
      window.clearTimeout(timer);
    }
  }, [demo, enabled]);

  const loadMoreAudit = useCallback(async () => {
    if (!enabled || demo || auditLoadingMore) return;
    const snapshot = verifiedData.current;
    const offset = snapshot?.auditNextOffset ?? 0;
    if (snapshot && offset >= snapshot.auditTotal) return;
    if (!snapshot?.audit.length) return;
    setAuditLoadingMore(true);
    setAuditLoadError(null);
    const controller = new AbortController();
    auditLoadController.current?.abort();
    auditLoadController.current = controller;
    const sessionGeneration = authGeneration;
    const sessionPartition = memorySessionId;
    const dataEpoch = auditDataEpoch.current;
    const isCurrentRequest = () =>
      mounted.current &&
      auditLoadController.current === controller &&
      authGeneration === sessionGeneration &&
      memorySessionId === sessionPartition &&
      verifiedPartition.current === sessionPartition;
    const timer = window.setTimeout(() => controller.abort(), 6500);
    try {
      const requestOffset = Math.max(0, offset - 1);
      const response = await getJson(
        `/audit?limit=${AUDIT_PAGE_SIZE + 1}&offset=${requestOffset}`,
        controller.signal,
      );
      if (!isCurrentRequest()) return;
      const body = asRecord(response.payload);
      const page = listFrom(body, "items").map(normalizeAudit);
      const headResponse = await getJson(`/audit?limit=${AUDIT_PAGE_SIZE}`, controller.signal);
      if (!isCurrentRequest() || auditDataEpoch.current !== dataEpoch) return;
      const headBody = asRecord(headResponse.payload);
      const head = listFrom(headBody, "items").map(normalizeAudit);
      const auditWindow = mergeAuditPageWithFreshHead(
        snapshot,
        page,
        requestOffset,
        asFiniteNumber(body.total),
        head,
        asFiniteNumber(headBody.total),
      );
      setData((current) => {
        if (
          auditDataEpoch.current !== dataEpoch ||
          authGeneration !== sessionGeneration ||
          memorySessionId !== sessionPartition ||
          verifiedPartition.current !== sessionPartition
        ) {
          return current;
        }
        const next = { ...current, ...auditWindow };
        auditDataEpoch.current += 1;
        verifiedData.current = next;
        return next;
      });
    } catch {
      if (isCurrentRequest()) setAuditLoadError("Could not load older audit events. Try again.");
    } finally {
      window.clearTimeout(timer);
      if (isCurrentRequest()) {
        auditLoadController.current = null;
        setAuditLoadingMore(false);
      }
    }
  }, [auditLoadingMore, demo, enabled]);

  useEffect(() => {
    mounted.current = true;
    if (demo) {
      fullRefreshEpoch.current += 1;
      clusterRequestEpoch.current += 1;
      auditLoadController.current?.abort();
      auditLoadController.current = null;
      verifiedData.current = null;
      verifiedPartition.current = null;
      const transition = window.setTimeout(() => {
        setData(DEMO_DATA);
        setMode("demo");
        setError("Preview data only. No live API session is active.");
        setRefreshing(false);
        setAuditLoadingMore(false);
        setAuditLoadError(null);
      }, 0);
      return () => {
        mounted.current = false;
        fullRefreshEpoch.current += 1;
        clusterRequestEpoch.current += 1;
        auditLoadController.current?.abort();
        auditLoadController.current = null;
        window.clearTimeout(transition);
      };
    }
    if (!enabled) {
      fullRefreshEpoch.current += 1;
      clusterRequestEpoch.current += 1;
      auditLoadController.current?.abort();
      auditLoadController.current = null;
      verifiedData.current = null;
      verifiedPartition.current = null;
      const transition = window.setTimeout(() => {
        setData(EMPTY_DATA);
        setMode("live");
        setError(null);
        setRefreshing(false);
        setAuditLoadingMore(false);
        setAuditLoadError(null);
      }, 0);
      return () => {
        mounted.current = false;
        fullRefreshEpoch.current += 1;
        clusterRequestEpoch.current += 1;
        auditLoadController.current?.abort();
        auditLoadController.current = null;
        window.clearTimeout(transition);
      };
    }
    if (verifiedPartition.current !== memorySessionId) {
      fullRefreshEpoch.current += 1;
      clusterRequestEpoch.current += 1;
      auditLoadController.current?.abort();
      auditLoadController.current = null;
      verifiedData.current = null;
      verifiedPartition.current = memorySessionId;
      setAuditLoadingMore(false);
      setAuditLoadError(null);
    }
    const initialRefresh = window.setTimeout(() => void refresh(), 0);
    const onOnline = () => {
      setOnline(true);
      void refresh();
    };
    const onOffline = () => {
      fullRefreshEpoch.current += 1;
      clusterRequestEpoch.current += 1;
      setOnline(false);
      setRefreshing(false);
      setMode("cached");
      setData((current) => {
        const next = { ...current, nodes: unavailableNodeTelemetry(current.nodes) };
        verifiedData.current = next;
        return next;
      });
      setError(
        verifiedData.current
          ? "You are offline. Showing the last verified on-device snapshot."
          : "You are offline and no verified on-device snapshot is available.",
      );
    };
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      mounted.current = false;
      fullRefreshEpoch.current += 1;
      clusterRequestEpoch.current += 1;
      auditLoadController.current?.abort();
      auditLoadController.current = null;
      window.clearTimeout(initialRefresh);
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, [demo, enabled, refresh]);

  useEffect(() => {
    if (!enabled || demo || !online) return;
    const telemetryPoller = window.setInterval(() => void refreshClusterTelemetry(), 30000);
    return () => window.clearInterval(telemetryPoller);
  }, [demo, enabled, online, refreshClusterTelemetry]);

  useEffect(() => {
    if (!enabled || demo || !online || mode !== "live") return;
    if (typeof EventSource === "undefined") {
      const fallbackPoller = window.setInterval(() => void refresh(true), 30000);
      return () => window.clearInterval(fallbackPoller);
    }
    let stopped = false;
    let poller: number | undefined;
    let retryTimer: number | undefined;
    let renewalTimer: number | undefined;
    let stream: EventSource | undefined;
    let renewal: Promise<void> | null = null;
    const startPolling = () => {
      if (!stopped && !poller) poller = window.setInterval(() => void refresh(true), 30000);
    };
    const clearTimers = () => {
      if (retryTimer) window.clearTimeout(retryTimer);
      if (renewalTimer) window.clearTimeout(renewalTimer);
      retryTimer = undefined;
      renewalTimer = undefined;
    };
    const scheduleRetry = (callback: () => void, delay: number) => {
      if (retryTimer) window.clearTimeout(retryTimer);
      retryTimer = window.setTimeout(callback, delay);
    };
    const renewStream = async () => {
      if (stopped || renewal) return renewal;
      renewal = (async () => {
        setLiveUpdates(false);
        if (renewalTimer) window.clearTimeout(renewalTimer);
        renewalTimer = undefined;
        const refreshed = await refreshAccessToken();
        if (stopped) return;
        stream?.close();
        if (refreshed) scheduleRetry(connect, 250);
        else {
          startPolling();
          scheduleRetry(connect, 30000);
        }
      })();
      try {
        await renewal;
      } finally {
        renewal = null;
      }
    };
    const scheduleRenewal = () => {
      if (!memoryAccessExpiresAt) return;
      if (renewalTimer) window.clearTimeout(renewalTimer);
      const delay = Math.max(1000, memoryAccessExpiresAt - Date.now() - 30000);
      renewalTimer = window.setTimeout(() => {
        void renewStream();
      }, delay);
    };
    const connect = () => {
      if (stopped) return;
      retryTimer = undefined;
      stream?.close();
      // EventSource cannot attach a bearer header. The backend's short-lived,
      // HttpOnly stream cookie is renewed together with the access token.
      stream = new EventSource(`${API_BASE}/stream`, { withCredentials: true });
      stream.onopen = () => {
        if (stopped) return;
        if (poller) window.clearInterval(poller);
        poller = undefined;
        setLiveUpdates(true);
        scheduleRenewal();
      };
      stream.onmessage = () => void refresh(true);
      stream.onerror = () => {
        if (stopped) return;
        setLiveUpdates(false);
        stream?.close();
        void renewStream();
      };
    };
    connect();
    return () => {
      stopped = true;
      stream?.close();
      if (poller) window.clearInterval(poller);
      clearTimers();
      setLiveUpdates(false);
    };
  }, [demo, enabled, mode, online, refresh]);

  return {
    data,
    mode,
    online,
    refreshing,
    error,
    liveUpdates,
    auditLoadingMore,
    auditLoadError,
    loadMoreAudit,
    refresh,
    setData,
  };
}

function getRoute(pathname: string): { id: RouteId; incidentId?: string } {
  const parts = pathname.split("/").filter(Boolean);
  if (parts[0] === "incidents" && parts[1]) return { id: "incident", incidentId: parts[1] };
  const item = NAV_ITEMS.find((entry) => entry.path === `/${parts[0] ?? ""}`);
  return { id: item?.id ?? "overview" };
}

function useRoute() {
  const location = useLocation();
  const routerNavigate = useRouterNavigate();
  const route = useMemo(() => getRoute(location.pathname), [location.pathname]);
  const navigate = useCallback(
    (path: string) => {
      void routerNavigate(path);
      window.scrollTo({ top: 0, behavior: "smooth" });
    },
    [routerNavigate],
  );
  return { route, navigate };
}

function Icon({ symbol }: { symbol: string }) {
  return (
    <span className="icon-glyph" aria-hidden="true">
      {symbol}
    </span>
  );
}

function StatusDot({ health = "unknown" }: { health?: Health }) {
  return <span className={`status-dot status-dot--${health}`} aria-hidden="true" />;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-badge--${severity}`}>{severity}</span>;
}

function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={`incident-status incident-status--${status}`}>
      <span aria-hidden="true" />
      {status}
    </span>
  );
}

function EmptyState({
  icon,
  title,
  message,
  action,
}: {
  icon: string;
  title: string;
  message: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-state__icon">
        <Icon symbol={icon} />
      </div>
      <h3>{title}</h3>
      <p>{message}</p>
      {action}
    </div>
  );
}

function Panel({
  children,
  className = "",
  title,
  eyebrow,
  action,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
  eyebrow?: string;
  action?: ReactNode;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || eyebrow || action) && (
        <div className="panel__header">
          <div>
            {eyebrow && <span className="eyebrow">{eyebrow}</span>}
            {title && <h2>{title}</h2>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

function PageHeading({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-heading__actions">{actions}</div>}
    </div>
  );
}

function Brand() {
  const appName = useContext(AppNameContext);
  return (
    <div className="brand" aria-label={appName}>
      <span className="brand-mark" aria-hidden="true">
        <i />
        <i />
        <i />
      </span>
      <span>
        <b>{appName}</b>
        <small>distributed ops</small>
      </span>
    </div>
  );
}

function AuthLoading() {
  return (
    <div className="auth-screen auth-screen--loading">
      <div className="auth-loading-mark">
        <Brand />
        <span>
          <i />
          <i />
          <i />
        </span>
        <small>Contacting the nearest API node…</small>
      </div>
    </div>
  );
}

function AuthGate({
  onAuthenticated,
  onDemo,
}: {
  onAuthenticated: (payload: unknown, user?: Record<string, unknown>) => void;
  onDemo: () => void;
}) {
  const [mode, setMode] = useState<"login" | "bootstrap">(
    bootstrapSuggested ? "bootstrap" : "login",
  );
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (mode === "bootstrap" && password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const response = await apiFetch(mode === "login" ? "/auth/login" : "/auth/bootstrap", {
        method: "POST",
        body: JSON.stringify(
          mode === "login"
            ? { username, password, device_name: currentPushDeviceName() }
            : {
                bootstrap_token: bootstrapToken,
                username,
                password,
                device_name: currentPushDeviceName(),
              },
        ),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const body = asRecord(payload);
        throw new Error(
          String(
            body.detail ??
              body.message ??
              (response.status === 401
                ? "Username or password is incorrect."
                : "Authentication failed."),
          ),
        );
      }
      onAuthenticated(payload, asRecord(asRecord(payload).user));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="auth-screen">
      <div className="auth-grid" aria-hidden="true" />
      <section className="auth-story">
        <Brand />
        <div className="auth-story__copy">
          <span className="eyebrow">Distributed operations</span>
          <h1>
            Every node stays useful.
            <br />
            <em>Every event survives.</em>
          </h1>
          <p>
            Ingest locally, converge globally, and keep delivering alerts when a region disappears.
          </p>
        </div>
        <div className="auth-topology">
          <span className="auth-topology__line auth-topology__line--1" />
          <span className="auth-topology__line auth-topology__line--2" />
          <span className="auth-topology__line auth-topology__line--3" />
          {[
            { code: "A", label: "Peer region" },
            { code: "B", label: "Peer region" },
            { code: "C", label: "Peer region" },
          ].map((node, index) => (
            <div key={node.code} className={`auth-node auth-node--${index + 1}`}>
              <span>{node.code}</span>
              <b>{node.label}</b>
              <small>
                <StatusDot health="unknown" />
                example node
              </small>
            </div>
          ))}
          <div className="auth-topology__center">
            <span className="brand-mark">
              <i />
              <i />
              <i />
            </span>
            <small>example topology</small>
          </div>
        </div>
        <div className="auth-story__foot">
          <span>
            <Icon symbol="◇" />
            Self-hosted
          </span>
          <span>
            <Icon symbol="⇄" />
            Local-first
          </span>
          <span>
            <Icon symbol="◉" />
            Push ready
          </span>
        </div>
      </section>
      <section className="auth-panel">
        <div className="auth-panel__mobile-brand">
          <Brand />
        </div>
        <div className="auth-card">
          <span className="eyebrow">
            {mode === "login" ? "Operator access" : "First node setup"}
          </span>
          <h2>{mode === "login" ? "Welcome back" : "Bootstrap the cluster"}</h2>
          <p>
            {mode === "login"
              ? "Sign in to view the live incident ledger and manage this cluster."
              : "Use the one-time token stored on the server to create the first administrator."}
          </p>
          <div className="auth-tabs">
            <button
              className={mode === "login" ? "active" : ""}
              type="button"
              onClick={() => {
                setMode("login");
                setError(null);
              }}
            >
              Sign in
            </button>
            <button
              className={mode === "bootstrap" ? "active" : ""}
              type="button"
              onClick={() => {
                setMode("bootstrap");
                setError(null);
              }}
            >
              First run
            </button>
          </div>
          <form onSubmit={submit}>
            {mode === "bootstrap" && (
              <label>
                <span>Bootstrap token</span>
                <input
                  value={bootstrapToken}
                  onChange={(event) => setBootstrapToken(event.target.value)}
                  autoComplete="off"
                  placeholder="Paste token from the server"
                  required
                />
              </label>
            )}
            <label>
              <span>Username</span>
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                required
                autoFocus
              />
            </label>
            <label>
              <span>Password</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                placeholder="Enter your password"
                required
                minLength={mode === "bootstrap" ? 12 : 8}
              />
            </label>
            {mode === "bootstrap" && (
              <label>
                <span>Confirm password</span>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  autoComplete="new-password"
                  required
                  minLength={12}
                />
              </label>
            )}
            {error && (
              <div className="auth-error" role="alert">
                <Icon symbol="!" />
                {error}
              </div>
            )}
            <button className="button button--primary auth-submit" disabled={busy}>
              {busy ? "Authenticating…" : mode === "login" ? "Sign in" : "Create administrator"}
              <Icon symbol="→" />
            </button>
          </form>
          <div className="auth-demo">
            <span>Preview without a live API</span>
            <button onClick={onDemo}>
              Open demo snapshot <Icon symbol="→" />
            </button>
          </div>
        </div>
        <p className="auth-security">
          <Icon symbol="◇" />
          Access tokens stay in memory. Refresh sessions use a secure HttpOnly cookie.
        </p>
      </section>
    </div>
  );
}

function Sidebar({
  route,
  navigate,
  collapsed,
  onCollapse,
  incidents,
  nodes,
  operator,
}: {
  route: RouteId;
  navigate: (path: string) => void;
  collapsed: boolean;
  onCollapse: () => void;
  incidents: Incident[];
  nodes: ClusterNode[];
  operator: string;
}) {
  const activeIncidents = incidents.filter((item) => item.status !== "resolved").length;
  const healthyNodes = nodes.filter((item) => item.health === "healthy").length;
  const unknownNodes = nodes.filter((item) => item.health === "unknown").length;
  const impairedNodes = nodes.filter((item) =>
    ["degraded", "offline"].includes(item.health),
  ).length;
  return (
    <aside className={`sidebar ${collapsed ? "sidebar--collapsed" : ""}`}>
      <div className="sidebar__top">
        <Brand />
        <button
          className="icon-button sidebar__collapse"
          onClick={onCollapse}
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
        >
          <Icon symbol={collapsed ? "›" : "‹"} />
        </button>
      </div>
      <nav className="sidebar__nav" aria-label="Primary navigation">
        <span className="sidebar__section-label">Operations</span>
        {NAV_ITEMS.slice(0, 5).map((item) => (
          <button
            key={item.id}
            className={
              route === item.id || (route === "incident" && item.id === "incidents") ? "active" : ""
            }
            onClick={() => navigate(item.path)}
            title={collapsed ? item.label : undefined}
          >
            <Icon symbol={item.icon} />
            <span>{item.label}</span>
            {item.id === "incidents" && <em>{activeIncidents}</em>}
          </button>
        ))}
        <span className="sidebar__section-label">Manage</span>
        {NAV_ITEMS.slice(5).map((item) => (
          <button
            key={item.id}
            className={route === item.id ? "active" : ""}
            onClick={() => navigate(item.path)}
            title={collapsed ? item.label : undefined}
          >
            <Icon symbol={item.icon} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar__footer">
        <div className="sidebar__cluster-mini">
          <span className="cluster-ring">
            <i />
            <i />
            <i />
          </span>
          <span>
            <b>{nodes.length ? `${nodes.length} nodes` : "No verified nodes"}</b>
            <small>
              {nodes.length
                ? `${healthyNodes} healthy · ${impairedNodes} impaired · ${unknownNodes} unknown`
                : "Waiting for live data"}
            </small>
          </span>
        </div>
        <div className="sidebar__profile" aria-label="Signed-in account">
          <span className="avatar">OP</span>
          <span>
            <b>Operator</b>
            <small>{operator}</small>
          </span>
        </div>
      </div>
    </aside>
  );
}

function MobileNav({
  route,
  navigate,
  onMore,
}: {
  route: RouteId;
  navigate: (path: string) => void;
  onMore: () => void;
}) {
  const items = [NAV_ITEMS[0], NAV_ITEMS[1], NAV_ITEMS[2], NAV_ITEMS[6]];
  return (
    <nav className="mobile-nav" aria-label="Mobile navigation">
      {items.map((item) => (
        <button
          key={item.id}
          className={
            route === item.id || (route === "incident" && item.id === "incidents") ? "active" : ""
          }
          onClick={() => navigate(item.path)}
        >
          <Icon symbol={item.icon} />
          <span>{item.id === "reachability" ? "Reach" : item.label}</span>
        </button>
      ))}
      <button onClick={onMore}>
        <Icon symbol="•••" />
        <span>More</span>
      </button>
    </nav>
  );
}

function MobileDrawer({
  open,
  route,
  navigate,
  onClose,
}: {
  open: boolean;
  route: RouteId;
  navigate: (path: string) => void;
  onClose: () => void;
}) {
  if (!open) return null;
  return (
    <div className="drawer-backdrop" onMouseDown={onClose}>
      <aside
        className="mobile-drawer"
        onMouseDown={(event) => event.stopPropagation()}
        aria-label="All navigation"
      >
        <div className="mobile-drawer__head">
          <Brand />
          <button className="icon-button" onClick={onClose} aria-label="Close menu">
            <Icon symbol="×" />
          </button>
        </div>
        <nav>
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              className={
                route === item.id || (route === "incident" && item.id === "incidents")
                  ? "active"
                  : ""
              }
              onClick={() => {
                navigate(item.path);
                onClose();
              }}
            >
              <Icon symbol={item.icon} />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="mobile-drawer__foot">
          <span className="avatar">OP</span>
          <span>
            <b>Operator</b>
            <small>Signed-in session</small>
          </span>
        </div>
      </aside>
    </div>
  );
}

function ConnectionBanner({
  mode,
  online,
  error,
  onRetry,
}: {
  mode: DataMode;
  online: boolean;
  error: string | null;
  onRetry: () => void;
}) {
  if (!error && mode === "live") return null;
  return (
    <div
      className={`connection-banner connection-banner--${online ? "warning" : "offline"}`}
      role="status"
    >
      <Icon symbol={online ? "◇" : "⊘"} />
      <span>
        <b>{online ? (mode === "demo" ? "Demo snapshot" : "Partial data") : "Offline mode"}</b>
        {error ?? "Live API data is not available."}
      </span>
      {online && <button onClick={onRetry}>Retry</button>}
    </div>
  );
}

function AppHeader({
  nodes,
  mode,
  online,
  refreshing,
  liveUpdates,
  onRefresh,
  onNotifications,
  onMenu,
  onLogout,
  logoutBusy,
}: {
  nodes: ClusterNode[];
  mode: DataMode;
  online: boolean;
  refreshing: boolean;
  liveUpdates: boolean;
  onRefresh: () => void;
  onNotifications: () => void;
  onMenu: () => void;
  onLogout: () => void;
  logoutBusy: boolean;
}) {
  const clusterHealth = aggregateNodeHealth(nodes);
  const reportedLags = nodes.flatMap((node) => node.syncLag ?? []);
  const worstLag = reportedLags.length ? Math.max(...reportedLags) : null;
  const completeLagTelemetry = nodes.length > 0 && nodes.every((node) => node.syncLag != null);
  const syncHealth: Health = !online
    ? "offline"
    : clusterHealth === "healthy" && completeLagTelemetry
      ? worstLag != null && worstLag > 10
        ? "degraded"
        : "healthy"
      : clusterHealth;
  const syncLabel =
    syncHealth === "healthy" && worstLag != null
      ? `${worstLag.toFixed(1)}s`
      : syncHealth === "unknown"
        ? "telemetry unavailable"
        : syncHealth;
  return (
    <header className="app-header">
      <div className="app-header__mobile-brand">
        <button className="icon-button" onClick={onMenu} aria-label="Open menu">
          <Icon symbol="≡" />
        </button>
        <Brand />
      </div>
      <div className="node-chip" title="Latest cluster inventory">
        <StatusDot health={online ? (nodes.length ? clusterHealth : "paused") : "offline"} />
        <span>
          <small>Cluster inventory</small>
          <b>{nodes.length ? `${nodes.length} known node(s)` : "No node records"}</b>
        </span>
      </div>
      <div className="app-header__status">
        <span className="header-signal">
          <StatusDot health={syncHealth} />
          <span>
            Sync <b>{syncLabel}</b>
          </span>
        </span>
        <span className="header-signal">
          <StatusDot health={liveUpdates ? "healthy" : mode === "live" ? "degraded" : "paused"} />
          <span>
            {liveUpdates
              ? "Live"
              : mode === "live"
                ? "Polling"
                : mode === "cached"
                  ? "Cached"
                  : "Demo"}
          </span>
        </span>
        <button
          className={`icon-button refresh-button ${refreshing ? "is-spinning" : ""}`}
          onClick={onRefresh}
          aria-label="Refresh cluster data"
        >
          <Icon symbol="↻" />
        </button>
        <button className="button button--quiet notifications-button" onClick={onNotifications}>
          <Icon symbol="◉" />
          <span>Notifications</span>
        </button>
        <button
          className="button button--quiet button--small"
          type="button"
          onClick={onLogout}
          disabled={logoutBusy}
          aria-label="Log out of Alert Hub"
        >
          <Icon symbol="↪" />
          <span>{logoutBusy ? "Logging out…" : "Log out"}</span>
        </button>
      </div>
    </header>
  );
}

export function AlertHubApp({ appName = "Alert Hub" }: { appName?: string }) {
  return (
    <AppNameContext.Provider value={appName}>
      <AlertHubRuntime />
    </AppNameContext.Provider>
  );
}

function AlertHubRuntime() {
  const queryClient = useQueryClient();
  const auth = useAuthSession();
  const {
    data,
    mode,
    online,
    refreshing,
    error,
    liveUpdates,
    auditLoadingMore,
    auditLoadError,
    loadMoreAudit,
    refresh,
    setData,
  } = useHubData(
    auth.state.status === "authenticated" || auth.state.status === "offline",
    auth.state.status === "demo",
  );
  const { route, navigate } = useRoute();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenu, setMobileMenu] = useState(false);
  const [sourceWizard, setSourceWizard] = useState(false);
  const [notificationModal, setNotificationModal] = useState(false);
  const [logoutBusy, setLogoutBusy] = useState(false);
  const readOnly = auth.state.status === "demo" || auth.state.status === "offline";
  const effectiveOnline = auth.state.status === "offline" ? false : online;
  const refreshAll = async () => {
    if (auth.state.status === "offline") await auth.recover();
    await refresh();
  };
  const openNotifications = () => {
    if (!readOnly) setNotificationModal(true);
  };
  const logout = async () => {
    setLogoutBusy(true);
    try {
      await auth.logout();
    } catch {
      // Local credentials and the authenticated read cache are cleared even if the node is offline.
    } finally {
      queryClient.clear();
      setLogoutBusy(false);
    }
  };

  useEffect(() => {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker
        .register("/sw.js", { scope: "/" })
        .then(() => navigator.serviceWorker.ready)
        .then((registration) => {
          cacheLoadedShellAssets(registration);
          // Authentication restore runs concurrently with registration. A null
          // partition here is not proof of logout and must never erase the only
          // verified cache needed for a cold offline start.
          if (memorySessionId) pruneReadCaches(memorySessionId);
        })
        .catch(() => undefined);
    }
    const badgeNavigator = navigator as Navigator & { clearAppBadge?: () => Promise<void> };
    badgeNavigator.clearAppBadge?.().catch(() => undefined);
  }, []);

  if (auth.state.status === "checking") return <AuthLoading />;
  if (auth.state.status === "required") {
    return <AuthGate onAuthenticated={auth.authenticate} onDemo={auth.useDemo} />;
  }

  const view = (() => {
    switch (route.id) {
      case "incidents":
        return <IncidentsPage incidents={data.incidents} navigate={navigate} />;
      case "incident":
        return (
          <IncidentDetailPage
            incidentId={route.incidentId ?? ""}
            incidents={data.incidents}
            navigate={navigate}
            setData={setData}
            readOnly={readOnly}
          />
        );
      case "reachability":
        return (
          <ReachabilityPage
            cells={data.reachability}
            meta={data.reachabilityMeta}
            grafanaUrl={data.summary.grafanaUrl}
            datasources={data.datasources}
            readOnly={readOnly}
            onRefresh={() => void refresh()}
            setData={setData}
          />
        );
      case "sources":
        return (
          <SourcesPage
            sources={data.sources}
            readOnly={readOnly}
            onAdd={() => setSourceWizard(true)}
            setData={setData}
          />
        );
      case "channels":
        return (
          <ChannelsPage
            channels={data.channels}
            routes={data.routes}
            outboxPending={data.summary.outboxPending}
            readOnly={readOnly}
            setData={setData}
            onNotifications={openNotifications}
          />
        );
      case "devices":
        return (
          <DevicesPage
            devices={data.devices}
            readOnly={readOnly}
            setData={setData}
            onNotifications={openNotifications}
          />
        );
      case "cluster":
        return (
          <ClusterPage
            nodes={data.nodes}
            meta={data.clusterMeta}
            outboxPending={data.summary.outboxPending}
            onRefresh={() => void refresh()}
          />
        );
      case "audit":
        return (
          <AuditPage
            items={data.audit}
            nextOffset={data.auditNextOffset}
            total={data.auditTotal}
            nodes={data.nodes}
            loadingMore={auditLoadingMore}
            loadError={auditLoadError}
            onLoadMore={() => void loadMoreAudit()}
            readOnly={readOnly}
          />
        );
      case "settings":
        return <SettingsPage nodes={data.nodes} readOnly={readOnly} />;
      default:
        return (
          <OverviewPage
            data={data}
            readOnly={readOnly}
            navigate={navigate}
            onNotifications={openNotifications}
          />
        );
    }
  })();

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <Sidebar
        route={route.id}
        navigate={navigate}
        collapsed={sidebarCollapsed}
        onCollapse={() => setSidebarCollapsed((value) => !value)}
        incidents={data.incidents}
        nodes={data.nodes}
        operator={
          auth.state.status === "authenticated"
            ? String(auth.state.user.username ?? "operator")
            : auth.state.status === "offline"
              ? "offline · read-only"
              : "demo-preview"
        }
      />
      <div className="app-frame">
        <AppHeader
          nodes={data.nodes}
          mode={mode}
          online={effectiveOnline}
          refreshing={refreshing}
          liveUpdates={liveUpdates}
          onRefresh={() => void refreshAll()}
          onNotifications={openNotifications}
          onMenu={() => setMobileMenu(true)}
          onLogout={() => void logout()}
          logoutBusy={logoutBusy}
        />
        <main id="main-content" className="main-content">
          <ConnectionBanner
            mode={mode}
            online={effectiveOnline}
            error={error}
            onRetry={() => void refreshAll()}
          />
          {view}
        </main>
      </div>
      <MobileNav route={route.id} navigate={navigate} onMore={() => setMobileMenu(true)} />
      <MobileDrawer
        open={mobileMenu}
        route={route.id}
        navigate={navigate}
        onClose={() => setMobileMenu(false)}
      />
      {sourceWizard && (
        <SourceWizard
          onClose={() => setSourceWizard(false)}
          onCreated={(source) => {
            setData((current) => ({ ...current, sources: [source, ...current.sources] }));
          }}
        />
      )}
      {notificationModal && (
        <NotificationOnboarding
          onClose={() => setNotificationModal(false)}
          onSubscribed={() => void refresh()}
        />
      )}
    </div>
  );
}

function KpiCard({
  label,
  value,
  note,
  tone,
  spark = [],
}: {
  label: string;
  value: string | number;
  note: string;
  tone: "critical" | "warning" | "success" | "neutral";
  spark?: number[];
}) {
  const max = Math.max(...spark, 1);
  return (
    <div className={`kpi-card kpi-card--${tone}`}>
      <div className="kpi-card__top">
        <span>{label}</span>
        <i aria-hidden="true" />
      </div>
      <strong>{value}</strong>
      <div className="kpi-card__bottom">
        <small>{note}</small>
        {spark.length > 0 && (
          <span className="sparkline" aria-hidden="true">
            {spark.map((point, index) => (
              <i key={index} style={{ height: `${Math.max(14, (point / max) * 100)}%` }} />
            ))}
          </span>
        )}
      </div>
    </div>
  );
}

function GrafanaLink({ url }: { url: string | null }) {
  if (!url) {
    return (
      <span className="grafana-link grafana-link--missing" aria-label="Grafana not configured">
        <Icon symbol="∿" /> Grafana not configured
      </span>
    );
  }
  return (
    <a
      className="button button--quiet grafana-link"
      href={url}
      target="_blank"
      rel="noopener noreferrer"
    >
      <Icon symbol="∿" /> Open Grafana
    </a>
  );
}

function MetricEvidenceValue({
  result,
  kind,
}: {
  result: FixedMetricResult;
  kind: "alerts" | "health" | "jobs";
}) {
  if (result.status === "not_configured") {
    return (
      <>
        <strong>Not configured</strong>
        <small>Add an enabled Prometheus datasource.</small>
      </>
    );
  }
  if (result.status === "unavailable" || result.status === "unknown") {
    return (
      <>
        <strong>Unavailable</strong>
        <small>No verified sample was returned.</small>
      </>
    );
  }
  const active = result.samples.filter((sample) => sample.value > 0).length;
  const failed = result.samples.filter((sample) => sample.value <= 0).length;
  return (
    <>
      <strong>
        {kind === "alerts" ? active : `${active}/${result.samples.length}`}
        <span>{kind === "alerts" ? " firing" : " up"}</span>
      </strong>
      <small>
        {kind === "alerts"
          ? active
            ? "Prometheus reports active firing alerts."
            : "No firing alert samples returned."
          : failed
            ? `${failed} target${failed === 1 ? "" : "s"} down.`
            : result.samples.length
              ? "All returned targets are up."
              : "No target samples returned."}
      </small>
    </>
  );
}

function PrometheusEvidenceGrid({ data }: { data: HubData }) {
  const reachable = data.reachability.filter((cell) => cell.success).length;
  const reachabilityConfigured = data.reachabilityMeta.status !== "not_configured";
  const reportedLags = data.nodes.flatMap((node) => node.syncLag ?? []);
  return (
    <section className="prometheus-evidence" aria-labelledby="prometheus-evidence-title">
      <div className="prometheus-evidence__head">
        <span>
          <span className="eyebrow">Server-owned PromQL</span>
          <h2 id="prometheus-evidence-title">Prometheus operational evidence</h2>
        </span>
        <GrafanaLink url={data.summary.grafanaUrl} />
      </div>
      <div className="prometheus-evidence-grid">
        <Panel eyebrow="probe_success" title="Regional reachability">
          <div className="metric-evidence-value">
            <strong>
              {reachabilityConfigured && data.reachability.length
                ? `${reachable}/${data.reachability.length}`
                : reachabilityConfigured
                  ? "No samples"
                  : "Not configured"}
              {reachabilityConfigured && data.reachability.length ? <span> reachable</span> : null}
            </strong>
            <small>{data.reachabilityMeta.detail || "No verified probe result returned."}</small>
          </div>
        </Panel>
        <Panel eyebrow='ALERTS{alertstate="firing"}' title="Firing alerts">
          <div className="metric-evidence-value">
            <MetricEvidenceValue result={data.fixedMetrics.firingAlerts} kind="alerts" />
          </div>
        </Panel>
        <Panel eyebrow="up · key jobs" title="Prometheus / Alertmanager / Blackbox">
          <div className="metric-evidence-value">
            <MetricEvidenceValue result={data.fixedMetrics.keyJobsUp} kind="jobs" />
          </div>
        </Panel>
        <Panel eyebrow="up · Alert Hub jobs" title="Alert Hub sync / app health">
          <div className="metric-evidence-value">
            <MetricEvidenceValue result={data.fixedMetrics.alertHubHealth} kind="health" />
            <small>
              {reportedLags.length
                ? `Cluster projection max sync lag ${Math.max(...reportedLags).toFixed(1)}s.`
                : "Cluster sync lag was not reported."}
            </small>
          </div>
        </Panel>
      </div>
    </section>
  );
}

function OverviewPage({
  data,
  readOnly,
  navigate,
  onNotifications,
}: {
  data: HubData;
  readOnly: boolean;
  navigate: (path: string) => void;
  onNotifications: () => void;
}) {
  const appName = useContext(AppNameContext);
  const active = data.incidents.filter((incident) => incident.status !== "resolved");
  const critical = active.filter((incident) => incident.severity === "critical");
  const healthyNodes = data.nodes.filter((node) => node.health === "healthy").length;
  const unknownNodes = data.nodes.filter((node) => node.health === "unknown").length;
  const impairedNodes = data.nodes.filter((node) =>
    ["degraded", "offline"].includes(node.health),
  ).length;
  const reachable = data.reachability.filter((cell) => cell.success).length;
  const reachRate = data.reachability.length
    ? Math.round((reachable / data.reachability.length) * 100)
    : null;
  const reportedQueues = data.nodes.flatMap((node) => node.queue ?? []);
  const reportedLags = data.nodes.flatMap((node) => node.syncLag ?? []);
  const latest = [...active].sort((a, b) => Date.parse(b.lastEventAt) - Date.parse(a.lastEventAt));
  return (
    <div className="page-stack overview-page">
      <PageHeading
        eyebrow="Operational console"
        title="System overview"
        description="One operational view across every region, even when the network is not whole."
        actions={
          <>
            <button className="button button--quiet" onClick={onNotifications} disabled={readOnly}>
              <Icon symbol="◉" />
              Enable alerts
            </button>
            <button className="button button--primary" onClick={() => navigate("/incidents")}>
              <Icon symbol="!" />
              Open incidents
            </button>
          </>
        }
      />

      <div className="kpi-grid">
        <KpiCard
          label="Firing now"
          value={data.summary.open}
          note={critical.length ? `${critical.length} critical` : "No critical alerts"}
          tone={critical.length ? "critical" : "success"}
          spark={readOnly ? [2, 2, 3, 2, 4, 3, data.summary.open] : []}
        />
        <KpiCard
          label="Acknowledged"
          value={data.summary.acknowledged}
          note="From the incident ledger"
          tone={data.summary.acknowledged ? "warning" : "neutral"}
          spark={readOnly ? [0, 1, 1, 2, 1, 1, data.summary.acknowledged] : []}
        />
        <KpiCard
          label="Cluster inventory"
          value={data.nodes.length ? data.nodes.length : "Unknown"}
          note={
            !data.nodes.length
              ? "No node records returned"
              : unknownNodes
                ? `${unknownNodes} status unknown`
                : healthyNodes === data.nodes.length
                  ? "All nodes healthy"
                  : `${impairedNodes} needs attention`
          }
          tone={
            !data.nodes.length || unknownNodes
              ? "neutral"
              : healthyNodes === data.nodes.length
                ? "success"
                : "warning"
          }
          spark={
            readOnly
              ? data.nodes.flatMap((node) => node.syncLag ?? []).map((lag) => Math.max(1, 14 - lag))
              : []
          }
        />
        <KpiCard
          label="Delivery rate"
          value={
            data.summary.deliveryRate == null
              ? "Not measured"
              : `${data.summary.deliveryRate.toFixed(1)}%`
          }
          note={
            data.summary.deliveries24h == null
              ? "Delivery metrics unavailable"
              : data.summary.deliveries24h === 0
                ? "No delivery attempts in 24h"
                : `${data.summary.deliveries24h} attempts in 24h`
          }
          tone={
            data.summary.deliveryRate == null
              ? "neutral"
              : data.summary.deliveryRate > 97
                ? "success"
                : "warning"
          }
          spark={
            readOnly && data.summary.deliveryRate != null
              ? [96, 98, 97, 99, 99, 98, data.summary.deliveryRate]
              : []
          }
        />
      </div>

      <PrometheusEvidenceGrid data={data} />

      <div className="overview-grid">
        <Panel
          className="overview-incidents"
          eyebrow="Needs attention"
          title="Active incidents"
          action={
            <button className="text-button" onClick={() => navigate("/incidents")}>
              View all <Icon symbol="→" />
            </button>
          }
        >
          {latest.length ? (
            <div className="incident-compact-list">
              {latest.slice(0, 4).map((incident) => (
                <button
                  key={incident.id}
                  className="incident-compact"
                  onClick={() => navigate(`/incidents/${incident.id}`)}
                >
                  <span
                    className={`incident-compact__signal incident-compact__signal--${incident.severity}`}
                    aria-hidden="true"
                  />
                  <span className="incident-compact__body">
                    <span>
                      <b>{incident.title}</b>
                      <SeverityBadge severity={incident.severity} />
                    </span>
                    <small>
                      {incident.source} · {incident.region} → {incident.target}
                    </small>
                  </span>
                  <span className="incident-compact__meta">
                    <IncidentStatusBadge status={incident.status} />
                    <small>{formatRelative(incident.lastEventAt)}</small>
                  </span>
                  <Icon symbol="›" />
                </button>
              ))}
            </div>
          ) : (
            <EmptyState
              icon="✓"
              title="No active incidents returned"
              message="The current verified incident snapshot contains no active records."
            />
          )}
        </Panel>

        <Panel
          className="overview-cluster"
          eyebrow="Peer health"
          title="Cluster nodes"
          action={
            <button className="text-button" onClick={() => navigate("/cluster")}>
              Details <Icon symbol="→" />
            </button>
          }
        >
          <div className="node-list">
            {data.nodes.map((node) => (
              <div className="node-row" key={node.id}>
                <span className={`flag-tag flag-tag--${node.health}`}>{node.region}</span>
                <span className="node-row__name">
                  <b>{node.name}</b>
                  <small>
                    {node.city} · {node.version}
                  </small>
                </span>
                <span className="node-row__metric">
                  <small>Sync lag</small>
                  <b className={node.syncLag != null && node.syncLag > 10 ? "text-warning" : ""}>
                    {node.syncLag == null ? "Unknown" : `${node.syncLag.toFixed(1)}s`}
                  </b>
                </span>
                <span className="node-row__health">
                  <StatusDot health={node.health} />
                  {titleCase(node.health)}
                </span>
              </div>
            ))}
          </div>
          <div className="cluster-summary-strip">
            <span>
              <Icon symbol="⇄" />
              <b>
                {reportedQueues.length
                  ? reportedQueues.reduce((sum, queue) => sum + queue, 0)
                  : "Unknown"}
              </b>{" "}
              queued
            </span>
            <span>
              <Icon symbol="⌖" />
              <b>
                {reportedLags.length ? `${Math.max(...reportedLags).toFixed(1)}s` : "Unknown"}
              </b>{" "}
              max lag
            </span>
          </div>
        </Panel>
      </div>

      <div className="overview-grid overview-grid--lower">
        <Panel
          eyebrow="Prometheus · probe_success"
          title="Regional reachability"
          action={
            <button className="text-button" onClick={() => navigate("/reachability")}>
              {reachRate == null ? "No samples" : `${reachRate}% reachable`} <Icon symbol="→" />
            </button>
          }
        >
          <ReachabilityMatrix cells={data.reachability} compact />
          <div className="panel-footnote">
            <span>
              <i className="legend-dot legend-dot--healthy" />
              Reachable
            </span>
            <span>
              <i className="legend-dot legend-dot--failed" />
              Failed
            </span>
            <span>Updated {formatRelative(data.reachability[0]?.checkedAt ?? "")}</span>
          </div>
        </Panel>
        <Panel
          eyebrow="Last 24 hours"
          title="Delivery channels"
          action={
            <button className="text-button" onClick={() => navigate("/channels")}>
              Manage <Icon symbol="→" />
            </button>
          }
        >
          <div className="channel-mini-list">
            {data.channels
              .filter((channel) => channel.enabled)
              .slice(0, 4)
              .map((channel) => (
                <div className="channel-mini" key={channel.id}>
                  <ChannelIcon kind={channel.kind} />
                  <span>
                    <b>{channel.name}</b>
                    <small>
                      {channel.delivered24h} delivered ·{" "}
                      {channel.successRate == null
                        ? "not exercised"
                        : `${channel.successRate.toFixed(1)}%`}
                    </small>
                  </span>
                  <StatusDot health={channel.health} />
                </div>
              ))}
          </div>
          <button className="onboarding-callout" onClick={onNotifications} disabled={readOnly}>
            <span className="onboarding-callout__icon">
              <Icon symbol="◉" />
            </span>
            <span>
              <b>Make this device an alert endpoint</b>
              <small>Enable Web Push for failover-ready notifications.</small>
            </span>
            <Icon symbol="→" />
          </button>
        </Panel>
      </div>

      <div className="overview-footer">
        <span>
          <StatusDot health={data.sources.length ? "unknown" : "paused"} /> {appName} returned{" "}
          {data.sources.length} configured source{data.sources.length === 1 ? "" : "s"} on this
          read.
        </span>
      </div>
    </div>
  );
}

function IncidentsPage({
  incidents,
  navigate,
}: {
  incidents: Incident[];
  navigate: (path: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"active" | "all" | IncidentStatus>("active");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const filtered = useMemo(
    () =>
      incidents.filter((incident) => {
        const searchMatch =
          `${incident.title} ${incident.description} ${incident.source} ${Object.values(incident.labels).join(" ")}`
            .toLowerCase()
            .includes(query.toLowerCase());
        const statusMatch =
          status === "all" ||
          (status === "active" ? incident.status !== "resolved" : incident.status === status);
        const severityMatch = severity === "all" || incident.severity === severity;
        return searchMatch && statusMatch && severityMatch;
      }),
    [incidents, query, severity, status],
  );
  const counts = {
    active: incidents.filter((item) => item.status !== "resolved").length,
    acknowledged: incidents.filter((item) => item.status === "acknowledged").length,
    resolved: incidents.filter((item) => item.status === "resolved").length,
  };
  return (
    <div className="page-stack incidents-page">
      <PageHeading
        eyebrow="Incident ledger"
        title="Incidents"
        description="A convergent history of every firing, operator action, and delivery outcome."
      />
      <div className="incident-tabs" role="tablist" aria-label="Incident status">
        <button className={status === "active" ? "active" : ""} onClick={() => setStatus("active")}>
          Active <span>{counts.active}</span>
        </button>
        <button
          className={status === "acknowledged" ? "active" : ""}
          onClick={() => setStatus("acknowledged")}
        >
          Acknowledged <span>{counts.acknowledged}</span>
        </button>
        <button
          className={status === "resolved" ? "active" : ""}
          onClick={() => setStatus("resolved")}
        >
          Resolved <span>{counts.resolved}</span>
        </button>
        <button className={status === "all" ? "active" : ""} onClick={() => setStatus("all")}>
          All <span>{incidents.length}</span>
        </button>
      </div>
      <Panel className="incident-table-panel">
        <div className="filter-bar">
          <label className="search-field">
            <Icon symbol="⌕" />
            <span className="sr-only">Search incidents</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search title, source, label…"
            />
            {query && (
              <button onClick={() => setQuery("")} aria-label="Clear search">
                ×
              </button>
            )}
          </label>
          <label className="select-field">
            <span>Severity</span>
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value as "all" | Severity)}
            >
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
              <option value="unknown">Unknown</option>
            </select>
          </label>
          <span className="filter-result">
            {filtered.length} result{filtered.length === 1 ? "" : "s"}
          </span>
        </div>
        {filtered.length ? (
          <div className="incidents-table-wrap">
            <table className="incidents-table">
              <thead>
                <tr>
                  <th>Incident</th>
                  <th>Status</th>
                  <th>Source / region</th>
                  <th>Target</th>
                  <th>Last event</th>
                  <th>
                    <span className="sr-only">Open</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((incident) => (
                  <tr key={incident.id} onClick={() => navigate(`/incidents/${incident.id}`)}>
                    <td>
                      <span className={`table-severity table-severity--${incident.severity}`} />
                      <span>
                        <b>{incident.title}</b>
                        <small>
                          <SeverityBadge severity={incident.severity} />
                          {compactId(incident.id)}
                        </small>
                      </span>
                    </td>
                    <td>
                      <IncidentStatusBadge status={incident.status} />
                    </td>
                    <td>
                      <b className="table-regular">{incident.source}</b>
                      <small>{incident.region}</small>
                    </td>
                    <td>
                      <code>{incident.target}</code>
                    </td>
                    <td>
                      <b className="table-regular">{formatRelative(incident.lastEventAt)}</b>
                      <small>{formatDate(incident.lastEventAt)}</small>
                    </td>
                    <td>
                      <button className="row-open" aria-label={`Open ${incident.title}`}>
                        <Icon symbol="›" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon="⌕"
            title="No incidents match"
            message="Try clearing a filter or searching for a different label."
            action={
              <button
                className="button button--quiet"
                onClick={() => {
                  setQuery("");
                  setStatus("all");
                  setSeverity("all");
                }}
              >
                Clear filters
              </button>
            }
          />
        )}
      </Panel>
    </div>
  );
}

function IncidentDetailPage({
  incidentId,
  incidents,
  navigate,
  setData,
  readOnly,
}: {
  incidentId: string;
  incidents: Incident[];
  navigate: (path: string) => void;
  setData: React.Dispatch<React.SetStateAction<HubData>>;
  readOnly: boolean;
}) {
  const incident = incidents.find((item) => item.id === incidentId);
  const [busy, setBusy] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [commentOpen, setCommentOpen] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const applyDetail = useCallback(
    (payload: unknown) => {
      const detail = normalizeIncident(payload, 0);
      setData((current) => ({
        ...current,
        incidents: current.incidents.some((item) => item.id === detail.id)
          ? current.incidents.map((item) => (item.id === detail.id ? detail : item))
          : [detail, ...current.incidents],
      }));
    },
    [setData],
  );
  useEffect(() => {
    if (!incidentId || !memoryAccessToken) return;
    let active = true;
    void getJson(`/incidents/${encodeURIComponent(incidentId)}`)
      .then((result) => {
        if (!active) return;
        applyDetail(result.payload);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [applyDetail, incidentId]);
  if (!incident) {
    return (
      <EmptyState
        icon="!"
        title="Incident not found"
        message="It may have been removed from this local snapshot."
        action={
          <button className="button button--quiet" onClick={() => navigate("/incidents")}>
            Back to incidents
          </button>
        }
      />
    );
  }
  const mutate = async (action: "acknowledge" | "resolve" | "silence") => {
    if (readOnly) return;
    setBusy(action);
    setActionError(null);
    try {
      await mutationJson(`/incidents/${encodeURIComponent(incident.id)}/${action}`, {
        method: "POST",
        body: "{}",
      });
      const detail = await getJson(`/incidents/${encodeURIComponent(incident.id)}`);
      applyDetail(detail.payload);
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Incident action failed.");
    } finally {
      setBusy(null);
    }
  };
  const submitComment = async (event: FormEvent) => {
    event.preventDefault();
    const text = comment.trim();
    if (!text || readOnly) return;
    setBusy("comment");
    setActionError(null);
    try {
      await mutationJson(`/incidents/${encodeURIComponent(incident.id)}/comments`, {
        method: "POST",
        body: JSON.stringify({ body: text }),
      });
      const detail = await getJson(`/incidents/${encodeURIComponent(incident.id)}`);
      applyDetail(detail.payload);
      setComment("");
      setCommentOpen(false);
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Comment could not be saved.");
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="page-stack incident-detail-page">
      <button className="breadcrumb-button" onClick={() => navigate("/incidents")}>
        <Icon symbol="←" />
        Incidents
      </button>
      <div className="incident-detail-head">
        <div
          className={`incident-detail-head__signal incident-detail-head__signal--${incident.severity}`}
        >
          <Icon symbol={incident.severity === "critical" ? "!" : "△"} />
        </div>
        <div className="incident-detail-head__body">
          <div className="incident-detail-head__badges">
            <SeverityBadge severity={incident.severity} />
            <IncidentStatusBadge status={incident.status} />
            <span className="mono-tag">{compactId(incident.id)}</span>
          </div>
          <h1>{incident.title}</h1>
          <p>{incident.description}</p>
          <div className="incident-detail-head__meta">
            <span>
              <Icon symbol="⌖" />
              {incident.region} → {incident.target}
            </span>
            <span>
              <Icon symbol="∷" />
              {incident.source}
            </span>
            <span>
              <Icon symbol="◷" />
              Started {formatRelative(incident.startsAt)}
            </span>
          </div>
        </div>
        <div className="incident-actions">
          {incident.status !== "acknowledged" && incident.status !== "resolved" && (
            <button
              className="button button--primary"
              disabled={busy !== null || readOnly}
              onClick={() => void mutate("acknowledge")}
            >
              <Icon symbol="✓" />
              {busy === "acknowledge" ? "Saving…" : "Acknowledge"}
            </button>
          )}
          {incident.status !== "resolved" && (
            <button
              className="button button--quiet"
              disabled={busy !== null || readOnly}
              onClick={() => void mutate("resolve")}
            >
              <Icon symbol="◎" />
              Resolve
            </button>
          )}
          {incident.status !== "silenced" && incident.status !== "resolved" && (
            <button
              className="button button--quiet button--icon-only"
              disabled={busy !== null || readOnly}
              onClick={() => void mutate("silence")}
              aria-label="Silence incident"
            >
              <Icon symbol="∿" />
            </button>
          )}
        </div>
      </div>
      {actionError && (
        <div className="permission-message permission-message--warning" role="alert">
          <Icon symbol="!" /> {actionError}
        </div>
      )}
      <div className="incident-detail-grid">
        <Panel
          className="timeline-panel"
          eyebrow="Append-only history"
          title="Incident timeline"
          action={
            readOnly ? null : (
              <button
                className="button button--quiet button--small"
                onClick={() => setCommentOpen((value) => !value)}
              >
                <Icon symbol="+" />
                Add comment
              </button>
            )
          }
        >
          {commentOpen && (
            <form className="comment-composer" onSubmit={submitComment}>
              <label>
                <span className="sr-only">Incident comment</span>
                <textarea
                  value={comment}
                  onChange={(event) => setComment(event.target.value)}
                  autoFocus
                  placeholder="Add context for the next operator…"
                />
              </label>
              <div>
                <button type="button" className="text-button" onClick={() => setCommentOpen(false)}>
                  Cancel
                </button>
                <button
                  className="button button--primary button--small"
                  disabled={!comment.trim() || busy === "comment"}
                >
                  {busy === "comment" ? "Posting…" : "Post comment"}
                </button>
              </div>
            </form>
          )}
          {incident.events.length ? (
            <div className="timeline">
              {incident.events.map((event, index) => (
                <div className="timeline-item" key={event.id}>
                  <div className="timeline-item__rail">
                    <span className={`timeline-icon timeline-icon--${event.type}`}>
                      <Icon
                        symbol={
                          event.type === "firing"
                            ? "!"
                            : event.type.includes("delivery")
                              ? "↗"
                              : event.type === "resolved"
                                ? "✓"
                                : event.type === "commented"
                                  ? "“"
                                  : "•"
                        }
                      />
                    </span>
                    {index < incident.events.length - 1 && <i />}
                  </div>
                  <div className="timeline-item__content">
                    <div>
                      <b>{event.label}</b>
                      <time>{formatDate(event.at, true)}</time>
                    </div>
                    <p>{event.detail}</p>
                    <span>
                      <code>{event.node}</code>
                      {event.actor && <> · {event.actor}</>}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon="∷"
              title="No timeline returned"
              message="This node did not return incident events for the selected record."
            />
          )}
        </Panel>
        <div className="incident-detail-side">
          <Panel eyebrow="Current projection" title="Incident context">
            <dl className="detail-list">
              <div>
                <dt>Incident ID</dt>
                <dd>
                  <code>{compactId(incident.id)}</code>
                </dd>
              </div>
              <div>
                <dt>Source</dt>
                <dd>{incident.source}</dd>
              </div>
              <div>
                <dt>First seen</dt>
                <dd>{formatDate(incident.startsAt, true)}</dd>
              </div>
              <div>
                <dt>Last event</dt>
                <dd>{formatDate(incident.lastEventAt, true)}</dd>
              </div>
              <div>
                <dt>Timeline entries</dt>
                <dd>{incident.events.length}</dd>
              </div>
            </dl>
          </Panel>
          <Panel eyebrow="Preserved payload" title="Labels & annotations">
            <div className="metadata-block">
              <h3>
                Labels <span>{Object.keys(incident.labels).length}</span>
              </h3>
              {Object.entries(incident.labels).map(([key, value]) => (
                <div key={key}>
                  <code>{key}</code>
                  <span>{value}</span>
                </div>
              ))}
            </div>
            <div className="metadata-block">
              <h3>
                Annotations <span>{Object.keys(incident.annotations).length}</span>
              </h3>
              {Object.entries(incident.annotations).map(([key, value]) => (
                <div key={key}>
                  <code>{key}</code>
                  <span className="annotation-value">{value}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

function ReachabilityMatrix({
  cells,
  compact = false,
}: {
  cells: ReachabilityCell[];
  compact?: boolean;
}) {
  const sources = [...new Set(cells.map((cell) => cell.source))];
  const targets = [...new Set(cells.map((cell) => cell.target))];
  if (!cells.length)
    return (
      <EmptyState
        icon="∿"
        title="No probe data yet"
        message="Connect a Prometheus datasource to populate the regional matrix."
      />
    );
  return (
    <div
      className={`reachability-matrix ${compact ? "reachability-matrix--compact" : ""}`}
      style={{ ["--target-count" as string]: targets.length }}
      role="region"
      aria-label="Regional reachability matrix"
      tabIndex={0}
    >
      <div className="reachability-matrix__corner">Probe from</div>
      {targets.map((target) => (
        <div className="reachability-matrix__target" key={target}>
          <b>{target}</b>
          {!compact && <small>target</small>}
        </div>
      ))}
      {sources.map((source) => (
        <div className="reachability-matrix__row" key={source}>
          <div className="reachability-matrix__source">
            <span>{source.slice(0, 2).toUpperCase()}</span>
            <b>{source}</b>
          </div>
          {targets.map((target) => {
            const cell = cells.find((item) => item.source === source && item.target === target);
            const status = !cell
              ? "unknown"
              : cell.success
                ? cell.latency != null && cell.latency > 200
                  ? "slow"
                  : "healthy"
                : "failed";
            return (
              <div
                className={`reachability-cell reachability-cell--${status}`}
                key={target}
                title={
                  cell
                    ? `${source} → ${target}: ${
                        cell.success
                          ? cell.latency == null
                            ? "reachable"
                            : `${cell.latency} ms`
                          : "failed"
                      }`
                    : "No data"
                }
              >
                <span aria-hidden="true">
                  {status === "failed" ? "×" : status === "unknown" ? "·" : "✓"}
                </span>
                <b>
                  {cell?.success
                    ? cell.latency == null
                      ? "Reachable"
                      : `${cell.latency} ms`
                    : status === "failed"
                      ? "Failed"
                      : "No data"}
                </b>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

function ReachabilityPage({
  cells,
  meta,
  grafanaUrl,
  datasources,
  readOnly,
  onRefresh,
  setData,
}: {
  cells: ReachabilityCell[];
  meta: ReachabilityMeta;
  grafanaUrl: string | null;
  datasources: PrometheusDatasource[];
  readOnly: boolean;
  onRefresh: () => void;
  setData: React.Dispatch<React.SetStateAction<HubData>>;
}) {
  const reachable = cells.filter((cell) => cell.success).length;
  const failed = cells.filter((cell) => !cell.success).length;
  const [adding, setAdding] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const updateDatasource = (value: PrometheusDatasource) => {
    setData((current) => ({
      ...current,
      datasources: current.datasources.some((item) => item.id === value.id)
        ? current.datasources.map((item) => (item.id === value.id ? value : item))
        : [value, ...current.datasources],
    }));
  };
  const toggleDatasource = async (datasource: PrometheusDatasource) => {
    setBusy(datasource.id);
    setActionError(null);
    try {
      const body = await mutationJson(
        `/prometheus-datasources/${encodeURIComponent(datasource.id)}`,
        { method: "PATCH", body: JSON.stringify({ enabled: !datasource.enabled }) },
      );
      updateDatasource(normalizeDatasource(body, 0));
      onRefresh();
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Datasource update failed.");
    } finally {
      setBusy(null);
    }
  };
  const removeDatasource = async (datasource: PrometheusDatasource) => {
    if (!window.confirm(`Delete Prometheus datasource “${datasource.name}”?`)) return;
    setBusy(datasource.id);
    setActionError(null);
    try {
      await mutationJson(`/prometheus-datasources/${encodeURIComponent(datasource.id)}`, {
        method: "DELETE",
      });
      setData((current) => ({
        ...current,
        datasources: current.datasources.filter((item) => item.id !== datasource.id),
      }));
      onRefresh();
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Datasource delete failed.");
    } finally {
      setBusy(null);
    }
  };
  const testDatasource = async (datasource: PrometheusDatasource) => {
    setTesting(datasource.id);
    setActionError(null);
    setOutcome(null);
    try {
      const body = asRecord(
        await mutationJson(`/prometheus-datasources/${encodeURIComponent(datasource.id)}/test`, {
          method: "POST",
        }),
      );
      setOutcome(
        `${datasource.name}: ${String(body.status ?? "completed")} · ${Number(body.samples ?? 0)} sample(s)`,
      );
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Datasource test failed.");
    } finally {
      setTesting(null);
    }
  };
  return (
    <div className="page-stack reachability-page">
      <PageHeading
        eyebrow="Prometheus view"
        title="Regional reachability"
        description="The same endpoints observed from every probe region—without copying raw time-series into Alert Hub."
        actions={
          <>
            <GrafanaLink url={grafanaUrl} />
            <button className="button button--quiet" type="button" onClick={onRefresh}>
              <Icon symbol="↻" /> Refresh evidence
            </button>
            <button
              className="button button--primary"
              type="button"
              onClick={() => setAdding(true)}
              disabled={readOnly}
            >
              <Icon symbol="+" /> Add datasource
            </button>
          </>
        }
      />
      <div className="reach-summary">
        <div>
          <span className="reach-summary__icon reach-summary__icon--healthy">
            <Icon symbol="✓" />
          </span>
          <span>
            <small>Reachable paths</small>
            <b>
              {reachable}
              <em>/{cells.length}</em>
            </b>
          </span>
        </div>
        <div>
          <span className="reach-summary__icon reach-summary__icon--failed">
            <Icon symbol="×" />
          </span>
          <span>
            <small>Failed paths</small>
            <b>{failed}</b>
          </span>
        </div>
        <div>
          <span className="reach-summary__icon">
            <Icon symbol="∿" />
          </span>
          <span>
            <small>Datasources queried</small>
            <b>{meta.datasources == null ? "Unknown" : meta.datasources}</b>
          </span>
        </div>
        <div>
          <span className="reach-summary__icon">
            <Icon symbol="◷" />
          </span>
          <span>
            <small>Query status</small>
            <b>{titleCase(meta.status)}</b>
          </span>
        </div>
      </div>
      <Panel
        className="reach-matrix-panel"
        eyebrow="probe_success"
        title="Probe region × target matrix"
        action={
          <span className="live-stamp">
            <StatusDot
              health={
                meta.status === "ok"
                  ? "healthy"
                  : meta.status === "partial"
                    ? "degraded"
                    : "unknown"
              }
            />{" "}
            {meta.detail || "No reachability status returned"}
          </span>
        }
      >
        <ReachabilityMatrix cells={cells} />
        <div className="matrix-legend">
          <span>
            <i className="legend-dot legend-dot--healthy" />
            Reachable
          </span>
          <span>
            <i className="legend-dot legend-dot--slow" />
            Reachable, slower than 200 ms when latency is supplied
          </span>
          <span>
            <i className="legend-dot legend-dot--failed" />
            Probe failed
          </span>
          <span>
            <i className="legend-dot legend-dot--unknown" />
            No data
          </span>
        </div>
      </Panel>
      <div className="reach-detail-grid">
        <Panel eyebrow="Active failures" title="Paths requiring attention">
          {cells.filter((cell) => !cell.success).length ? (
            <div className="failed-path-list">
              {cells
                .filter((cell) => !cell.success)
                .map((cell) => (
                  <div key={`${cell.source}-${cell.target}`}>
                    <span className="path-line">
                      <i />×<i />
                    </span>
                    <span>
                      <b>
                        {cell.source} → {cell.target}
                      </b>
                      <small>Probe returned 0 · checked {formatRelative(cell.checkedAt)}</small>
                    </span>
                    {cell.datasourceName && <code>{cell.datasourceName}</code>}
                  </div>
                ))}
            </div>
          ) : (
            <EmptyState
              icon="✓"
              title={cells.length ? "No failed paths returned" : "No reachability samples"}
              message={
                cells.length
                  ? "The current probe_success response contains no failed paths."
                  : meta.detail || "Configure and test a Prometheus datasource."
              }
            />
          )}
        </Panel>
        <Panel eyebrow="Fixed backend query" title="Prometheus datasources">
          <p className="settings-intro">
            The browser requests the predefined <code>probe_success</code> query; it cannot submit
            PromQL.
          </p>
          {datasources.length ? (
            <div className="live-resource-list">
              {datasources.map((datasource) => (
                <div key={datasource.id} className="live-resource-row">
                  <span className="datasource-logo">P</span>
                  <span>
                    <b>{datasource.name}</b>
                    <small>
                      {datasource.url} · {datasource.region ?? "No region"} · {datasource.authType}
                    </small>
                  </span>
                  <StatusDot health={datasource.enabled ? "unknown" : "paused"} />
                  <span className="live-resource-actions">
                    <button
                      className="button button--quiet button--small"
                      onClick={() => void testDatasource(datasource)}
                      disabled={readOnly || testing === datasource.id || !datasource.enabled}
                    >
                      {testing === datasource.id ? "Testing…" : "Test"}
                    </button>
                    <button
                      className="button button--quiet button--small"
                      onClick={() => void toggleDatasource(datasource)}
                      disabled={readOnly || busy === datasource.id}
                    >
                      {datasource.enabled ? "Disable" : "Enable"}
                    </button>
                    <button
                      className="text-button text-button--danger"
                      onClick={() => void removeDatasource(datasource)}
                      disabled={readOnly || busy === datasource.id}
                    >
                      Delete
                    </button>
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon="P"
              title="No Prometheus datasource"
              message="Add an HTTPS datasource to populate the reachability matrix."
            />
          )}
        </Panel>
      </div>
      {meta.errors.length > 0 && (
        <Panel eyebrow="Partial results" title="Datasource errors">
          <div className="live-error-list">
            {meta.errors.map((error, index) => (
              <div key={`${error.datasourceId}-${error.code}-${index}`}>
                <b>{error.datasourceName}</b>
                <code>{error.code}</code>
                <span>{error.detail}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}
      {(outcome || actionError) && (
        <div
          className={`permission-message ${actionError ? "permission-message--warning" : "permission-message--success"}`}
          role="status"
        >
          <Icon symbol={actionError ? "!" : "✓"} /> {actionError ?? outcome}
        </div>
      )}
      {adding && (
        <DatasourceWizard
          onClose={() => setAdding(false)}
          onCreated={(datasource) => {
            updateDatasource(datasource);
            setAdding(false);
            onRefresh();
          }}
        />
      )}
    </div>
  );
}

function SourceKindIcon({ kind }: { kind: Source["kind"] }) {
  return (
    <span className={`source-kind-icon source-kind-icon--${kind}`} aria-hidden="true">
      <Icon symbol={kind === "alertmanager" ? "A" : kind === "heartbeat" ? "♥" : "{ }"} />
    </span>
  );
}

function SourceCredentialDetails({ credential }: { credential: SourceCredential }) {
  const [tokenVisible, setTokenVisible] = useState(true);
  const exampleLabel =
    credential.kind === "alertmanager"
      ? "Ready Alertmanager receiver fragment"
      : credential.kind === "generic_json"
        ? "Ready Generic JSON request"
        : "Ready heartbeat request";
  return (
    <>
      <div className="one-time-warning">
        <Icon symbol="!" />
        <span>
          <b>Copy this token now.</b>
          <small>It cannot be revealed again after you close this window.</small>
        </span>
      </div>
      <label className="secret-field">
        <span>Bearer token</span>
        <div>
          <code>{tokenVisible ? credential.token : "•".repeat(32)}</code>
          <button
            onClick={() => setTokenVisible((value) => !value)}
            aria-label={tokenVisible ? "Hide token" : "Show token"}
          >
            <Icon symbol={tokenVisible ? "◉" : "⊘"} />
          </button>
          <CopyButton value={credential.token} />
        </div>
      </label>
      <label className="secret-field">
        <span>Absolute webhook URL</span>
        <div>
          <code>{credential.webhookUrl}</code>
          <CopyButton value={credential.webhookUrl} />
        </div>
      </label>
      <div className="config-snippet">
        <div>
          <span>{exampleLabel}</span>
          <CopyButton value={credential.example} label="Copy example" />
        </div>
        <pre>{credential.example}</pre>
      </div>
      {credential.kind === "generic_json" && (
        <div className="config-snippet">
          <div>
            <span>Generic JSON schema · required: dedup_key and status</span>
            <CopyButton value={GENERIC_JSON_SCHEMA_EXAMPLE} label="Copy schema" />
          </div>
          <pre>{GENERIC_JSON_SCHEMA_EXAMPLE}</pre>
        </div>
      )}
    </>
  );
}

function RotatedSourceCredentialModal({
  credential,
  onClose,
}: {
  credential: SourceCredential;
  onClose: () => void;
}) {
  return (
    <Modal onClose={onClose} size="large" label="Rotated source token">
      <div className="modal-head">
        <div>
          <span className="eyebrow">Source credential</span>
          <h2>Token rotated</h2>
        </div>
        <button className="icon-button" onClick={onClose} aria-label="Close">
          <Icon symbol="×" />
        </button>
      </div>
      <div className="wizard-body wizard-success">
        <SourceCredentialDetails credential={credential} />
      </div>
      <div className="modal-foot">
        <button className="button button--primary" onClick={onClose}>
          I saved the new token
        </button>
      </div>
    </Modal>
  );
}

function SourcesPage({
  sources,
  onAdd,
  readOnly,
  setData,
}: {
  sources: Source[];
  onAdd: () => void;
  readOnly: boolean;
  setData: React.Dispatch<React.SetStateAction<HubData>>;
}) {
  const [testing, setTesting] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [rotatedCredential, setRotatedCredential] = useState<SourceCredential | null>(null);
  const testSource = async (source: Source) => {
    setTesting(source.id);
    setOutcome(null);
    setActionError(null);
    try {
      const body = asRecord(
        await mutationJson(`/sources/${encodeURIComponent(source.id)}/test`, { method: "POST" }),
      );
      setOutcome(
        `${source.name}: accepted ${Number(body.accepted ?? 0)}, duplicates ${Number(body.duplicates ?? 0)}`,
      );
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Source test failed.");
    } finally {
      setTesting(null);
    }
  };
  const toggleSource = async (source: Source) => {
    setBusy(source.id);
    setActionError(null);
    try {
      const body = await mutationJson(`/sources/${encodeURIComponent(source.id)}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !source.enabled }),
      });
      const updated = normalizeSource(body, 0);
      setData((current) => ({
        ...current,
        sources: current.sources.map((item) => (item.id === updated.id ? updated : item)),
      }));
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Source update failed.");
    } finally {
      setBusy(null);
    }
  };
  const removeSource = async (source: Source) => {
    if (!window.confirm(`Delete source “${source.name}”? Its token will stop working.`)) return;
    setBusy(source.id);
    setActionError(null);
    try {
      await mutationJson(`/sources/${encodeURIComponent(source.id)}`, { method: "DELETE" });
      setData((current) => ({
        ...current,
        sources: current.sources.filter((item) => item.id !== source.id),
      }));
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Source delete failed.");
    } finally {
      setBusy(null);
    }
  };
  const rotateSourceToken = async (source: Source) => {
    if (
      !window.confirm(
        `Rotate the token for “${source.name}”? The current token will stop working immediately.`,
      )
    )
      return;
    setBusy(source.id);
    setOutcome(null);
    setActionError(null);
    try {
      const payload = await mutationJson(`/sources/${encodeURIComponent(source.id)}/rotate-token`, {
        method: "POST",
      });
      setRotatedCredential(sourceCredential(payload, source.kind));
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Source token rotation failed.");
    } finally {
      setBusy(null);
    }
  };
  const reportedEvents = sources.flatMap((source) => source.events24h ?? []);
  return (
    <div className="page-stack sources-page">
      <PageHeading
        eyebrow="Event ingest"
        title="Sources"
        description="Normalize Alertmanager, heartbeat, and JSON events at the nearest living node."
        actions={
          <button className="button button--primary" onClick={onAdd} disabled={readOnly}>
            <Icon symbol="+" />
            Add source
          </button>
        }
      />
      <div className="section-summary-bar">
        <span>
          <StatusDot health={sources.length ? "unknown" : "paused"} />
          <b>{sources.filter((source) => source.enabled).length}</b> enabled
        </span>
        <span>
          <Icon symbol="⇣" />
          <b>
            {reportedEvents.length
              ? reportedEvents.reduce((sum, count) => sum + count, 0).toLocaleString()
              : "Unknown"}
          </b>{" "}
          events / 24h
        </span>
        <span>
          <Icon symbol="✓" />
          <b>{sources.filter((source) => source.health === "healthy").length}</b> reported healthy
        </span>
      </div>
      {sources.length ? (
        <div className="source-grid">
          {sources.map((source) => (
            <Panel
              className={`source-card ${!source.enabled ? "source-card--disabled" : ""}`}
              key={source.id}
            >
              <div className="source-card__head">
                <SourceKindIcon kind={source.kind} />
                <span>
                  <b>{source.name}</b>
                  <small>
                    {titleCase(source.kind)} · {source.region}
                  </small>
                </span>
              </div>
              <div className="source-card__status">
                <span>
                  <StatusDot health={source.health} />
                  {source.enabled ? titleCase(source.health) : "Disabled"}
                </span>
                <span>
                  Last event{" "}
                  <b>{source.lastEvent ? formatRelative(source.lastEvent) : "Unknown"}</b>
                </span>
              </div>
              <div className="source-card__metrics">
                <span>
                  <small>Events · 24h</small>
                  <b>{source.events24h == null ? "Unknown" : source.events24h.toLocaleString()}</b>
                </span>
                <span>
                  <small>Source ID</small>
                  <code>{compactId(source.id)}</code>
                </span>
              </div>
              <div className="source-card__endpoint">
                <span>Absolute webhook URL</span>
                <code>{sourceWebhookUrl(source)}</code>
                <CopyButton value={sourceWebhookUrl(source)} label="Copy URL" />
              </div>
              <div className="source-card__actions">
                <button
                  className="button button--quiet button--small"
                  disabled={readOnly || !source.enabled || testing === source.id}
                  onClick={() => void testSource(source)}
                >
                  <Icon symbol="▷" />
                  {testing === source.id ? "Testing…" : "Send test"}
                </button>
                <button
                  className="text-button"
                  disabled={readOnly || busy === source.id}
                  onClick={() => void rotateSourceToken(source)}
                >
                  Rotate token
                </button>
                <button
                  className="text-button"
                  disabled={readOnly || busy === source.id}
                  onClick={() => void toggleSource(source)}
                >
                  {source.enabled ? "Disable" : "Enable"}
                </button>
                <button
                  className="text-button text-button--danger"
                  disabled={readOnly || busy === source.id}
                  onClick={() => void removeSource(source)}
                >
                  Delete
                </button>
              </div>
            </Panel>
          ))}
        </div>
      ) : (
        <Panel>
          <EmptyState
            icon="→"
            title="No event sources"
            message="Add Alertmanager, a generic JSON webhook, or a heartbeat monitor."
            action={
              <button className="button button--primary" onClick={onAdd} disabled={readOnly}>
                Add your first source
              </button>
            }
          />
        </Panel>
      )}
      <Panel eyebrow="Ingest contract" title="Generic JSON schema">
        <p className="panel-description">
          Send one JSON object per request. <code>dedup_key</code> and <code>status</code> are
          required; status must be <code>firing</code> or <code>resolved</code>.
        </p>
        <div className="config-snippet">
          <div>
            <span>Schema version 1 example</span>
            <CopyButton value={GENERIC_JSON_SCHEMA_EXAMPLE} label="Copy schema" />
          </div>
          <pre>{GENERIC_JSON_SCHEMA_EXAMPLE}</pre>
        </div>
      </Panel>
      <div className="info-callout">
        <Icon symbol="i" />
        <span>
          <b>Events are accepted locally first.</b> Every enabled ingest node can receive this
          source, persist it, then converge with its peers—no quorum required.
        </span>
      </div>
      {(outcome || actionError) && (
        <div
          className={`permission-message ${actionError ? "permission-message--warning" : "permission-message--success"}`}
          role="status"
        >
          <Icon symbol={actionError ? "!" : "✓"} /> {actionError ?? outcome}
        </div>
      )}
      {rotatedCredential && (
        <RotatedSourceCredentialModal
          credential={rotatedCredential}
          onClose={() => setRotatedCredential(null)}
        />
      )}
    </div>
  );
}

function ChannelIcon({ kind }: { kind: Channel["kind"] }) {
  const symbol =
    kind === "web_push" ? "◉" : kind === "telegram" ? "↗" : kind === "smtp" ? "@" : "⇄";
  return (
    <span className={`channel-icon channel-icon--${kind}`}>
      <Icon symbol={symbol} />
    </span>
  );
}

function ChannelsPage({
  channels,
  routes,
  outboxPending,
  readOnly,
  setData,
  onNotifications,
}: {
  channels: Channel[];
  routes: NotificationRoute[];
  outboxPending: number | null;
  readOnly: boolean;
  setData: React.Dispatch<React.SetStateAction<HubData>>;
  onNotifications: () => void;
}) {
  const [testing, setTesting] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [addingChannel, setAddingChannel] = useState(false);
  const [addingRoute, setAddingRoute] = useState(false);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const updateChannel = (channel: Channel) => {
    setData((current) => ({
      ...current,
      channels: current.channels.some((item) => item.id === channel.id)
        ? current.channels.map((item) => (item.id === channel.id ? channel : item))
        : [channel, ...current.channels],
    }));
  };
  const updateRoute = (route: NotificationRoute) => {
    setData((current) => ({
      ...current,
      routes: current.routes.some((item) => item.id === route.id)
        ? current.routes.map((item) => (item.id === route.id ? route : item))
        : [...current.routes, route].sort((a, b) => a.priority - b.priority),
    }));
  };
  const test = async (channel: Channel) => {
    setTesting(channel.id);
    setOutcome(null);
    setActionError(null);
    try {
      const body = asRecord(
        await mutationJson(`/channels/${encodeURIComponent(channel.id)}/test`, { method: "POST" }),
      );
      const statusValue = String(body.status ?? "completed");
      const detail = String(body.detail ?? "Provider test completed.");
      if (body.ok !== true) {
        const diagnostics = listFrom(body.outcomes, "outcomes")
          .map(asRecord)
          .filter((item) => item.outcome !== "succeeded")
          .map((item) =>
            String(item.error_code ?? item.provider_status ?? item.outcome ?? "failed"),
          )
          .filter(Boolean);
        const reasons = [...new Set(diagnostics)].slice(0, 4);
        throw new Error(
          `${statusValue}: ${detail}${reasons.length ? ` · ${reasons.join(", ")}` : ""}`,
        );
      }
      setOutcome(`${channel.name}: ${statusValue} · ${detail}`);
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Channel test failed.");
    } finally {
      setTesting(null);
    }
  };
  const toggleChannel = async (channel: Channel) => {
    setBusy(channel.id);
    setActionError(null);
    try {
      const body = await mutationJson(`/channels/${encodeURIComponent(channel.id)}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !channel.enabled }),
      });
      updateChannel(normalizeChannel(body, 0));
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Channel update failed.");
    } finally {
      setBusy(null);
    }
  };
  const removeChannel = async (channel: Channel) => {
    if (!window.confirm(`Delete notification channel “${channel.name}”?`)) return;
    setBusy(channel.id);
    setActionError(null);
    try {
      await mutationJson(`/channels/${encodeURIComponent(channel.id)}`, { method: "DELETE" });
      setData((current) => ({
        ...current,
        channels: current.channels.filter((item) => item.id !== channel.id),
        routes: current.routes.map((route) => ({
          ...route,
          channelIds: route.channelIds.filter((id) => id !== channel.id),
        })),
      }));
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Channel delete failed.");
    } finally {
      setBusy(null);
    }
  };
  const toggleRoute = async (route: NotificationRoute) => {
    setBusy(route.id);
    setActionError(null);
    try {
      const body = await mutationJson(`/routes/${encodeURIComponent(route.id)}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !route.enabled }),
      });
      updateRoute(normalizeRoute(body, 0));
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Route update failed.");
    } finally {
      setBusy(null);
    }
  };
  const removeRoute = async (route: NotificationRoute) => {
    if (!window.confirm(`Delete notification route “${route.name}”?`)) return;
    setBusy(route.id);
    setActionError(null);
    try {
      await mutationJson(`/routes/${encodeURIComponent(route.id)}`, { method: "DELETE" });
      setData((current) => ({
        ...current,
        routes: current.routes.filter((item) => item.id !== route.id),
      }));
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Route delete failed.");
    } finally {
      setBusy(null);
    }
  };
  const attempts = channels.reduce((sum, channel) => sum + channel.deliveryAttempts24h, 0);
  const delivered = channels.reduce((sum, channel) => sum + channel.delivered24h, 0);
  const deliveryRate = attempts > 0 ? (delivered / attempts) * 100 : null;
  return (
    <div className="page-stack channels-page">
      <PageHeading
        eyebrow="Delivery plane"
        title="Notification channels"
        description="Route alerts through deterministic node ownership, with visible retry and regional failover."
        actions={
          <button
            className="button button--primary"
            onClick={() => setAddingChannel(true)}
            disabled={readOnly}
          >
            <Icon symbol="+" />
            Add channel
          </button>
        }
      />
      <div className="channel-health-banner">
        <div
          className="delivery-ring"
          style={{ ["--progress" as string]: `${deliveryRate ?? 0}%` }}
        >
          <span>
            {deliveryRate == null ? "—" : deliveryRate.toFixed(1)}
            {deliveryRate != null && <small>%</small>}
          </span>
        </div>
        <span>
          <b>{deliveryRate == null ? "No delivery attempts" : "Recorded delivery outcomes"}</b>
          <small>
            {delivered} succeeded of {attempts} attempts in the last 24 hours
          </small>
        </span>
        <span className="channel-health-banner__metrics">
          <b>{outboxPending == null ? "Unknown" : outboxPending}</b>
          <small>outbox pending</small>
        </span>
        <span className="channel-health-banner__metrics">
          <b>{channels.filter((channel) => channel.enabled).length}</b>
          <small>enabled channels</small>
        </span>
      </div>
      <div className="channel-grid">
        {channels.map((channel) => (
          <Panel
            className={`channel-card ${!channel.enabled ? "channel-card--disabled" : ""}`}
            key={channel.id}
          >
            <div className="channel-card__head">
              <ChannelIcon kind={channel.kind} />
              <span>
                <b>{channel.name}</b>
                <small>{titleCase(channel.kind)}</small>
              </span>
              <span className={`health-label health-label--${channel.health}`}>
                <StatusDot health={channel.health} />
                {channel.enabled ? titleCase(channel.health) : "Paused"}
              </span>
            </div>
            <dl className="channel-card__details">
              <div>
                <dt>Route</dt>
                <dd>
                  {routes.filter((route) => route.channelIds.includes(channel.id)).length
                    ? routes
                        .filter((route) => route.channelIds.includes(channel.id))
                        .map((route) => route.name)
                        .join(", ")
                    : "No route"}
                </dd>
              </div>
              <div>
                <dt>Eligible delivery nodes</dt>
                <dd>{channel.eligible}</dd>
              </div>
            </dl>
            <div className="channel-card__performance">
              <span>
                <small>Delivered · 24h</small>
                <b>{channel.delivered24h}</b>
              </span>
              <span>
                <small>Success</small>
                <b>
                  {channel.successRate == null
                    ? "Not exercised"
                    : `${channel.successRate.toFixed(1)}%`}
                </b>
              </span>
              <span className="mini-progress">
                <i style={{ width: `${channel.successRate ?? 0}%` }} />
              </span>
            </div>
            <div className="channel-card__actions">
              <button
                className="button button--quiet button--small"
                disabled={readOnly || !channel.enabled || testing === channel.id}
                onClick={() => void test(channel)}
              >
                <Icon symbol="▷" />
                {testing === channel.id ? "Sending…" : "Send test"}
              </button>
              <button
                className="text-button"
                disabled={readOnly || busy === channel.id}
                onClick={() => void toggleChannel(channel)}
              >
                {channel.enabled ? "Disable" : "Enable"}
              </button>
              <button
                className="text-button text-button--danger"
                disabled={readOnly || busy === channel.id}
                onClick={() => void removeChannel(channel)}
              >
                Delete
              </button>
            </div>
          </Panel>
        ))}
      </div>
      <Panel
        className="routing-panel"
        eyebrow="Ordered evaluation"
        title="Notification routes"
        action={
          <button
            className="button button--quiet button--small"
            onClick={() => setAddingRoute(true)}
            disabled={readOnly || channels.length === 0}
          >
            <Icon symbol="+" />
            Add route
          </button>
        }
      >
        {routes.length ? (
          <div className="route-list">
            {routes.map((route, index) => (
              <div key={route.id} className={!route.enabled ? "is-disabled" : ""}>
                <span className="route-index">{String(index + 1).padStart(2, "0")}</span>
                <span>
                  <b>{route.name}</b>
                  <small>
                    priority {route.priority} · sources {route.sourceFilter.join(", ") || "any"} ·
                    severity {route.severityFilter.join(", ") || "any"}
                  </small>
                </span>
                <span className="route-destinations">
                  {route.channelIds.map((channelId) => {
                    const channel = channels.find((item) => item.id === channelId);
                    return channel ? <ChannelIcon key={channelId} kind={channel.kind} /> : null;
                  })}
                </span>
                <span className="route-continue">
                  {route.continueMatching ? "Continue" : "Stop"}
                </span>
                <span className="live-resource-actions">
                  <button
                    className="text-button"
                    disabled={readOnly || busy === route.id}
                    onClick={() => void toggleRoute(route)}
                  >
                    {route.enabled ? "Disable" : "Enable"}
                  </button>
                  <button
                    className="text-button text-button--danger"
                    disabled={readOnly || busy === route.id}
                    onClick={() => void removeRoute(route)}
                  >
                    Delete
                  </button>
                </span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon="⇢"
            title="No notification routes"
            message="Create a route to connect incident filters to one or more channels."
          />
        )}
      </Panel>
      <button className="onboarding-callout" onClick={onNotifications} disabled={readOnly}>
        <span className="onboarding-callout__icon">
          <Icon symbol="◉" />
        </span>
        <span>
          <b>Register this browser for Web Push</b>
          <small>Permission is requested only after this action.</small>
        </span>
        <Icon symbol="→" />
      </button>
      {(outcome || actionError) && (
        <div
          className={`permission-message ${actionError ? "permission-message--warning" : "permission-message--success"}`}
          role="status"
        >
          <Icon symbol={actionError ? "!" : "✓"} /> {actionError ?? outcome}
        </div>
      )}
      {addingChannel && (
        <ChannelWizard
          onClose={() => setAddingChannel(false)}
          onCreated={(channel) => {
            updateChannel(channel);
            setAddingChannel(false);
          }}
        />
      )}
      {addingRoute && (
        <RouteWizard
          channels={channels}
          onClose={() => setAddingRoute(false)}
          onCreated={(route) => {
            updateRoute(route);
            setAddingRoute(false);
          }}
        />
      )}
    </div>
  );
}

function DevicesPage({
  devices,
  onNotifications,
  readOnly,
  setData,
}: {
  devices: Device[];
  onNotifications: () => void;
  readOnly: boolean;
  setData: React.Dispatch<React.SetStateAction<HubData>>;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);
  const secureContext = typeof window !== "undefined" && window.isSecureContext;
  const serviceWorkerAvailable = typeof navigator !== "undefined" && "serviceWorker" in navigator;
  const permission = typeof Notification === "undefined" ? "unsupported" : Notification.permission;
  const currentPush = devices.some((device) => device.current && device.push);
  const pushReady =
    secureContext && serviceWorkerAvailable && permission === "granted" && currentPush;
  const revoke = async (device: Device) => {
    setBusy(device.id);
    setActionError(null);
    setOutcome(null);
    try {
      await mutationJson(`/devices/${encodeURIComponent(device.id)}/sessions`, {
        method: "DELETE",
      });
      setData((current) => ({
        ...current,
        devices: current.devices.filter((item) => item.id !== device.id),
      }));
      setOutcome(`${device.name} session revoked.`);
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Session revoke failed.");
    } finally {
      setBusy(null);
    }
  };
  const revokeOthers = async () => {
    const targets = devices.filter((device) => !device.current);
    if (!targets.length || !window.confirm(`Revoke ${targets.length} other session(s)?`)) return;
    setBusy("others");
    setActionError(null);
    setOutcome(null);
    try {
      for (const device of targets) {
        await mutationJson(`/devices/${encodeURIComponent(device.id)}/sessions`, {
          method: "DELETE",
        });
      }
      const targetIds = new Set(targets.map((device) => device.id));
      setData((current) => ({
        ...current,
        devices: current.devices.filter((item) => !targetIds.has(item.id)),
      }));
      setOutcome(`${targets.length} other session(s) revoked.`);
    } catch (reason) {
      setActionError(
        reason instanceof Error ? reason.message : "Other sessions were not all revoked.",
      );
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="page-stack devices-page">
      <PageHeading
        eyebrow="Account security"
        title="Devices & sessions"
        description="Control refresh sessions and Web Push subscriptions independently on every device."
        actions={
          <button className="button button--primary" onClick={onNotifications} disabled={readOnly}>
            <Icon symbol="◉" />
            Enable notifications
          </button>
        }
      />
      <Panel className="device-readiness">
        <div className="readiness-graphic">
          <span>
            <Icon symbol="◉" />
          </span>
          <i />
          <span>
            <Icon symbol="⇄" />
          </span>
          <i />
          <span>
            <Icon symbol="▣" />
          </span>
        </div>
        <div>
          <span className="eyebrow">Push readiness</span>
          <h2>
            {pushReady ? "This device is registered for Web Push" : "Push setup is incomplete"}
          </h2>
          <p>Permission, service worker, and cluster subscription are checked separately.</p>
        </div>
        <div className="readiness-checks">
          <span>
            <Icon symbol={secureContext ? "✓" : "×"} />
            Secure context: {secureContext ? "yes" : "no"}
          </span>
          <span>
            <Icon symbol={serviceWorkerAvailable ? "✓" : "×"} />
            Service worker: {serviceWorkerAvailable ? "supported" : "unsupported"}
          </span>
          <span>
            <Icon symbol={currentPush ? "✓" : "×"} />
            API subscription: {currentPush ? "registered" : "not registered"} · permission{" "}
            {permission}
          </span>
        </div>
      </Panel>
      <Panel
        eyebrow={`${devices.length} active`}
        title="Signed-in devices"
        action={
          <button
            className="text-button text-button--danger"
            disabled={readOnly || busy !== null || !devices.some((device) => !device.current)}
            onClick={() => void revokeOthers()}
          >
            {busy === "others" ? "Revoking…" : "Revoke other sessions"}
          </button>
        }
      >
        {devices.length ? (
          <div className="device-list">
            {devices.map((device) => (
              <div className="device-row" key={device.id}>
                <span className="device-illustration">
                  <Icon symbol={device.platform.toLowerCase().includes("mac") ? "▭" : "▯"} />
                </span>
                <span className="device-row__name">
                  <span>
                    <b>{device.name}</b>
                    {device.current && <em>Current device</em>}
                  </span>
                  <small>{device.platform}</small>
                </span>
                <span className="device-row__meta">
                  <small>Last active</small>
                  <b>{formatRelative(device.lastUsed)}</b>
                  <span>{device.location}</span>
                </span>
                <span className={`push-state ${device.push ? "push-state--on" : ""}`}>
                  <Icon symbol={device.push ? "◉" : "⊘"} />
                  {device.push ? "Push enabled" : "Push off"}
                </span>
                {!device.current && (
                  <button
                    className="button button--quiet button--small"
                    disabled={readOnly || busy !== null}
                    onClick={() => void revoke(device)}
                  >
                    {busy === device.id ? "Revoking…" : "Revoke"}
                  </button>
                )}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon="▣"
            title="No active devices"
            message="New sessions will appear here after sign-in."
          />
        )}
      </Panel>
      {(outcome || actionError) && (
        <div
          className={`permission-message ${actionError ? "permission-message--warning" : "permission-message--success"}`}
          role="status"
        >
          <Icon symbol={actionError ? "!" : "✓"} /> {actionError ?? outcome}
        </div>
      )}
      <div className="security-note">
        <Icon symbol="◇" />
        <span>
          <b>Refresh tokens rotate on use.</b> Revoking a device signs it out as soon as the cluster
          event reaches the node it contacts.
        </span>
      </div>
    </div>
  );
}

function ClusterPage({
  nodes,
  meta,
  outboxPending,
  onRefresh,
}: {
  nodes: ClusterNode[];
  meta: ClusterMeta;
  outboxPending: number | null;
  onRefresh: () => void;
}) {
  const [selected, setSelected] = useState(nodes[0]?.id ?? "");
  const current = nodes.find((node) => node.id === selected) ?? nodes[0];
  const cursorEntries = Object.entries(meta.cursor).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  return (
    <div className="page-stack cluster-page">
      <PageHeading
        eyebrow="Eventual consistency"
        title="Cluster"
        description="Every peer remains useful on its own. Cursors show how the shared event history is converging."
        actions={
          <button className="button button--quiet" onClick={onRefresh}>
            <Icon symbol="⇄" />
            Refresh cluster data
          </button>
        }
      />
      <div className="cluster-hero">
        <div className="cluster-topology" aria-label="Cluster topology">
          <div className="topology-lines">
            <i />
            <i />
            <i />
          </div>
          {nodes.slice(0, 3).map((node, index) => (
            <button
              key={node.id}
              className={`topology-node topology-node--${index + 1} ${selected === node.id ? "active" : ""}`}
              onClick={() => setSelected(node.id)}
            >
              <span className={`topology-node__ring topology-node__ring--${node.health}`}>
                <b>{node.region}</b>
              </span>
              <strong>{node.name}</strong>
              <small>
                <StatusDot health={node.health} />
                {titleCase(node.health)}
              </small>
            </button>
          ))}
          <div className="topology-center">
            <span>{nodes.length}</span>
            <small>known peers</small>
          </div>
        </div>
        <div className="cluster-principle">
          <span className="eyebrow">Operating principle</span>
          <h2>No quorum. No single point of failure.</h2>
          <p>
            An isolated node continues to ingest, store, notify, and serve the interface. Partitions
            may produce a duplicate notification—never a discarded event.
          </p>
          <div>
            <span>
              <Icon symbol="✓" />
              Local-first writes
            </span>
            <span>
              <Icon symbol="✓" />
              Append-only events
            </span>
            <span>
              <Icon symbol="✓" />
              Deterministic merge
            </span>
          </div>
        </div>
      </div>
      <div className="node-card-grid">
        {nodes.map((node) => (
          <Panel
            key={node.id}
            className={`node-card ${selected === node.id ? "node-card--selected" : ""}`}
          >
            <button
              className="node-card__select"
              onClick={() => setSelected(node.id)}
              aria-label={`Inspect ${node.name}`}
            />
            <div className="node-card__head">
              <span className={`flag-tag flag-tag--${node.health}`}>{node.region}</span>
              <span>
                <b>{node.name}</b>
                <small>{node.city}</small>
              </span>
              <span className={`health-label health-label--${node.health}`}>
                <StatusDot health={node.health} />
                {titleCase(node.health)}
              </span>
            </div>
            <div className="node-card__metrics">
              <span>
                <small>Sync lag</small>
                <b className={node.syncLag != null && node.syncLag > 10 ? "text-warning" : ""}>
                  {node.syncLag == null ? "Unknown" : `${node.syncLag.toFixed(1)}s`}
                </b>
              </span>
              <span>
                <small>Outbox</small>
                <b>{node.queue == null ? "Unknown" : node.queue}</b>
              </span>
              <span>
                <small>Last seen</small>
                <b>{formatRelative(node.lastSeen)}</b>
              </span>
            </div>
            <div className="role-tags">
              {node.roles.map((role) => (
                <span key={role}>{role}</span>
              ))}
            </div>
            <div className="node-card__foot">
              <code>{node.version}</code>
            </div>
          </Panel>
        ))}
      </div>
      <div className="cluster-detail-grid">
        <Panel
          eyebrow="Local vector cursor"
          title={current ? `${current.name} · latest local read` : "Synchronization"}
          action={
            <span className="live-stamp">
              <StatusDot health={current?.health ?? "unknown"} /> API evidence
            </span>
          }
        >
          <div className="cursor-table">
            <div className="cursor-table__head">
              <span>Origin</span>
              <span>Local cursor</span>
            </div>
            {cursorEntries.length ? (
              cursorEntries.map(([origin, sequence]) => (
                <div key={origin}>
                  <span>
                    <span className="region-mini">ID</span>
                    {origin}
                  </span>
                  <code>{sequence.toLocaleString()}</code>
                </div>
              ))
            ) : (
              <EmptyState
                icon="⇄"
                title="No cursor data"
                message="The current node did not return vector cursor evidence."
              />
            )}
          </div>
        </Panel>
        <Panel eyebrow="Node health" title="Runtime signals">
          <div className="runtime-signals">
            <span>
              <small>Cluster events</small>
              <b>{meta.eventCount == null ? "Unknown" : meta.eventCount.toLocaleString()}</b>
            </span>
            <span>
              <small>Cursor origins</small>
              <b>{cursorEntries.length}</b>
            </span>
            <span>
              <small>Outbox depth</small>
              <b>{outboxPending == null ? "Unknown" : outboxPending}</b>
            </span>
            <span>
              <small>Known nodes</small>
              <b>{nodes.length}</b>
            </span>
          </div>
          <a
            className="button button--quiet button--block"
            href="/metrics"
            target="_blank"
            rel="noreferrer"
          >
            <Icon symbol="↗" />
            Open application metrics
          </a>
        </Panel>
      </div>
    </div>
  );
}

function AuditPage({
  items,
  nextOffset,
  total,
  nodes,
  loadingMore,
  loadError,
  onLoadMore,
  readOnly,
}: {
  items: AuditItem[];
  nextOffset: number;
  total: number;
  nodes: ClusterNode[];
  loadingMore: boolean;
  loadError: string | null;
  onLoadMore: () => void;
  readOnly: boolean;
}) {
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState("all");
  const [range, setRange] = useState("7d");
  const [rangeAnchor] = useState(() => Date.now());
  const rangeDays = range === "7d" ? 7 : range === "30d" ? 30 : null;
  const cutoff = rangeDays == null ? null : rangeAnchor - rangeDays * 24 * 60 * 60 * 1000;
  const filtered = useMemo(
    () =>
      items.filter(
        (item) =>
          `${item.action} ${item.detail} ${item.actor} ${item.node}`
            .toLowerCase()
            .includes(query.toLowerCase()) &&
          (scope === "all" ||
            (scope === "system" ? item.actor === "system" : item.actor !== "system")) &&
          (cutoff == null ||
            (Number.isFinite(Date.parse(item.at)) && Date.parse(item.at) >= cutoff)),
      ),
    [cutoff, items, query, scope],
  );
  const grouped = useMemo(() => groupAuditBursts(filtered), [filtered]);
  const clusterHealth = aggregateNodeHealth(nodes);
  const healthyNodes = nodes.filter((node) => node.health === "healthy").length;
  const knownTotal = Math.max(total, items.length);
  const canLoadMore = nextOffset < knownTotal;
  const exportLoaded = () => {
    const blob = new Blob(
      [items.map((item) => JSON.stringify(item.raw ?? item)).join("\n") + "\n"],
      {
        type: "application/x-ndjson",
      },
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "alert-hub-audit-loaded.jsonl";
    link.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="page-stack audit-page">
      <PageHeading
        eyebrow="Immutable operations trail"
        title="Audit log"
        description="Authentication, configuration, and incident actions recorded by the API node serving this session."
        actions={
          <button className="button button--quiet" onClick={exportLoaded} disabled={!items.length}>
            <Icon symbol="⇩" />
            Export loaded JSONL
          </button>
        }
      />
      <div className={`audit-current-health audit-current-health--${clusterHealth}`}>
        <StatusDot health={clusterHealth} />
        <span>
          <b>Current cluster status</b>
          <small>
            {nodes.length
              ? `${healthyNodes}/${nodes.length} nodes healthy. Audit failures below are historical events, not active alarms.`
              : "Live cluster telemetry is not available."}
          </small>
        </span>
      </div>
      <Panel className="audit-panel">
        <div className="filter-bar">
          <label className="search-field">
            <Icon symbol="⌕" />
            <span className="sr-only">Search audit log</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search actor, action, node…"
            />
          </label>
          <div className="segmented">
            <button className={scope === "all" ? "active" : ""} onClick={() => setScope("all")}>
              All
            </button>
            <button
              className={scope === "operator" ? "active" : ""}
              onClick={() => setScope("operator")}
            >
              Operator
            </button>
            <button
              className={scope === "system" ? "active" : ""}
              onClick={() => setScope("system")}
            >
              System
            </button>
          </div>
          <label className="compact-select">
            <span className="sr-only">Audit date range</span>
            <select value={range} onChange={(event) => setRange(event.target.value)}>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="all">All loaded history</option>
            </select>
          </label>
        </div>
        <div className="audit-date-row">
          <span>
            {filtered[0]
              ? `${formatDay(filtered[0].at)} · ${filtered.length} event${filtered.length === 1 ? "" : "s"}`
              : "Audit trail"}
          </span>
          <i />
        </div>
        {grouped.length ? (
          <div className="audit-list">
            {grouped.map((item) => (
              <div className="audit-item" key={item.id}>
                <span className={`audit-item__icon audit-item__icon--${item.tone}`}>
                  <Icon
                    symbol={
                      item.tone === "success"
                        ? "✓"
                        : item.tone === "danger"
                          ? "!"
                          : item.tone === "warning"
                            ? "△"
                            : "•"
                    }
                  />
                </span>
                <span className="audit-item__body">
                  <b>
                    {item.actionCode === "cluster_auth_failed"
                      ? "Rejected cluster-auth attempt"
                      : item.action}
                  </b>
                  <p>{item.detail}</p>
                  <small>
                    <span className="avatar avatar--tiny">
                      {item.actor === "system" ? "AH" : "OP"}
                    </span>
                    {item.actor} <i /> <code>{item.node}</code>
                  </small>
                </span>
                <time>{formatDate(item.at)}</time>
                {item.count > 1 ? (
                  <span
                    className="audit-item__count"
                    title={`${item.count} identical events from ${formatDate(item.oldestAt)} through ${formatDate(item.at)}`}
                    aria-label={`${item.count} identical events in this burst`}
                  >
                    ×{item.count}
                  </span>
                ) : (
                  <span />
                )}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon="⌕"
            title="No matching audit entries"
            message="Try another actor or search term."
          />
        )}
        {canLoadMore && (
          <div className="audit-load-more">
            <button
              className="button button--quiet"
              type="button"
              onClick={onLoadMore}
              disabled={loadingMore || readOnly}
            >
              {loadingMore
                ? "Loading older events…"
                : `Load older events (${items.length}/${knownTotal})`}
            </button>
          </div>
        )}
        {loadError && (
          <p className="audit-load-error" role="alert">
            {loadError}
          </p>
        )}
        <div className="audit-integrity">
          <Icon symbol="◇" />
          <span>
            <b>Audit storage policy</b>
            <small>
              Entries are append-only on this node. Burst grouping changes only this view; export
              retains every field returned by the API for every loaded event. Secrets and
              authorization headers are never recorded.
            </small>
          </span>
          <span>
            <StatusDot health="unknown" />
            {items.length}/{knownTotal} loaded
          </span>
        </div>
      </Panel>
    </div>
  );
}

function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      className={`toggle ${checked ? "toggle--on" : ""}`}
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      disabled={disabled}
    >
      <span />
    </button>
  );
}

function SettingsPage({ nodes, readOnly }: { nodes: ClusterNode[]; readOnly: boolean }) {
  const appName = useContext(AppNameContext);
  const [autoFailover, setAutoFailover] = useState(() =>
    typeof localStorage === "undefined"
      ? true
      : localStorage.getItem("alert-hub-auto-failover") !== "false",
  );
  const [cacheMessage, setCacheMessage] = useState<string | null>(null);
  const [endpoints, setEndpoints] = useState<string[]>(() => {
    if (typeof window === "undefined") return [];
    try {
      const saved = JSON.parse(localStorage.getItem("alert-hub-api-endpoints") ?? "[]");
      return Array.isArray(saved)
        ? saved.filter((item): item is string => typeof item === "string")
        : [];
    } catch {
      return [];
    }
  });
  const availableEndpoints = [
    ...new Set(
      nodes
        .map((node) => normalizePeerBase(node.publicApiUrl))
        .filter((item): item is string => Boolean(item)),
    ),
  ];
  const enabledEndpoints = endpoints.filter((item) => availableEndpoints.includes(item));
  const toggleEndpoint = (item: string) => {
    const enabled = enabledEndpoints.includes(item);
    const next = enabled
      ? enabledEndpoints.filter((entry) => entry !== item)
      : [...new Set([...enabledEndpoints, item])].slice(0, 8);
    let disabled: string[];
    try {
      const saved = JSON.parse(localStorage.getItem("alert-hub-disabled-api-endpoints") ?? "[]");
      disabled = Array.isArray(saved)
        ? saved.filter((value): value is string => typeof value === "string")
        : [];
    } catch {
      disabled = [];
    }
    const nextDisabled = enabled
      ? [...new Set([...disabled, item])]
      : disabled.filter((entry) => entry !== item);
    setEndpoints(next);
    localStorage.setItem("alert-hub-api-endpoints", JSON.stringify(next));
    localStorage.setItem("alert-hub-disabled-api-endpoints", JSON.stringify(nextDisabled));
  };
  return (
    <div className="page-stack settings-page">
      <PageHeading
        eyebrow="Local & cluster configuration"
        title="Settings"
        description="Device preferences stay local. Cluster settings replicate as auditable configuration events."
      />
      <div className="settings-grid">
        <nav className="settings-nav" aria-label="Settings sections">
          <button className="active" disabled>
            <Icon symbol="◫" />
            General
          </button>
        </nav>
        <div className="settings-content">
          <Panel eyebrow="Appearance" title="Interface preferences">
            <div className="setting-row">
              <span>
                <b>Theme</b>
                <small>{appName} uses a dark operations palette.</small>
              </span>
              <span className="theme-picker">
                <button className="active" disabled>
                  <i />
                  Dark
                </button>
                <button disabled>
                  <i />
                  System
                </button>
              </span>
            </div>
          </Panel>
          <Panel eyebrow="Resilient client" title="Saved API endpoints">
            <p className="settings-intro">
              When the current node is unavailable, the PWA can try another trusted cluster URL for
              read access.
            </p>
            <div className="endpoint-list">
              {availableEndpoints.map((item, index) => (
                <div key={item}>
                  <span className="endpoint-order">{index + 1}</span>
                  <span>
                    <b>{item}</b>
                    <small>Verified from the authenticated cluster inventory</small>
                  </span>
                  <StatusDot health={enabledEndpoints.includes(item) ? "unknown" : "paused"} />
                  <button
                    className="button button--quiet button--small"
                    onClick={() => toggleEndpoint(item)}
                    disabled={readOnly}
                    aria-label={`${enabledEndpoints.includes(item) ? "Disable" : "Enable"} failover to ${item}`}
                  >
                    {enabledEndpoints.includes(item) ? "Disable" : "Enable"}
                  </button>
                </div>
              ))}
              {!availableEndpoints.length && (
                <EmptyState
                  icon="⇄"
                  title="No saved peer endpoints"
                  message="Verified HTTPS public API URLs discovered from cluster reads appear here."
                />
              )}
            </div>
            <div className="setting-row setting-row--border">
              <span>
                <b>Automatic read failover</b>
                <small>
                  Try enabled, authenticated cluster endpoints when the current API node is
                  unavailable.
                </small>
              </span>
              <Toggle
                checked={autoFailover}
                onChange={(checked) => {
                  setAutoFailover(checked);
                  localStorage.setItem("alert-hub-auto-failover", String(checked));
                }}
                label="Automatic read failover"
                disabled={readOnly}
              />
            </div>
          </Panel>
          <Panel eyebrow="Cluster identity" title="Application settings">
            <div className="form-grid">
              <label>
                <span>Display name</span>
                <input value={appName} readOnly aria-readonly="true" />
              </label>
            </div>
            <div className="settings-actions">
              <span>
                <Icon symbol="i" />
                Display name is controlled by the server-side APP_NAME setting and is read-only
                here.
              </span>
            </div>
          </Panel>
          <Panel className="danger-panel" eyebrow="Maintenance" title="Local application data">
            <div className="setting-row">
              <span>
                <b>Clear cached snapshot</b>
                <small>
                  Removes read-only incident data from this device. Cluster data is unaffected.
                </small>
              </span>
              <button
                className="button button--danger"
                disabled={readOnly}
                onClick={() => {
                  pruneReadCaches(null);
                  setCacheMessage("Authenticated read caches were cleared on this device.");
                }}
              >
                Clear cache
              </button>
            </div>
            {cacheMessage && (
              <div className="permission-message permission-message--success" role="status">
                <Icon symbol="✓" /> {cacheMessage}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Modal({
  children,
  onClose,
  size = "medium",
  label,
}: {
  children: ReactNode;
  onClose: () => void;
  size?: "medium" | "large";
  label: string;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    document.body.classList.add("modal-open");
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.classList.remove("modal-open");
    };
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div
        className={`modal modal--${size}`}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        onMouseDown={(event) => event.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
}

function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="button button--quiet button--small"
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1600);
        });
      }}
    >
      <Icon symbol={copied ? "✓" : "□"} />
      {copied ? "Copied" : label}
    </button>
  );
}

function SourceWizard({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (source: Source) => void;
}) {
  const appName = useContext(AppNameContext);
  const [step, setStep] = useState(1);
  const [kind, setKind] = useState<Source["kind"]>("alertmanager");
  const [name, setName] = useState("");
  const [region, setRegion] = useState("");
  const [cidr, setCidr] = useState("");
  const [interval, setIntervalValue] = useState("60");
  const [grace, setGrace] = useState("90");
  const [heartbeatSeverity, setHeartbeatSeverity] = useState<Severity>("critical");
  const [heartbeatLabels, setHeartbeatLabels] = useState("");
  const [saving, setSaving] = useState(false);
  const [created, setCreated] = useState<SourceCredential | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testOutcome, setTestOutcome] = useState<string | null>(null);
  const create = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const payload = await mutationJson("/sources", {
        method: "POST",
        body: JSON.stringify({
          name,
          kind,
          region: region.trim() || null,
          enabled: true,
          allowed_cidrs: cidr
            .split(/[\n,]/)
            .map((item) => item.trim())
            .filter(Boolean),
          config:
            kind === "heartbeat"
              ? {
                  interval_seconds: Number(interval),
                  grace_seconds: Number(grace),
                  severity: heartbeatSeverity,
                  labels: parseKeyValueLines(heartbeatLabels, "Heartbeat labels"),
                }
              : {},
        }),
      });
      const body = asRecord(payload);
      setCreated(sourceCredential(body, kind));
      onCreated(normalizeSource(body, 0));
      setStep(3);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Source could not be created.");
    } finally {
      setSaving(false);
    }
  };
  const testCreatedSource = async () => {
    if (!created) return;
    setTestOutcome(null);
    setError(null);
    try {
      const body = asRecord(
        await mutationJson(`/sources/${encodeURIComponent(created.id)}/test`, { method: "POST" }),
      );
      setTestOutcome(
        `Accepted ${Number(body.accepted ?? 0)} event; incident ${String(body.incident_id ?? "returned by API")}.`,
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Source test failed.");
    }
  };
  return (
    <Modal onClose={onClose} size="large" label="Add source">
      <div className="modal-head">
        <div>
          <span className="eyebrow">Source onboarding</span>
          <h2>{step === 3 ? "Source created" : "Add event source"}</h2>
        </div>
        <button className="icon-button" onClick={onClose} aria-label="Close">
          <Icon symbol="×" />
        </button>
      </div>
      <div className="wizard-progress">
        <span className={step >= 1 ? "active" : ""}>
          <i>{step > 1 ? "✓" : "1"}</i>Type
        </span>
        <b />
        <span className={step >= 2 ? "active" : ""}>
          <i>{step > 2 ? "✓" : "2"}</i>Configure
        </span>
        <b />
        <span className={step >= 3 ? "active" : ""}>
          <i>3</i>Connect
        </span>
      </div>
      {step === 1 && (
        <div className="wizard-body">
          <p className="wizard-intro">
            Choose how events will enter this cluster. You can change routing later without rotating
            the source token.
          </p>
          <div className="source-type-picker">
            <button
              className={kind === "alertmanager" ? "active" : ""}
              onClick={() => setKind("alertmanager")}
            >
              <SourceKindIcon kind="alertmanager" />
              <span>
                <b>Alertmanager</b>
                <small>
                  Official grouped webhook payload. Each alert is normalized independently.
                </small>
                <em>Recommended</em>
              </span>
              <i />
            </button>
            <button
              className={kind === "generic_json" ? "active" : ""}
              onClick={() => setKind("generic_json")}
            >
              <SourceKindIcon kind="generic_json" />
              <span>
                <b>Generic JSON</b>
                <small>Send events using the stable {appName} schema.</small>
              </span>
              <i />
            </button>
            <button
              className={kind === "heartbeat" ? "active" : ""}
              onClick={() => setKind("heartbeat")}
            >
              <SourceKindIcon kind="heartbeat" />
              <span>
                <b>Heartbeat</b>
                <small>Fire when a scheduled signal misses its grace window.</small>
              </span>
              <i />
            </button>
          </div>
        </div>
      )}
      {step === 2 && (
        <form id="source-config-form" className="wizard-body source-config-form" onSubmit={create}>
          <div className="form-grid">
            <label>
              <span>Source name</span>
              <input
                required
                autoFocus
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder={kind === "heartbeat" ? "Billing heartbeat" : "Prometheus EU"}
              />
            </label>
            <label>
              <span>Nearest region</span>
              <input
                value={region}
                onChange={(event) => setRegion(event.target.value)}
                placeholder="Region label (optional)"
              />
            </label>
          </div>
          {kind !== "heartbeat" && (
            <label className="full-field">
              <span>
                Allowed source IP / CIDR <em>Optional</em>
              </span>
              <input
                value={cidr}
                onChange={(event) => setCidr(event.target.value)}
                placeholder="10.14.0.0/16"
              />
              <small>Requests still require the bearer token. Private CIDRs are recommended.</small>
            </label>
          )}
          {kind === "heartbeat" && (
            <>
              <div className="form-grid">
                <label>
                  <span>Expected interval</span>
                  <div className="input-suffix">
                    <input
                      type="number"
                      min="10"
                      value={interval}
                      onChange={(event) => setIntervalValue(event.target.value)}
                    />
                    <span>seconds</span>
                  </div>
                </label>
                <label>
                  <span>Grace period</span>
                  <div className="input-suffix">
                    <input
                      type="number"
                      min="0"
                      value={grace}
                      onChange={(event) => setGrace(event.target.value)}
                    />
                    <span>seconds</span>
                  </div>
                </label>
                <label>
                  <span>Missed heartbeat severity</span>
                  <select
                    value={heartbeatSeverity}
                    onChange={(event) => setHeartbeatSeverity(event.target.value as Severity)}
                  >
                    <option value="critical">Critical</option>
                    <option value="warning">Warning</option>
                    <option value="info">Info</option>
                    <option value="unknown">Unknown</option>
                  </select>
                </label>
              </div>
              <label className="full-field">
                <span>Heartbeat labels · one key=value per line</span>
                <textarea
                  value={heartbeatLabels}
                  onChange={(event) => setHeartbeatLabels(event.target.value)}
                  placeholder={"service=billing\nenvironment=production"}
                  rows={3}
                />
                <small>These labels are attached to the missed-heartbeat incident.</small>
              </label>
            </>
          )}
          <div className="token-safety-note">
            <Icon symbol="◇" />
            <span>
              <b>The bearer token is stored as a hash.</b> It will be shown exactly once after
              creation. Losing it requires rotation.
            </span>
          </div>
          {error && (
            <div className="permission-message permission-message--warning" role="alert">
              <Icon symbol="!" /> {error}
            </div>
          )}
        </form>
      )}
      {step === 3 && created && (
        <div className="wizard-body wizard-success">
          <div className="success-seal">
            <Icon symbol="✓" />
          </div>
          <SourceCredentialDetails credential={created} />
          {testOutcome && (
            <div className="permission-message permission-message--success" role="status">
              <Icon symbol="✓" /> {testOutcome}
            </div>
          )}
          {error && (
            <div className="permission-message permission-message--warning" role="alert">
              <Icon symbol="!" /> {error}
            </div>
          )}
          <div className="verification-note">
            <span>
              <b>1</b>Copy the credential
            </span>
            <i />
            <span>
              <b>2</b>Apply and validate config
            </span>
            <i />
            <span>
              <b>3</b>Send a test event
            </span>
          </div>
        </div>
      )}
      <div className="modal-foot">
        {step === 1 && (
          <>
            <button className="text-button" onClick={onClose}>
              Cancel
            </button>
            <button className="button button--primary" onClick={() => setStep(2)}>
              Continue <Icon symbol="→" />
            </button>
          </>
        )}
        {step === 2 && (
          <>
            <button className="text-button" onClick={() => setStep(1)}>
              <Icon symbol="←" />
              Back
            </button>
            <button
              className="button button--primary"
              type="submit"
              form="source-config-form"
              disabled={!name.trim() || saving}
            >
              {saving ? "Creating…" : "Create source"}
            </button>
          </>
        )}
        {step === 3 && created && (
          <>
            <button className="button button--quiet" onClick={() => void testCreatedSource()}>
              <Icon symbol="▷" />
              Send test event
            </button>
            <button className="button button--primary" onClick={onClose}>
              I saved the token
            </button>
          </>
        )}
      </div>
    </Modal>
  );
}

function splitList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseKeyValueLines(value: string, label: string) {
  const entries: Array<[string, string]> = [];
  for (const [index, raw] of value.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) throw new Error(`${label} line ${index + 1} must use key=value.`);
    const key = line.slice(0, separator).trim();
    const item = line.slice(separator + 1).trim();
    if (!key || !item) throw new Error(`${label} line ${index + 1} cannot be blank.`);
    entries.push([key, item]);
  }
  return Object.fromEntries(entries);
}

function parseHeaderLines(value: string) {
  const entries: Array<[string, string]> = [];
  for (const [index, raw] of value.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line) continue;
    const separator = line.indexOf(":");
    if (separator <= 0)
      throw new Error(`Webhook header line ${index + 1} must use Header-Name: value.`);
    const name = line.slice(0, separator).trim();
    const item = line.slice(separator + 1).trim();
    if (!name || !item) throw new Error(`Webhook header line ${index + 1} cannot be blank.`);
    entries.push([name, item]);
  }
  return Object.fromEntries(entries);
}

function ChannelWizard({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (channel: Channel) => void;
}) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Channel["kind"]>("web_push");
  const [regions, setRegions] = useState("");
  const [nodeIds, setNodeIds] = useState("");
  const [botToken, setBotToken] = useState("");
  const [chatId, setChatId] = useState("");
  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState("587");
  const [smtpTls, setSmtpTls] = useState("starttls");
  const [smtpFrom, setSmtpFrom] = useState("");
  const [smtpTo, setSmtpTo] = useState("");
  const [smtpUsername, setSmtpUsername] = useState("");
  const [smtpPassword, setSmtpPassword] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [hmacSecret, setHmacSecret] = useState("");
  const [webhookHeaders, setWebhookHeaders] = useState("");
  const [signatureHeader, setSignatureHeader] = useState("X-Alert-Hub-Signature");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const parsedHeaders = parseHeaderLines(webhookHeaders);
      const config: Record<string, unknown> =
        kind === "telegram"
          ? { bot_token: botToken, chat_id: chatId }
          : kind === "smtp"
            ? {
                host: smtpHost,
                port: Number(smtpPort),
                tls: smtpTls,
                from: smtpFrom,
                to: splitList(smtpTo),
                ...(smtpUsername ? { username: smtpUsername, password: smtpPassword } : {}),
              }
            : kind === "generic_webhook"
              ? {
                  url: webhookUrl,
                  ...(Object.keys(parsedHeaders).length ? { headers: parsedHeaders } : {}),
                  ...(hmacSecret
                    ? { hmac_secret: hmacSecret, signature_header: signatureHeader.trim() }
                    : {}),
                }
              : {};
      const body = await mutationJson("/channels", {
        method: "POST",
        body: JSON.stringify({
          name,
          kind,
          enabled: true,
          config,
          eligible_regions: splitList(regions),
          eligible_node_ids: splitList(nodeIds),
        }),
      });
      onCreated(normalizeChannel(body, 0));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Channel could not be created.");
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal onClose={onClose} size="large" label="Add notification channel">
      <div className="modal-head">
        <div>
          <span className="eyebrow">Live delivery provider</span>
          <h2>Add notification channel</h2>
        </div>
        <button className="icon-button" onClick={onClose} aria-label="Close channel dialog">
          <Icon symbol="×" />
        </button>
      </div>
      <form id="channel-create-form" className="wizard-body source-config-form" onSubmit={submit}>
        <div className="form-grid">
          <label>
            <span>Channel name</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              autoFocus
            />
          </label>
          <label>
            <span>Provider type</span>
            <select
              value={kind}
              onChange={(event) => setKind(event.target.value as Channel["kind"])}
            >
              <option value="web_push">Web Push</option>
              <option value="telegram">Telegram</option>
              <option value="smtp">SMTP</option>
              <option value="generic_webhook">Generic webhook</option>
            </select>
          </label>
        </div>
        {kind === "telegram" && (
          <div className="form-grid">
            <label>
              <span>Bot token · write-only field</span>
              <input
                type="password"
                autoComplete="new-password"
                value={botToken}
                onChange={(event) => setBotToken(event.target.value)}
                required
              />
            </label>
            <label>
              <span>Chat ID</span>
              <input value={chatId} onChange={(event) => setChatId(event.target.value)} required />
            </label>
          </div>
        )}
        {kind === "smtp" && (
          <>
            <div className="form-grid">
              <label>
                <span>SMTP host</span>
                <input
                  value={smtpHost}
                  onChange={(event) => setSmtpHost(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>Port</span>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={smtpPort}
                  onChange={(event) => setSmtpPort(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>TLS mode</span>
                <select value={smtpTls} onChange={(event) => setSmtpTls(event.target.value)}>
                  <option value="starttls">STARTTLS</option>
                  <option value="implicit">Implicit TLS</option>
                </select>
              </label>
              <label>
                <span>From address</span>
                <input
                  type="email"
                  value={smtpFrom}
                  onChange={(event) => setSmtpFrom(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>Recipients · comma separated</span>
                <input
                  value={smtpTo}
                  onChange={(event) => setSmtpTo(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>Username · optional</span>
                <input
                  autoComplete="username"
                  value={smtpUsername}
                  onChange={(event) => setSmtpUsername(event.target.value)}
                />
              </label>
              <label>
                <span>Password · write-only field</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={smtpPassword}
                  onChange={(event) => setSmtpPassword(event.target.value)}
                  required={Boolean(smtpUsername)}
                />
              </label>
            </div>
          </>
        )}
        {kind === "generic_webhook" && (
          <>
            <div className="form-grid">
              <label>
                <span>HTTPS webhook URL</span>
                <input
                  type="url"
                  value={webhookUrl}
                  onChange={(event) => setWebhookUrl(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>HMAC secret · optional, write-only field</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={hmacSecret}
                  onChange={(event) => setHmacSecret(event.target.value)}
                />
              </label>
              <label>
                <span>HMAC signature header</span>
                <input
                  value={signatureHeader}
                  onChange={(event) => setSignatureHeader(event.target.value)}
                  disabled={!hmacSecret}
                  required={Boolean(hmacSecret)}
                />
              </label>
            </div>
            <label className="full-field">
              <span>Custom headers · one Header-Name: value per line</span>
              <textarea
                value={webhookHeaders}
                onChange={(event) => setWebhookHeaders(event.target.value)}
                placeholder={"Authorization: Bearer secret\nX-Tenant-ID: operations"}
                rows={3}
                autoComplete="off"
              />
              <small>
                Header values are encrypted as provider credentials and never returned by the API.
              </small>
            </label>
          </>
        )}
        {kind === "web_push" && (
          <div className="token-safety-note">
            <Icon symbol="i" />
            <span>
              Web Push uses server VAPID configuration and registered browser subscriptions.
            </span>
          </div>
        )}
        <div className="form-grid">
          <label>
            <span>Eligible regions · optional</span>
            <input
              value={regions}
              onChange={(event) => setRegions(event.target.value)}
              placeholder="region-a, region-b"
            />
          </label>
          <label>
            <span>Eligible node IDs · optional</span>
            <input
              value={nodeIds}
              onChange={(event) => setNodeIds(event.target.value)}
              placeholder="node-id-1, node-id-2"
            />
          </label>
        </div>
        <div className="token-safety-note">
          <Icon symbol="◇" />
          <span>Provider secrets are encrypted at rest and never returned after this request.</span>
        </div>
        {error && (
          <div className="permission-message permission-message--warning" role="alert">
            <Icon symbol="!" /> {error}
          </div>
        )}
      </form>
      <div className="modal-foot">
        <button className="text-button" onClick={onClose}>
          Cancel
        </button>
        <button
          className="button button--primary"
          type="submit"
          form="channel-create-form"
          disabled={saving || !name.trim()}
        >
          {saving ? "Creating…" : "Create channel"}
        </button>
      </div>
    </Modal>
  );
}

function RouteWizard({
  channels,
  onClose,
  onCreated,
}: {
  channels: Channel[];
  onClose: () => void;
  onCreated: (route: NotificationRoute) => void;
}) {
  const [name, setName] = useState("");
  const [priority, setPriority] = useState("0");
  const [sources, setSources] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const [labelMatchers, setLabelMatchers] = useState<NotificationRoute["labelMatchers"]>([]);
  const [channelIds, setChannelIds] = useState<string[]>([]);
  const [continueMatching, setContinueMatching] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const body = await mutationJson("/routes", {
        method: "POST",
        body: JSON.stringify({
          name,
          enabled: true,
          priority: Number(priority),
          source_filter: splitList(sources),
          severity_filter: severities,
          label_matchers: labelMatchers,
          channel_ids: channelIds,
          continue_matching: continueMatching,
        }),
      });
      onCreated(normalizeRoute(body, 0));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Route could not be created.");
    } finally {
      setSaving(false);
    }
  };
  const invalidMatcher = labelMatchers.some(
    (matcher) =>
      !matcher.name.trim() ||
      (!["exists", "not_exists"].includes(matcher.operator) && !matcher.value),
  );
  return (
    <Modal onClose={onClose} size="large" label="Add notification route">
      <div className="modal-head">
        <div>
          <span className="eyebrow">Ordered evaluation</span>
          <h2>Add notification route</h2>
        </div>
        <button className="icon-button" onClick={onClose} aria-label="Close route dialog">
          <Icon symbol="×" />
        </button>
      </div>
      <form id="route-create-form" className="wizard-body source-config-form" onSubmit={submit}>
        <div className="form-grid">
          <label>
            <span>Route name</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              autoFocus
            />
          </label>
          <label>
            <span>Priority · lower evaluates first</span>
            <input
              type="number"
              min="-1000000"
              max="1000000"
              value={priority}
              onChange={(event) => setPriority(event.target.value)}
              required
            />
          </label>
        </div>
        <label className="full-field">
          <span>Source IDs · optional, comma separated</span>
          <input
            value={sources}
            onChange={(event) => setSources(event.target.value)}
            placeholder="Empty matches any source"
          />
        </label>
        <fieldset className="choice-fieldset">
          <legend>Severities · empty matches any</legend>
          {["critical", "warning", "info", "unknown"].map((severity) => (
            <label key={severity}>
              <input
                type="checkbox"
                checked={severities.includes(severity)}
                onChange={(event) =>
                  setSeverities((current) =>
                    event.target.checked
                      ? [...current, severity]
                      : current.filter((item) => item !== severity),
                  )
                }
              />{" "}
              {titleCase(severity)}
            </label>
          ))}
        </fieldset>
        <fieldset className="matcher-builder">
          <legend>Label matchers · all configured matchers must pass</legend>
          {labelMatchers.map((matcher, index) => (
            <div className="matcher-builder__row" key={index}>
              <label>
                <span>Label name</span>
                <input
                  value={matcher.name}
                  onChange={(event) =>
                    setLabelMatchers((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index ? { ...item, name: event.target.value } : item,
                      ),
                    )
                  }
                  required
                />
              </label>
              <label>
                <span>Operator</span>
                <select
                  value={matcher.operator}
                  onChange={(event) =>
                    setLabelMatchers((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index ? { ...item, operator: event.target.value } : item,
                      ),
                    )
                  }
                >
                  <option value="equals">Equals</option>
                  <option value="not_equals">Does not equal</option>
                  <option value="regex">Regex full match</option>
                  <option value="not_regex">Does not regex-match</option>
                  <option value="exists">Exists</option>
                  <option value="not_exists">Does not exist</option>
                </select>
              </label>
              <label>
                <span>Value</span>
                <input
                  value={matcher.value}
                  onChange={(event) =>
                    setLabelMatchers((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index ? { ...item, value: event.target.value } : item,
                      ),
                    )
                  }
                  disabled={["exists", "not_exists"].includes(matcher.operator)}
                  required={!["exists", "not_exists"].includes(matcher.operator)}
                />
              </label>
              <button
                type="button"
                className="text-button text-button--danger"
                onClick={() =>
                  setLabelMatchers((current) =>
                    current.filter((_, itemIndex) => itemIndex !== index),
                  )
                }
                aria-label={`Remove label matcher ${index + 1}`}
              >
                Remove
              </button>
            </div>
          ))}
          <button
            type="button"
            className="button button--quiet button--small"
            onClick={() =>
              setLabelMatchers((current) => [
                ...current,
                { name: "", operator: "equals", value: "" },
              ])
            }
          >
            <Icon symbol="+" /> Add label matcher
          </button>
        </fieldset>
        <fieldset className="choice-fieldset">
          <legend>Destination channels</legend>
          {channels.map((channel) => (
            <label key={channel.id}>
              <input
                type="checkbox"
                checked={channelIds.includes(channel.id)}
                onChange={(event) =>
                  setChannelIds((current) =>
                    event.target.checked
                      ? [...current, channel.id]
                      : current.filter((item) => item !== channel.id),
                  )
                }
              />{" "}
              {channel.name} · {titleCase(channel.kind)}
            </label>
          ))}
        </fieldset>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={continueMatching}
            onChange={(event) => setContinueMatching(event.target.checked)}
          />{" "}
          Continue evaluating later routes after a match
        </label>
        {error && (
          <div className="permission-message permission-message--warning" role="alert">
            <Icon symbol="!" /> {error}
          </div>
        )}
      </form>
      <div className="modal-foot">
        <button className="text-button" onClick={onClose}>
          Cancel
        </button>
        <button
          className="button button--primary"
          type="submit"
          form="route-create-form"
          disabled={saving || !name.trim() || channelIds.length === 0 || invalidMatcher}
        >
          {saving ? "Creating…" : "Create route"}
        </button>
      </div>
    </Modal>
  );
}

function DatasourceWizard({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (datasource: PrometheusDatasource) => void;
}) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [nodeId, setNodeId] = useState("");
  const [region, setRegion] = useState("");
  const [authType, setAuthType] = useState<"none" | "bearer" | "basic">("none");
  const [bearerToken, setBearerToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    const credentials =
      authType === "bearer"
        ? { auth_type: "bearer", bearer_token: bearerToken }
        : authType === "basic"
          ? { auth_type: "basic", username, password }
          : { auth_type: "none" };
    try {
      const body = await mutationJson("/prometheus-datasources", {
        method: "POST",
        body: JSON.stringify({
          name,
          url,
          node_id: nodeId.trim() || null,
          region: region.trim() || null,
          enabled: true,
          credentials,
        }),
      });
      onCreated(normalizeDatasource(body, 0));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Datasource could not be created.");
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal onClose={onClose} size="large" label="Add Prometheus datasource">
      <div className="modal-head">
        <div>
          <span className="eyebrow">Fixed-query integration</span>
          <h2>Add Prometheus datasource</h2>
        </div>
        <button className="icon-button" onClick={onClose} aria-label="Close datasource dialog">
          <Icon symbol="×" />
        </button>
      </div>
      <form
        id="datasource-create-form"
        className="wizard-body source-config-form"
        onSubmit={submit}
      >
        <div className="form-grid">
          <label>
            <span>Datasource name</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              autoFocus
            />
          </label>
          <label>
            <span>Prometheus HTTPS URL</span>
            <input
              type="url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              required
            />
          </label>
          <label>
            <span>Owning node ID · optional</span>
            <input value={nodeId} onChange={(event) => setNodeId(event.target.value)} />
          </label>
          <label>
            <span>Region · optional</span>
            <input value={region} onChange={(event) => setRegion(event.target.value)} />
          </label>
          <label>
            <span>Authentication</span>
            <select
              value={authType}
              onChange={(event) => setAuthType(event.target.value as "none" | "bearer" | "basic")}
            >
              <option value="none">None</option>
              <option value="bearer">Bearer token</option>
              <option value="basic">Basic auth</option>
            </select>
          </label>
        </div>
        {authType === "bearer" && (
          <label className="full-field">
            <span>Bearer token · write-only field</span>
            <input
              type="password"
              autoComplete="new-password"
              value={bearerToken}
              onChange={(event) => setBearerToken(event.target.value)}
              required
            />
          </label>
        )}
        {authType === "basic" && (
          <div className="form-grid">
            <label>
              <span>Username · write-only field</span>
              <input
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
              />
            </label>
            <label>
              <span>Password · write-only field</span>
              <input
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </label>
          </div>
        )}
        <div className="token-safety-note">
          <Icon symbol="◇" />
          <span>
            Credentials are encrypted and responses expose only the authentication type and
            configured field names.
          </span>
        </div>
        {error && (
          <div className="permission-message permission-message--warning" role="alert">
            <Icon symbol="!" /> {error}
          </div>
        )}
      </form>
      <div className="modal-foot">
        <button className="text-button" onClick={onClose}>
          Cancel
        </button>
        <button
          className="button button--primary"
          type="submit"
          form="datasource-create-form"
          disabled={saving || !name.trim() || !url.trim()}
        >
          {saving ? "Creating…" : "Create datasource"}
        </button>
      </div>
    </Modal>
  );
}

type PushSetupMessage = { tone: "success" | "warning"; text: string };

async function pushApiRequest(
  path: string,
  init: RequestInit,
  timeoutMessage: string,
  signal: AbortSignal,
  expectedAuthGeneration: number,
  expectedSessionId: string | null,
) {
  if (signal.aborted) throw new PushSetupCancelledError();
  const controller = new AbortController();
  const cancel = () => controller.abort();
  signal.addEventListener("abort", cancel, { once: true });
  const timer = window.setTimeout(() => controller.abort(), 10_000);
  try {
    return await apiFetch(
      path,
      { ...init, signal: controller.signal },
      expectedAuthGeneration,
      expectedSessionId,
    );
  } catch (reason) {
    if (signal.aborted || reason instanceof PushSetupCancelledError) {
      throw new PushSetupCancelledError();
    }
    if (controller.signal.aborted) throw new Error(timeoutMessage, { cause: reason });
    throw reason;
  } finally {
    window.clearTimeout(timer);
    signal.removeEventListener("abort", cancel);
  }
}

function NotificationOnboarding({
  onClose,
  onSubscribed,
}: {
  onClose: () => void;
  onSubscribed: () => void;
}) {
  const appName = useContext(AppNameContext);
  const environment = useMemo(() => currentPushClientEnvironment(), []);
  const [permission, setPermission] = useState<NotificationPermission | "unsupported">(() =>
    typeof Notification === "undefined" ? "unsupported" : Notification.permission,
  );
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<PushSetupMessage | null>(() =>
    typeof Notification !== "undefined" && Notification.permission === "denied"
      ? { tone: "warning", text: blockedPermissionHelp(environment) }
      : null,
  );
  const mounted = useRef(true);
  const activeOperation = useRef<AbortController | null>(null);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeOperation.current?.abort();
      activeOperation.current = null;
    };
  }, []);
  const requestClose = () => {
    if (busy) return;
    activeOperation.current?.abort();
    activeOperation.current = null;
    onClose();
  };
  const enable = async () => {
    if (
      typeof Notification === "undefined" ||
      !("serviceWorker" in navigator) ||
      typeof PushManager === "undefined"
    ) {
      setPermission("unsupported");
      setMessage({
        tone: "warning",
        text: "This browser does not expose the Notifications, Service Worker, and Push APIs required for Web Push.",
      });
      return;
    }
    if (!window.isSecureContext) {
      setMessage({
        tone: "warning",
        text: "Web Push requires a secure HTTPS context. Reopen Alert Hub through its HTTPS address.",
      });
      return;
    }
    if (environment.ios && !environment.standalone) {
      setMessage({
        tone: "warning",
        text: "On iPhone and iPad, install Alert Hub with Share → Add to Home Screen, open that installed app, sign in, and enable notifications there.",
      });
      return;
    }
    if (Notification.permission === "denied") {
      setPermission("denied");
      setMessage({ tone: "warning", text: blockedPermissionHelp(environment) });
      return;
    }
    const operationGeneration = authGeneration;
    const operationSessionId = memorySessionId;
    const controller = new AbortController();
    activeOperation.current?.abort();
    activeOperation.current = controller;
    let createdSubscription: PushSubscription | null = null;
    let registrationStarted = false;
    let subscriptionSaved = false;
    const assertActive = () => {
      if (
        controller.signal.aborted ||
        !mounted.current ||
        activeOperation.current !== controller ||
        authGeneration !== operationGeneration ||
        memorySessionId !== operationSessionId
      ) {
        throw new PushSetupCancelledError();
      }
    };
    setBusy(true);
    setMessage(null);
    try {
      const result =
        Notification.permission === "granted" ? "granted" : await Notification.requestPermission();
      assertActive();
      setPermission(result);
      if (result !== "granted") {
        setMessage({
          tone: "warning",
          text:
            result === "denied"
              ? blockedPermissionHelp(environment)
              : "Notification permission was not granted. Try again when you are ready to accept the browser prompt.",
        });
        return;
      }
      const registration = await withPushTimeout(
        (async () => {
          const current = await navigator.serviceWorker.getRegistration("/");
          if (!current) await navigator.serviceWorker.register("/sw.js", { scope: "/" });
          return navigator.serviceWorker.ready;
        })(),
        10_000,
        "Service worker registration timed out. Reload the page and try again.",
      );
      assertActive();
      const keyResponse = await pushApiRequest(
        "/push/vapid-public-key",
        {},
        "The API did not return its Web Push key in time.",
        controller.signal,
        operationGeneration,
        operationSessionId,
      );
      assertActive();
      if (!keyResponse.ok) {
        const detail = await apiError(
          keyResponse,
          `This API node cannot publish a Web Push key (${keyResponse.status}).`,
        );
        assertActive();
        throw new Error(detail);
      }
      const keyBody = asRecord(await keyResponse.json().catch(() => ({})));
      assertActive();
      const vapidKey = String(keyBody.public_key ?? keyBody.vapid_public_key ?? "");
      const applicationServerKey = decodeApplicationServerKey(vapidKey);
      let subscription = await withPushTimeout(
        registration.pushManager.getSubscription(),
        10_000,
        "The browser did not return its current Push subscription in time.",
      );
      assertActive();
      if (
        subscription &&
        !applicationServerKeyMatches(
          subscription.options.applicationServerKey,
          applicationServerKey,
        )
      ) {
        const removed = await withPushTimeout(
          subscription.unsubscribe(),
          10_000,
          "The browser could not replace its outdated Push subscription in time.",
        );
        assertActive();
        if (!removed) throw new Error("The browser refused to replace its outdated Push key.");
        subscription = null;
      }
      if (!subscription) {
        createdSubscription = await withPushTimeout(
          registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey,
          }),
          15_000,
          "The browser Push service did not create a subscription in time.",
        );
        subscription = createdSubscription;
        assertActive();
      }
      const body = subscription.toJSON();
      if (!body.endpoint || !body.keys?.p256dh || !body.keys.auth) {
        throw new Error("The browser returned an incomplete Push subscription.");
      }
      assertActive();
      registrationStarted = true;
      const response = await pushApiRequest(
        "/push/subscriptions",
        {
          method: "POST",
          body: JSON.stringify({
            ...body,
            device_name: currentPushDeviceName(),
            user_agent: navigator.userAgent,
          }),
        },
        "The API did not save this Push subscription in time.",
        controller.signal,
        operationGeneration,
        operationSessionId,
      );
      assertActive();
      if (!response.ok) {
        const detail = await apiError(
          response,
          `The API rejected this Push subscription (${response.status}).`,
        );
        assertActive();
        throw new Error(detail);
      }
      subscriptionSaved = true;
      assertActive();
      setMessage({
        tone: "success",
        text: "This device is subscribed. Use Channels → Send test to verify visible delivery.",
      });
      assertActive();
      onSubscribed();
    } catch (reason) {
      if (reason instanceof PushSetupCancelledError || !mounted.current) {
        if (createdSubscription && !registrationStarted && !subscriptionSaved) {
          await withPushTimeout(
            createdSubscription.unsubscribe(),
            2_000,
            "Push subscription cleanup timed out.",
          ).catch(() => undefined);
        }
        if (
          mounted.current &&
          (authGeneration !== operationGeneration || memorySessionId !== operationSessionId)
        ) {
          setMessage({
            tone: "warning",
            text: "Your authenticated session changed while notifications were being configured. Reload the page and try again.",
          });
        }
        return;
      }
      const detail =
        reason instanceof DOMException && reason.name === "NotAllowedError"
          ? blockedPermissionHelp(environment)
          : reason instanceof Error && reason.message
            ? reason.message
            : "The browser or API could not complete the Push subscription.";
      setMessage({ tone: "warning", text: detail });
    } finally {
      if (activeOperation.current === controller) activeOperation.current = null;
      if (mounted.current) setBusy(false);
    }
  };
  return (
    <Modal onClose={requestClose} label="Enable notifications">
      <div className="modal-head">
        <div>
          <span className="eyebrow">Web Push onboarding</span>
          <h2>Never miss a cluster alert</h2>
        </div>
        <button className="icon-button" onClick={requestClose} aria-label="Close" disabled={busy}>
          <Icon symbol="×" />
        </button>
      </div>
      <div className="notification-hero">
        <span className="notification-device">
          <i />
          <Icon symbol="!" />
        </span>
        <div className="notification-card-preview">
          <span className="brand-mark brand-mark--small">
            <i />
            <i />
            <i />
          </span>
          <span>
            <small>{appName.toUpperCase()} · NOW</small>
            <b>Core API latency breach</b>
            <p>Critical · NL → api-core</p>
          </span>
        </div>
      </div>
      <div className="notification-body">
        <p>
          {environment.ios
            ? environment.standalone
              ? "This installed Home Screen app can request Web Push after the action below."
              : "On iPhone and iPad, Web Push works only from the installed Home Screen app."
            : "Permission is requested only after the action below. Alert Hub then registers this browser with the cluster."}
        </p>
        <ol className="onboarding-steps">
          {environment.ios && !environment.standalone ? (
            <>
              <li>
                <span>1</span>
                <p>
                  <b>Open in Safari</b>
                  <small>Use the Share menu for this site.</small>
                </p>
              </li>
              <li>
                <span>2</span>
                <p>
                  <b>Add to Home Screen</b>
                  <small>Launch {appName} from its new icon and sign in.</small>
                </p>
              </li>
              <li>
                <span>3</span>
                <p>
                  <b>Enable notifications</b>
                  <small>Approve the system prompt from the installed app.</small>
                </p>
              </li>
            </>
          ) : (
            <>
              <li>
                <span>1</span>
                <p>
                  <b>Allow notifications</b>
                  <small>Approve the browser or system prompt.</small>
                </p>
              </li>
              <li>
                <span>2</span>
                <p>
                  <b>Register this device</b>
                  <small>The subscription is encrypted and stored by the cluster.</small>
                </p>
              </li>
              <li>
                <span>3</span>
                <p>
                  <b>Send a test</b>
                  <small>Verify delivery from the Web Push channel.</small>
                </p>
              </li>
            </>
          )}
        </ol>
        {permission === "unsupported" && (
          <div className="permission-message permission-message--warning">
            <Icon symbol="!" />
            This browser does not expose Notifications and Service Worker support.
          </div>
        )}
        {message && (
          <div
            className={`permission-message permission-message--${message.tone}`}
            role={message.tone === "warning" ? "alert" : "status"}
          >
            <Icon symbol={message.tone === "success" ? "✓" : "!"} />
            {message.text}
          </div>
        )}
      </div>
      <div className="modal-foot modal-foot--stack-mobile">
        <button className="text-button" onClick={requestClose} disabled={busy}>
          Maybe later
        </button>
        <button
          className="button button--primary"
          disabled={busy || permission === "unsupported"}
          onClick={() => void enable()}
        >
          <Icon symbol="◉" />
          {busy
            ? "Connecting…"
            : message?.tone === "success" || permission === "granted"
              ? "Verify subscription"
              : permission === "denied"
                ? "Show recovery steps"
                : "Enable notifications"}
        </button>
      </div>
    </Modal>
  );
}
