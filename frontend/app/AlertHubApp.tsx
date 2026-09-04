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
type UiLanguage = "ru" | "en";
const LANGUAGE_STORAGE_KEY = "alert-hub-ui-language";
const LanguageContext = createContext<{
  language: UiLanguage;
  setLanguage: (language: UiLanguage) => void;
}>({ language: "ru", setLanguage: () => undefined });

function currentUiLanguage(): UiLanguage {
  if (typeof window === "undefined") return "ru";
  try {
    const stored = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (stored === "ru" || stored === "en") return stored;
  } catch {
    // Storage can be blocked in hardened browser contexts; the document language remains usable.
  }
  return document.documentElement.lang === "en" ? "en" : "ru";
}

function tr(russian: string, english: string) {
  return currentUiLanguage() === "ru" ? russian : english;
}

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
    super(
      tr(
        "Настройка Push отменена: активная сессия изменилась.",
        "Push setup was cancelled because the active session changed.",
      ),
    );
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

function createTimelineA(): IncidentEvent[] {
  return [
    {
      id: "evt-a4",
      type: "delivery_succeeded",
      label: tr("Push доставлен", "Push delivered"),
      detail: tr(
        "Основной узел доставки eu-nl-01 завершил отправку с первой попытки.",
        "Primary delivery owner eu-nl-01 completed on attempt 1.",
      ),
      at: "2026-09-01T12:44:11Z",
      node: "eu-nl-01",
    },
    {
      id: "evt-a3",
      type: "replicated",
      label: tr("Синхронизировано на 3 узла", "Replicated to 3 nodes"),
      detail: tr(
        "Событие кластера согласовано; векторные курсоры инцидента совпадают.",
        "Cluster event converged; vector cursors match for this incident.",
      ),
      at: "2026-09-01T12:44:08Z",
      node: "ru-msk-01",
    },
    {
      id: "evt-a2",
      type: "firing",
      label: tr("Порог всё ещё превышен", "Threshold still exceeded"),
      detail: tr(
        "Задержка p95 держится на 2,84 сек. пять минут подряд.",
        "p95 latency 2.84 s for 5 consecutive minutes.",
      ),
      at: "2026-09-01T12:44:02Z",
      node: "eu-nl-01",
    },
    {
      id: "evt-a1",
      type: "firing",
      label: tr("Инцидент открыт", "Incident opened"),
      detail: tr(
        "Alertmanager обработал активное событие от prometheus-nl.",
        "Alertmanager normalized a firing event from prometheus-nl.",
      ),
      at: "2026-09-01T12:39:02Z",
      node: "eu-nl-01",
    },
  ];
}

function createDemoData(): HubData {
  return {
    incidents: [
      {
        id: "inc-01J7ZQ4K8W8AWMRV77B9",
        title: tr("Высокая задержка основного API", "Core API latency breach"),
        description: tr(
          "p95 Checkout API превышает 2,5 сек. из двух регионов проверки.",
          "Checkout API p95 is above 2.5 s from two probe regions.",
        ),
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
          summary: tr(
            "Задержка p95 Checkout API превышает SLO",
            "Checkout API p95 latency exceeds SLO",
          ),
          runbook_url: "https://runbooks.example.net/api-latency",
        },
        events: createTimelineA(),
      },
      {
        id: "inc-01J7ZNRQBGCQKD0NN06T",
        title: tr("Точка VLESS недоступна", "VLESS endpoint unreachable"),
        description: tr(
          "nl-edge-02 не отвечает с московского узла проверки.",
          "nl-edge-02 is unreachable from the Moscow probe node.",
        ),
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
        annotations: {
          summary: tr("Проверка с ru-msk-01 не прошла", "Probe failed from ru-msk-01"),
        },
        events: [
          {
            id: "evt-b3",
            type: "acknowledged",
            label: tr("Принят в работу оператором", "Acknowledged by operator"),
            detail: tr(
              "Проверяем изменения маршрута у провайдера.",
              "Investigating upstream route changes.",
            ),
            at: "2026-09-01T12:42:52Z",
            node: "ru-msk-01",
            actor: "ops@local",
          },
          {
            id: "evt-b2",
            type: "delivery_succeeded",
            label: tr("Доставлено в Telegram", "Telegram delivered"),
            detail: tr(
              "Политика доставки в ЕС выбрала узел eu-de-01.",
              "EU-only delivery policy selected eu-de-01.",
            ),
            at: "2026-09-01T12:31:34Z",
            node: "eu-de-01",
          },
          {
            id: "evt-b1",
            type: "firing",
            label: tr("Инцидент открыт", "Incident opened"),
            detail: tr(
              "probe_success вернул 0 с узла ru-msk-01.",
              "probe_success returned 0 from ru-msk-01.",
            ),
            at: "2026-09-01T12:31:25Z",
            node: "ru-msk-01",
          },
        ],
      },
      {
        id: "inc-01J7ZHW5D6W2C66RJ2EM",
        title: tr("Сертификат TLS истекает через 12 дней", "TLS certificate expires in 12 days"),
        description: tr(
          "Сертификат portal.example.net вошёл в интервал предупреждения.",
          "portal.example.net certificate is inside the warning window.",
        ),
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
        annotations: {
          summary: tr(
            "Срок действия сертификата меньше 14 дней",
            "Certificate validity below 14 days",
          ),
        },
        events: [
          {
            id: "evt-c1",
            type: "firing",
            label: tr("Инцидент открыт", "Incident opened"),
            detail: tr(
              "До истечения сертификата осталось 12,4 дня.",
              "Certificate has 12.4 days remaining.",
            ),
            at: "2026-09-01T11:58:00Z",
            node: "eu-de-01",
          },
        ],
      },
      {
        id: "inc-01J7Z9P2ZVM3A1NNDKWB",
        title: tr("Синхронизация узла восстановлена", "Peer sync lag recovered"),
        description: tr(
          "eu-de-01 догнал кластер после краткого разрыва WireGuard.",
          "eu-de-01 caught up after a transient WireGuard interruption.",
        ),
        severity: "info",
        status: "resolved",
        source: tr("Состояние Alert Hub", "Alert Hub health"),
        region: "DE",
        target: "eu-de-01",
        startsAt: "2026-09-01T10:42:00Z",
        lastEventAt: "2026-09-01T11:07:19Z",
        labels: {
          alertname: "PeerSyncLagHigh",
          source_region: "nl",
          target_name: "eu-de-01",
        },
        annotations: {
          summary: tr(
            "Узел восстановился без ручного вмешательства",
            "Peer recovered without manual action",
          ),
        },
        events: [
          {
            id: "evt-d2",
            type: "resolved",
            label: tr("Инцидент решён", "Incident resolved"),
            detail: tr(
              "Задержка синхронизации вернулась ниже 5 секунд.",
              "Sync lag returned below 5 seconds.",
            ),
            at: "2026-09-01T11:07:19Z",
            node: "eu-nl-01",
          },
          {
            id: "evt-d1",
            type: "firing",
            label: tr("Инцидент открыт", "Incident opened"),
            detail: tr(
              "Отставание курсора узла достигло 184 секунд.",
              "Peer cursor lag reached 184 seconds.",
            ),
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
        city: tr("Москва", "Moscow"),
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
        city: tr("Амстердам", "Amsterdam"),
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
        city: tr("Франкфурт", "Frankfurt"),
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
        name: tr("Контроль биллинга", "Billing heartbeat"),
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
        name: tr("События деплоя", "Deploy events"),
        kind: "generic_json",
        region: tr("Глобально", "Global"),
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
        name: tr("Web Push оператора", "Operator Web Push"),
        kind: "web_push",
        health: "healthy",
        enabled: true,
        delivered24h: 48,
        deliveryAttempts24h: 49,
        successRate: 98.7,
        eligible: tr("Все узлы", "All nodes"),
        eligibleRegions: [],
        eligibleNodeIds: [],
        configuredFields: [],
        configAvailable: true,
      },
      {
        id: "ch-tg",
        name: tr("Дежурный Telegram ЕС", "EU on-call Telegram"),
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
        name: tr("Сводка инцидентов", "Incident digest"),
        kind: "smtp",
        health: "degraded",
        enabled: true,
        delivered24h: 7,
        deliveryAttempts24h: 8,
        successRate: 92.1,
        eligible: tr("Все узлы", "All nodes"),
        eligibleRegions: [],
        eligibleNodeIds: [],
        configuredFields: ["host", "port", "from", "to", "tls"],
        configAvailable: true,
      },
      {
        id: "ch-hook",
        name: tr("Вебхук тикет-системы", "Ticketing webhook"),
        kind: "generic_webhook",
        health: "paused",
        enabled: false,
        delivered24h: 0,
        deliveryAttempts24h: 0,
        successRate: null,
        eligible: tr("Только NL", "NL only"),
        eligibleRegions: ["NL"],
        eligibleNodeIds: [],
        configuredFields: ["url", "hmac_secret"],
        configAvailable: true,
      },
    ],
    routes: [
      {
        id: "route-demo-critical",
        name: tr("Критические — во все каналы", "Critical fan-out"),
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
        name: tr("Демо Prometheus", "Demo Prometheus"),
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
        name: tr("iPhone Дмитрия", "Dmitry’s iPhone"),
        platform: "iOS PWA · Safari",
        current: true,
        push: true,
        lastUsed: "2026-09-01T12:45:20Z",
        location: tr("Москва, RU", "Moscow, RU"),
      },
      {
        id: "dev-mac",
        name: tr("Рабочий MacBook", "Operations MacBook"),
        platform: "macOS · Chrome",
        current: false,
        push: true,
        lastUsed: "2026-09-01T09:13:08Z",
        location: tr("Москва, RU", "Moscow, RU"),
      },
      {
        id: "dev-ipad",
        name: tr("Дежурный iPad", "On-call iPad"),
        platform: "iPadOS PWA · Safari",
        current: false,
        push: false,
        lastUsed: "2026-08-29T18:21:42Z",
        location: tr("Амстердам, NL", "Amsterdam, NL"),
      },
    ],
    audit: [
      {
        id: "aud-1",
        action: tr("Инцидент принят в работу", "Incident acknowledged"),
        detail: tr(
          "Точка VLESS недоступна · расследование начато",
          "VLESS endpoint unreachable · investigation started",
        ),
        actor: "ops@local",
        node: "ru-msk-01",
        at: "2026-09-01T12:42:52Z",
        tone: "warning",
      },
      {
        id: "aud-2",
        action: tr("Переключение доставки", "Delivery failover"),
        detail: tr(
          "Доставка Telegram перенесена с eu-nl-01 на eu-de-01",
          "Telegram delivery moved from eu-nl-01 to eu-de-01",
        ),
        actor: tr("система", "system"),
        node: "eu-de-01",
        at: "2026-09-01T12:31:34Z",
        tone: "success",
      },
      {
        id: "aud-3",
        action: tr("Настройки источника изменены", "Source configuration changed"),
        detail: tr(
          "Допустимая задержка сигнала биллинга изменена с 60 до 90 сек.",
          "Billing heartbeat grace period changed from 60s to 90s",
        ),
        actor: "ops@local",
        node: "eu-nl-01",
        at: "2026-09-01T11:28:02Z",
        tone: "neutral",
      },
      {
        id: "aud-4",
        action: tr("Связь с узлом восстановлена", "Peer connection restored"),
        detail: tr(
          "eu-de-01 завершил синхронизацию; применено 286 событий",
          "eu-de-01 completed resync; 286 events applied",
        ),
        actor: tr("система", "system"),
        node: "eu-de-01",
        at: "2026-09-01T11:07:19Z",
        tone: "success",
      },
      {
        id: "aud-5",
        action: tr("Проверка канала не прошла", "Channel test failed"),
        detail: tr(
          "SMTP-провайдер вернул 451; повтор поставлен в очередь",
          "SMTP provider returned 451; retry queued",
        ),
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
        source: tr("Москва", "Moscow"),
        target: "api-core",
        success: true,
        latency: 182,
        checkedAt: "2026-09-01T12:45:18Z",
      },
      {
        source: tr("Москва", "Moscow"),
        target: "nl-edge-02",
        success: false,
        latency: null,
        checkedAt: "2026-09-01T12:45:16Z",
      },
      {
        source: tr("Москва", "Moscow"),
        target: "portal",
        success: true,
        latency: 211,
        checkedAt: "2026-09-01T12:45:17Z",
      },
      {
        source: tr("Москва", "Moscow"),
        target: "billing",
        success: true,
        latency: 238,
        checkedAt: "2026-09-01T12:45:14Z",
      },
      {
        source: tr("Амстердам", "Amsterdam"),
        target: "api-core",
        success: true,
        latency: 44,
        checkedAt: "2026-09-01T12:45:19Z",
      },
      {
        source: tr("Амстердам", "Amsterdam"),
        target: "nl-edge-02",
        success: true,
        latency: 18,
        checkedAt: "2026-09-01T12:45:19Z",
      },
      {
        source: tr("Амстердам", "Amsterdam"),
        target: "portal",
        success: true,
        latency: 26,
        checkedAt: "2026-09-01T12:45:18Z",
      },
      {
        source: tr("Амстердам", "Amsterdam"),
        target: "billing",
        success: true,
        latency: 73,
        checkedAt: "2026-09-01T12:45:16Z",
      },
      {
        source: tr("Франкфурт", "Frankfurt"),
        target: "api-core",
        success: true,
        latency: 61,
        checkedAt: "2026-09-01T12:45:08Z",
      },
      {
        source: tr("Франкфурт", "Frankfurt"),
        target: "nl-edge-02",
        success: true,
        latency: 33,
        checkedAt: "2026-09-01T12:45:08Z",
      },
      {
        source: tr("Франкфурт", "Frankfurt"),
        target: "portal",
        success: true,
        latency: 17,
        checkedAt: "2026-09-01T12:45:07Z",
      },
      {
        source: tr("Франкфурт", "Frankfurt"),
        target: "billing",
        success: false,
        latency: null,
        checkedAt: "2026-09-01T12:45:04Z",
      },
    ],
    reachabilityMeta: {
      status: "ok",
      detail: tr("Демонстрационные данные доступности", "Demo reachability fixture"),
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
            datasourceName: tr("Демо Prometheus", "Demo Prometheus"),
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
            datasourceName: tr("Демо Prometheus", "Demo Prometheus"),
            metric: { instance: "prometheus:9090", job: "prometheus" },
            value: 1,
            timestamp: "2026-09-01T12:45:20Z",
          },
          {
            datasourceId: "prom-demo",
            datasourceName: tr("Демо Prometheus", "Demo Prometheus"),
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
            datasourceName: tr("Демо Prometheus", "Demo Prometheus"),
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
}

const NAV_ITEMS = [
  {
    id: "overview",
    get label() {
      return tr("Обзор", "Overview");
    },
    path: "/",
    icon: "◫",
  },
  {
    id: "incidents",
    get label() {
      return tr("Инциденты", "Incidents");
    },
    path: "/incidents",
    icon: "!",
  },
  {
    id: "reachability",
    get label() {
      return tr("Доступность", "Regional reachability");
    },
    path: "/reachability",
    icon: "∿",
  },
  {
    id: "sources",
    get label() {
      return tr("Источники", "Sources");
    },
    path: "/sources",
    icon: "→",
  },
  {
    id: "channels",
    get label() {
      return tr("Каналы", "Channels");
    },
    path: "/channels",
    icon: "≫",
  },
  {
    id: "devices",
    get label() {
      return tr("Устройства", "Devices");
    },
    path: "/devices",
    icon: "▣",
  },
  {
    id: "cluster",
    get label() {
      return tr("Кластер", "Cluster");
    },
    path: "/cluster",
    icon: "⌘",
  },
  {
    id: "audit",
    get label() {
      return tr("Журнал действий", "Audit log");
    },
    path: "/audit",
    icon: "≡",
  },
  {
    id: "settings",
    get label() {
      return tr("Настройки", "Settings");
    },
    path: "/settings",
    icon: "⚙",
  },
] as const;

type RouteId = (typeof NAV_ITEMS)[number]["id"] | "incident";

function titleCase(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

const HEALTH_LABELS: Record<Health, readonly [string, string]> = {
  healthy: ["Работает", "Healthy"],
  degraded: ["Есть проблемы", "Degraded"],
  offline: ["Нет связи", "Offline"],
  paused: ["Приостановлено", "Paused"],
  unknown: ["Нет данных", "Unknown"],
  not_exercised: ["Не проверено", "Not Exercised"],
};

const SEVERITY_LABELS: Record<Severity, readonly [string, string]> = {
  critical: ["Критический", "Critical"],
  warning: ["Предупреждение", "Warning"],
  info: ["Информация", "Info"],
  unknown: ["Неизвестно", "Unknown"],
};

const INCIDENT_STATUS_LABELS: Record<IncidentStatus, readonly [string, string]> = {
  open: ["Открыт", "Open"],
  acknowledged: ["Принят в работу", "Acknowledged"],
  resolved: ["Решён", "Resolved"],
  silenced: ["Приглушён", "Silenced"],
};

const SOURCE_KIND_LABELS: Record<Source["kind"], readonly [string, string]> = {
  alertmanager: ["Alertmanager", "Alertmanager"],
  generic_json: ["JSON-вебхук", "Generic Json"],
  heartbeat: ["Контрольный сигнал", "Heartbeat"],
};

const CHANNEL_KIND_LABELS: Record<Channel["kind"], readonly [string, string]> = {
  web_push: ["Web Push", "Web Push"],
  telegram: ["Telegram", "Telegram"],
  smtp: ["Электронная почта", "Smtp"],
  generic_webhook: ["Вебхук", "Generic Webhook"],
};

function healthLabel(value: Health) {
  const [russian, english] = HEALTH_LABELS[value] ?? HEALTH_LABELS.unknown;
  return tr(russian, english);
}

function severityLabel(value: Severity) {
  const [russian, english] = SEVERITY_LABELS[value] ?? SEVERITY_LABELS.unknown;
  return tr(russian, english);
}

function incidentStatusLabel(value: IncidentStatus) {
  const label = INCIDENT_STATUS_LABELS[value];
  return label ? tr(label[0], label[1]) : value;
}

function sourceKindLabel(value: Source["kind"]) {
  const label = SOURCE_KIND_LABELS[value];
  return label ? tr(label[0], label[1]) : value;
}

function channelKindLabel(value: Channel["kind"]) {
  const label = CHANNEL_KIND_LABELS[value];
  return label ? tr(label[0], label[1]) : value;
}

function isSystemActor(value: string) {
  return value === "system" || value === "система";
}

const EVENT_TYPE_LABELS: Record<string, readonly [string, string]> = {
  firing: ["Тревога активна", "Firing"],
  resolved: ["Инцидент решён", "Resolved"],
  acknowledged: ["Инцидент принят в работу", "Acknowledged"],
  silenced: ["Инцидент приглушён", "Silenced"],
  commented: ["Добавлен комментарий", "Commented"],
  delivery_succeeded: ["Уведомление доставлено", "Delivery Succeeded"],
  delivery_failed: ["Ошибка доставки", "Delivery Failed"],
  delivery_retry: ["Повторная доставка", "Delivery Retry"],
  replicated: ["Событие синхронизировано", "Replicated"],
};

const AUDIT_ACTION_LABELS: Record<string, readonly [string, string]> = {
  bootstrap_failed: ["Ошибка первичной настройки", "Bootstrap Failed"],
  bootstrap_completed: ["Первичная настройка завершена", "Bootstrap Completed"],
  bootstrap_conflict_detected: [
    "Обнаружен конфликт первичной настройки",
    "Bootstrap Conflict Detected",
  ],
  login_failed: ["Неудачная попытка входа", "Login Failed"],
  login_succeeded: ["Вход выполнен", "Login Succeeded"],
  session_refreshed: ["Сессия обновлена", "Session Refreshed"],
  logout: ["Выход из системы", "Logout"],
  session_revoked: ["Сессия отозвана", "Session Revoked"],
  source_created: ["Источник создан", "Source Created"],
  source_updated: ["Источник обновлён", "Source Updated"],
  source_deleted: ["Источник удалён", "Source Deleted"],
  source_token_rotated: ["Токен источника обновлён", "Source Token Rotated"],
  ingest_auth_failed: ["Ошибка авторизации источника", "Ingest Auth Failed"],
  channel_created: ["Канал создан", "Channel Created"],
  channel_updated: ["Канал обновлён", "Channel Updated"],
  channel_deleted: ["Канал удалён", "Channel Deleted"],
  channel_test_requested: ["Запрошена проверка канала", "Channel Test Requested"],
  channel_test_rejected: ["Проверка канала отклонена", "Channel Test Rejected"],
  channel_test_completed: ["Проверка канала завершена", "Channel Test Completed"],
  notification_route_created: ["Маршрут уведомлений создан", "Notification Route Created"],
  notification_route_updated: ["Маршрут уведомлений обновлён", "Notification Route Updated"],
  notification_route_deleted: ["Маршрут уведомлений удалён", "Notification Route Deleted"],
  incident_acknowledged: ["Инцидент принят в работу", "Incident Acknowledged"],
  incident_resolved: ["Инцидент решён", "Incident Resolved"],
  incident_silenced: ["Инцидент приглушён", "Incident Silenced"],
  prometheus_datasource_created: ["Источник Prometheus создан", "Prometheus Datasource Created"],
  prometheus_datasource_updated: ["Источник Prometheus обновлён", "Prometheus Datasource Updated"],
  prometheus_datasource_deleted: ["Источник Prometheus удалён", "Prometheus Datasource Deleted"],
  prometheus_datasource_test_failed: [
    "Проверка Prometheus не прошла",
    "Prometheus Datasource Test Failed",
  ],
  cluster_peer_denied: ["Подключение узла отклонено", "Cluster Peer Denied"],
  cluster_auth_failed: ["Ошибка авторизации узла", "Cluster Auth Failed"],
  push_subscription_created: ["Push-подписка создана", "Push Subscription Created"],
  push_subscription_updated: ["Push-подписка обновлена", "Push Subscription Updated"],
  push_subscription_disabled: ["Push-подписка отключена", "Push Subscription Disabled"],
};

function eventTypeLabel(value: string) {
  const label = EVENT_TYPE_LABELS[value];
  return label ? tr(label[0], label[1]) : titleCase(value);
}

function auditActionLabel(code: string, fallback: unknown) {
  const label = AUDIT_ACTION_LABELS[code];
  return label ? tr(label[0], label[1]) : String(fallback ?? titleCase(code));
}

function formatRelative(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || tr("Никогда", "Never");
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return tr(`${Math.max(1, seconds)} сек. назад`, `${Math.max(1, seconds)}s ago`);
  if (seconds < 3600)
    return tr(`${Math.floor(seconds / 60)} мин. назад`, `${Math.floor(seconds / 60)}m ago`);
  if (seconds < 86400)
    return tr(`${Math.floor(seconds / 3600)} ч. назад`, `${Math.floor(seconds / 3600)}h ago`);
  return tr(`${Math.floor(seconds / 86400)} дн. назад`, `${Math.floor(seconds / 86400)}d ago`);
}

function formatDate(value: string, includeDate = false) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || "—";
  return (
    new Intl.DateTimeFormat(currentUiLanguage() === "ru" ? "ru-RU" : "en-GB", {
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
  if (Number.isNaN(date.getTime())) return tr("Журнал действий", "Audit trail");
  return new Intl.DateTimeFormat(currentUiLanguage() === "ru" ? "ru-RU" : "en-GB", {
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
    title: tr("Высокая задержка Checkout API", "Checkout API latency is high"),
    description: tr(
      "p95 превышает 800 мс в течение 10 минут",
      "p95 exceeded 800 ms for 10 minutes",
    ),
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
    throw new Error(
      tr(
        "Адрес источника должен использовать текущий домен Alert Hub.",
        "The source endpoint must use this Alert Hub origin.",
      ),
    );
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
    throw new Error(
      tr(
        "API не вернул обязательные одноразовые данные доступа источника.",
        "The API did not return the required one-time source credential fields.",
      ),
    );
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
    title: String(row.title ?? row.name ?? tr("Инцидент без названия", "Untitled incident")),
    description: String(
      row.description ?? row.summary ?? tr("Описание не добавлено.", "No description provided."),
    ),
    severity: (["critical", "warning", "info", "unknown"].includes(String(row.severity))
      ? String(row.severity)
      : "unknown") as Severity,
    status: (["open", "acknowledged", "resolved", "silenced"].includes(String(row.status))
      ? String(row.status)
      : "open") as IncidentStatus,
    source: String(
      asRecord(row.source).name ??
        row.source_name ??
        row.source ??
        tr("Источник не указан", "Unknown source"),
    ),
    region: String(
      row.region ?? asRecord(row.labels).source_region ?? tr("Глобально", "Global"),
    ).toUpperCase(),
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
        label: String(entry.label ?? eventTypeLabel(eventType)),
        detail: String(
          entry.detail ??
            entry.description ??
            eventPayload.body ??
            eventPayload.reason ??
            eventPayload.description ??
            eventPayload.title ??
            tr("Подробности события не переданы.", "No event detail supplied."),
        ),
        at: String(entry.occurred_at ?? entry.at ?? entry.created_at ?? ""),
        node: String(entry.origin_node_id ?? entry.node ?? tr("неизвестно", "unknown")),
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
    city: String(
      row.city ?? row.location ?? row.region ?? tr("Регион не указан", "Unknown region"),
    ),
    region: String(row.region ?? "—").toUpperCase(),
    health: (["healthy", "degraded", "offline", "paused"].includes(state)
      ? state
      : state === "online"
        ? "healthy"
        : "unknown") as Health,
    version: String(row.software_version ?? row.version ?? tr("неизвестно", "unknown")),
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
    name: String(row.name ?? tr(`Источник ${index + 1}`, `Source ${index + 1}`)),
    kind: ["alertmanager", "generic_json", "heartbeat"].includes(kind) ? kind : "generic_json",
    region: String(row.region ?? tr("Глобально", "Global")).toUpperCase(),
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
    name: String(row.name ?? tr(`Канал ${index + 1}`, `Channel ${index + 1}`)),
    kind: ["web_push", "telegram", "smtp", "generic_webhook"].includes(kind)
      ? kind
      : "generic_webhook",
    health: (row.enabled === false ? "paused" : String(row.health ?? "unknown")) as Health,
    enabled: row.enabled !== false,
    delivered24h: Number(row.delivered_24h ?? row.delivery_success_24h ?? 0),
    deliveryAttempts24h: Number(row.deliveries_24h ?? row.delivery_count ?? 0),
    successRate: asFiniteNumber(row.success_rate),
    eligible: String(row.eligible ?? tr("Все узлы", "All nodes")),
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
    name: String(row.name ?? tr(`Маршрут ${index + 1}`, `Route ${index + 1}`)),
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
    name: String(row.name ?? tr(`Источник данных ${index + 1}`, `Datasource ${index + 1}`)),
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
    action: auditActionLabel(actionCode, row.action),
    actionCode,
    detail: String(row.detail ?? row.description ?? tr("Системная операция", "System operation")),
    actor: String(row.actor ?? row.username ?? tr("система", "system")),
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
    source: String(row.source ?? row.source_region ?? tr("Неизвестно", "Unknown")),
    target: String(row.target ?? row.target_name ?? tr("Неизвестно", "Unknown")),
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
        datasourceName: String(
          sample.datasource_name ?? tr("Неизвестный источник данных", "Unknown datasource"),
        ),
        metric: asStringRecord(sample.metric),
        value: Number(sample.value ?? 0),
        timestamp: String(sample.timestamp ?? ""),
      };
    }),
    errors: listFrom(body.errors, "errors").map((item) => {
      const error = asRecord(item);
      return {
        datasourceId: String(error.datasource_id ?? ""),
        datasourceName: String(
          error.datasource_name ?? tr("Неизвестный источник данных", "Unknown datasource"),
        ),
        code: String(error.code ?? "unknown"),
        detail: String(error.detail ?? tr("Подробности не переданы", "No detail supplied")),
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
    throw new Error(
      tr("В демо-режиме изменения отключены.", "Live mutations are disabled in demo mode."),
    );
  }
  if (offlineReadOnlyActive && method !== "GET" && method !== "HEAD") {
    throw new Error(
      tr(
        "В офлайн-режиме изменения отключены.",
        "Live mutations are disabled while using an offline cached session.",
      ),
    );
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
  throw primaryError instanceof Error
    ? primaryError
    : new Error(tr("Ни один узел API не ответил", "No API node responded"));
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
    throw new Error(
      await apiError(
        response,
        tr(`Запрос завершился ошибкой (${response.status})`, `Request failed (${response.status})`),
      ),
    );
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

function useHubData(enabled: boolean, demo: boolean, demoLanguage: UiLanguage) {
  const queryClient = useQueryClient();
  const localizedDataVersion = demo ? demoLanguage : "live";
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
        if (successful === 0)
          throw new Error(tr("Ни один узел API не ответил", "No API node responded"));
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
                name: String(
                  row.device_name ??
                    row.name ??
                    tr(`Устройство ${index + 1}`, `Device ${index + 1}`),
                ),
                platform: String(
                  row.platform ?? row.user_agent ?? tr("Сессия браузера", "Browser session"),
                ),
                current: Boolean(row.current ?? row.is_current),
                push: Boolean(row.push_enabled ?? row.push ?? false),
                lastUsed: String(row.last_used_at ?? row.last_used ?? ""),
                location: String(
                  row.location ?? tr("Местоположение неизвестно", "Unknown location"),
                ),
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
                  datasourceName: String(
                    row.datasource_name ?? tr("Неизвестный источник данных", "Unknown datasource"),
                  ),
                  code: String(row.code ?? "unknown"),
                  detail: String(row.detail ?? tr("Подробности не переданы", "No detail supplied")),
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
            tr(
              "Часть запросов к API недоступна. Показаны подтверждённые данные с устройства.",
              "The live API is unavailable for some requests. Showing verified on-device data.",
            ),
          );
        } else {
          setMode("live");
          setError(
            successful < requests.length
              ? tr(
                  "Часть данных кластера временно недоступна.",
                  "Some cluster data is temporarily unavailable.",
                )
              : null,
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
              ? tr(
                  "Узлы API недоступны. Показан последний подтверждённый снимок.",
                  "API nodes are unavailable. Showing the last verified operational snapshot.",
                )
              : tr(
                  "Нет подключения. Показан последний подтверждённый снимок с устройства.",
                  "You are offline. Showing the last verified on-device snapshot.",
                ),
          );
        } else {
          setError(
            navigator.onLine
              ? tr(
                  "Узлы API недоступны, подтверждённых данных нет.",
                  "API nodes are unavailable. No verified operational data is available.",
                )
              : tr(
                  "Нет подключения и сохранённого подтверждённого снимка.",
                  "You are offline and no verified on-device snapshot is available.",
                ),
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
      if (isCurrentRequest())
        setAuditLoadError(
          tr(
            "Не удалось загрузить старые события. Повторите.",
            "Could not load older audit events. Try again.",
          ),
        );
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
        setData(createDemoData());
        setMode("demo");
        setError(
          tr(
            "Показаны демонстрационные данные. Активной сессии API нет.",
            "Preview data only. No live API session is active.",
          ),
        );
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
          ? tr(
              "Нет подключения. Показан последний подтверждённый снимок с устройства.",
              "You are offline. Showing the last verified on-device snapshot.",
            )
          : tr(
              "Нет подключения и сохранённого подтверждённого снимка.",
              "You are offline and no verified on-device snapshot is available.",
            ),
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
  }, [demo, enabled, localizedDataVersion, refresh]);

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
  return (
    <span className={`severity-badge severity-badge--${severity}`}>{severityLabel(severity)}</span>
  );
}

function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={`incident-status incident-status--${status}`}>
      <span aria-hidden="true" />
      {incidentStatusLabel(status)}
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
        <small>{tr("центр мониторинга", "distributed ops")}</small>
      </span>
    </div>
  );
}

function LanguageSwitch({ className = "" }: { className?: string }) {
  const { language, setLanguage } = useContext(LanguageContext);
  return (
    <div
      className={`language-switch ${className}`}
      aria-label={tr("Язык интерфейса", "Interface language")}
    >
      {(["ru", "en"] as const).map((item) => (
        <button
          key={item}
          type="button"
          className={language === item ? "active" : ""}
          aria-pressed={language === item}
          onClick={() => setLanguage(item)}
        >
          {item.toUpperCase()}
        </button>
      ))}
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
        <small>
          {tr("Подключаемся к ближайшему узлу API…", "Contacting the nearest API node…")}
        </small>
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
      setError(tr("Пароли не совпадают.", "Passwords do not match."));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const response = await apiFetch(mode === "login" ? "/auth/login" : "/auth/bootstrap", {
        method: "POST",
        body: JSON.stringify(
          mode === "login"
            ? { username, password, device_name: currentPushDeviceName(currentUiLanguage()) }
            : {
                bootstrap_token: bootstrapToken,
                username,
                password,
                device_name: currentPushDeviceName(currentUiLanguage()),
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
                ? tr("Неверное имя пользователя или пароль.", "Username or password is incorrect.")
                : tr("Не удалось войти.", "Authentication failed.")),
          ),
        );
      }
      onAuthenticated(payload, asRecord(asRecord(payload).user));
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось войти.", "Authentication failed."),
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="auth-screen">
      <LanguageSwitch className="auth-language-switch" />
      <div className="auth-grid" aria-hidden="true" />
      <section className="auth-story">
        <Brand />
        <div className="auth-story__copy">
          <span className="eyebrow">
            {tr("Распределённый мониторинг", "Distributed operations")}
          </span>
          <h1>
            {tr("Каждый узел работает автономно.", "Every node stays useful.")}
            <br />
            <em>{tr("Ни одно событие не потеряется.", "Every event survives.")}</em>
          </h1>
          <p>
            {tr(
              "Принимайте события локально, синхронизируйте их между регионами и получайте оповещения даже при потере связи.",
              "Ingest locally, converge globally, and keep delivering alerts when a region disappears.",
            )}
          </p>
        </div>
        <div className="auth-topology">
          <span className="auth-topology__line auth-topology__line--1" />
          <span className="auth-topology__line auth-topology__line--2" />
          <span className="auth-topology__line auth-topology__line--3" />
          {[
            { code: "A", label: tr("Региональный узел", "Peer region") },
            { code: "B", label: tr("Региональный узел", "Peer region") },
            { code: "C", label: tr("Региональный узел", "Peer region") },
          ].map((node, index) => (
            <div key={node.code} className={`auth-node auth-node--${index + 1}`}>
              <span>{node.code}</span>
              <b>{node.label}</b>
              <small>
                <StatusDot health="unknown" />
                {tr("пример узла", "example node")}
              </small>
            </div>
          ))}
          <div className="auth-topology__center">
            <span className="brand-mark">
              <i />
              <i />
              <i />
            </span>
            <small>{tr("пример топологии", "example topology")}</small>
          </div>
        </div>
        <div className="auth-story__foot">
          <span>
            <Icon symbol="◇" />
            {tr("На своих серверах", "Self-hosted")}
          </span>
          <span>
            <Icon symbol="⇄" />
            {tr("Сначала локально", "Local-first")}
          </span>
          <span>
            <Icon symbol="◉" />
            {tr("Готово к Push", "Push ready")}
          </span>
        </div>
      </section>
      <section className="auth-panel">
        <div className="auth-panel__mobile-brand">
          <Brand />
        </div>
        <div className="auth-card">
          <span className="eyebrow">
            {mode === "login"
              ? tr("Доступ оператора", "Operator access")
              : tr("Настройка первого узла", "First node setup")}
          </span>
          <h2>
            {mode === "login"
              ? tr("Вход в систему", "Welcome back")
              : tr("Запуск кластера", "Bootstrap the cluster")}
          </h2>
          <p>
            {mode === "login"
              ? tr(
                  "Войдите, чтобы просматривать инциденты и управлять кластером.",
                  "Sign in to view the live incident ledger and manage this cluster.",
                )
              : tr(
                  "Используйте одноразовый токен с сервера, чтобы создать первого администратора.",
                  "Use the one-time token stored on the server to create the first administrator.",
                )}
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
              {tr("Войти", "Sign in")}
            </button>
            <button
              className={mode === "bootstrap" ? "active" : ""}
              type="button"
              onClick={() => {
                setMode("bootstrap");
                setError(null);
              }}
            >
              {tr("Первый запуск", "First run")}
            </button>
          </div>
          <form onSubmit={submit}>
            {mode === "bootstrap" && (
              <label>
                <span>{tr("Токен первичной настройки", "Bootstrap token")}</span>
                <input
                  value={bootstrapToken}
                  onChange={(event) => setBootstrapToken(event.target.value)}
                  autoComplete="off"
                  placeholder={tr("Вставьте токен с сервера", "Paste token from the server")}
                  required
                />
              </label>
            )}
            <label>
              <span>{tr("Имя пользователя", "Username")}</span>
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                required
                autoFocus
              />
            </label>
            <label>
              <span>{tr("Пароль", "Password")}</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                placeholder={tr("Введите пароль", "Enter your password")}
                required
                minLength={mode === "bootstrap" ? 12 : 8}
              />
            </label>
            {mode === "bootstrap" && (
              <label>
                <span>{tr("Повторите пароль", "Confirm password")}</span>
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
              {busy
                ? tr("Входим…", "Authenticating…")
                : mode === "login"
                  ? tr("Войти", "Sign in")
                  : tr("Создать администратора", "Create administrator")}
              <Icon symbol="→" />
            </button>
          </form>
          <div className="auth-demo">
            <span>{tr("Посмотреть без подключения к API", "Preview without a live API")}</span>
            <button onClick={onDemo}>
              {tr("Открыть демо", "Open demo snapshot")} <Icon symbol="→" />
            </button>
          </div>
        </div>
        <p className="auth-security">
          <Icon symbol="◇" />
          {tr(
            "Токены доступа хранятся только в памяти. Сессия обновляется через защищённый HttpOnly cookie.",
            "Access tokens stay in memory. Refresh sessions use a secure HttpOnly cookie.",
          )}
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
          aria-label={
            collapsed
              ? tr("Развернуть навигацию", "Expand navigation")
              : tr("Свернуть навигацию", "Collapse navigation")
          }
        >
          <Icon symbol={collapsed ? "›" : "‹"} />
        </button>
      </div>
      <nav className="sidebar__nav" aria-label={tr("Основная навигация", "Primary navigation")}>
        <span className="sidebar__section-label">{tr("Мониторинг", "Operations")}</span>
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
        <span className="sidebar__section-label">{tr("Управление", "Manage")}</span>
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
            <b>
              {nodes.length
                ? currentUiLanguage() === "ru"
                  ? `${nodes.length} узл.`
                  : `${nodes.length} nodes`
                : tr("Нет подтверждённых узлов", "No verified nodes")}
            </b>
            <small>
              {nodes.length
                ? currentUiLanguage() === "ru"
                  ? `${healthyNodes} работают · ${impairedNodes} с проблемами · ${unknownNodes} без данных`
                  : `${healthyNodes} healthy · ${impairedNodes} impaired · ${unknownNodes} unknown`
                : tr("Ожидаем данные", "Waiting for live data")}
            </small>
          </span>
        </div>
        <div
          className="sidebar__profile"
          aria-label={tr("Текущая учётная запись", "Signed-in account")}
        >
          <span className="avatar">OP</span>
          <span>
            <b>{tr("Оператор", "Operator")}</b>
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
    <nav className="mobile-nav" aria-label={tr("Мобильная навигация", "Mobile navigation")}>
      {items.map((item) => (
        <button
          key={item.id}
          className={
            route === item.id || (route === "incident" && item.id === "incidents") ? "active" : ""
          }
          onClick={() => navigate(item.path)}
        >
          <Icon symbol={item.icon} />
          <span>{item.label}</span>
        </button>
      ))}
      <button onClick={onMore}>
        <Icon symbol="•••" />
        <span>{tr("Ещё", "More")}</span>
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
        aria-label={tr("Вся навигация", "All navigation")}
      >
        <div className="mobile-drawer__head">
          <Brand />
          <button
            className="icon-button"
            onClick={onClose}
            aria-label={tr("Закрыть меню", "Close menu")}
          >
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
          <LanguageSwitch className="drawer-language-switch" />
          <span className="avatar">OP</span>
          <span>
            <b>{tr("Оператор", "Operator")}</b>
            <small>{tr("Активная сессия", "Signed-in session")}</small>
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
      <span className="connection-banner__content">
        <b>
          {online
            ? mode === "demo"
              ? tr("Демонстрационный режим", "Demo snapshot")
              : tr("Часть данных недоступна", "Partial data")
            : tr("Нет подключения", "Offline mode")}
        </b>
        {error ?? tr("Данные API сейчас недоступны.", "Live API data is not available.")}
      </span>
      {online && <button onClick={onRetry}>{tr("Повторить", "Retry")}</button>}
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
      ? `${worstLag.toFixed(1)}${tr(" сек.", "s")}`
      : syncHealth === "unknown"
        ? tr("нет телеметрии", "telemetry unavailable")
        : healthLabel(syncHealth);
  return (
    <header className="app-header">
      <div className="app-header__mobile-brand">
        <button
          className="icon-button"
          onClick={onMenu}
          aria-label={tr("Открыть меню", "Open menu")}
        >
          <Icon symbol="≡" />
        </button>
        <Brand />
      </div>
      <div
        className="node-chip"
        title={tr("Последнее состояние кластера", "Latest cluster inventory")}
      >
        <StatusDot health={online ? (nodes.length ? clusterHealth : "paused") : "offline"} />
        <span>
          <small>{tr("Состав кластера", "Cluster inventory")}</small>
          <b>
            {nodes.length
              ? currentUiLanguage() === "ru"
                ? `${nodes.length} узл.`
                : `${nodes.length} known node(s)`
              : tr("Нет данных об узлах", "No node records")}
          </b>
        </span>
      </div>
      <div className="app-header__status">
        <span className="header-signal">
          <StatusDot health={syncHealth} />
          <span>
            {tr("Синхронизация", "Sync")} <b>{syncLabel}</b>
          </span>
        </span>
        <span className="header-signal">
          <StatusDot health={liveUpdates ? "healthy" : mode === "live" ? "degraded" : "paused"} />
          <span>
            {liveUpdates
              ? tr("В реальном времени", "Live")
              : mode === "live"
                ? tr("Опрос", "Polling")
                : mode === "cached"
                  ? tr("Из кэша", "Cached")
                  : tr("Демо", "Demo")}
          </span>
        </span>
        <LanguageSwitch className="header-language-switch" />
        <button
          className={`icon-button refresh-button ${refreshing ? "is-spinning" : ""}`}
          onClick={onRefresh}
          aria-label={tr("Обновить данные кластера", "Refresh cluster data")}
        >
          <Icon symbol="↻" />
        </button>
        <button className="button button--quiet notifications-button" onClick={onNotifications}>
          <Icon symbol="◉" />
          <span>{tr("Уведомления", "Notifications")}</span>
        </button>
        <button
          className="button button--quiet button--small"
          type="button"
          onClick={onLogout}
          disabled={logoutBusy}
          aria-label={tr("Выйти из Alert Hub", "Log out of Alert Hub")}
        >
          <Icon symbol="↪" />
          <span>{logoutBusy ? tr("Выходим…", "Logging out…") : tr("Выйти", "Log out")}</span>
        </button>
      </div>
    </header>
  );
}

export function AlertHubApp({ appName = "Alert Hub" }: { appName?: string }) {
  const [language, setLanguageState] = useState<UiLanguage>(currentUiLanguage);
  const setLanguage = useCallback((nextLanguage: UiLanguage) => {
    document.documentElement.lang = nextLanguage;
    try {
      window.localStorage.setItem(LANGUAGE_STORAGE_KEY, nextLanguage);
    } catch {
      // The in-memory React state still keeps language switching functional.
    }
    setLanguageState(nextLanguage);
  }, []);
  useEffect(() => {
    document.documentElement.lang = language;
    const pageTitle = `${appName} — ${language === "ru" ? "консоль мониторинга" : "distributed operations console"}`;
    document.title = pageTitle;
    document
      .querySelectorAll<HTMLMetaElement>('meta[property="og:title"], meta[name="twitter:title"]')
      .forEach((meta) => {
        meta.content = pageTitle;
      });
  }, [appName, language]);
  return (
    <LanguageContext.Provider value={{ language, setLanguage }}>
      <AppNameContext.Provider value={appName}>
        <AlertHubRuntime />
      </AppNameContext.Provider>
    </LanguageContext.Provider>
  );
}

function AlertHubRuntime() {
  const queryClient = useQueryClient();
  const { language } = useContext(LanguageContext);
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
    language,
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
        {tr("Перейти к содержимому", "Skip to content")}
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
              ? tr("офлайн · только чтение", "offline · read-only")
              : tr("демо-режим", "demo-preview")
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
      <span
        className="button button--quiet grafana-link grafana-link--missing"
        aria-label={tr("Grafana не настроена", "Grafana not configured")}
        aria-disabled="true"
      >
        <Icon symbol="∿" /> {tr("Grafana не настроена", "Grafana not configured")}
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
      <Icon symbol="∿" /> {tr("Открыть Grafana", "Open Grafana")}
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
        <strong>{tr("Не настроено", "Not configured")}</strong>
        <small>
          {tr(
            "Добавьте активный источник данных Prometheus.",
            "Add an enabled Prometheus datasource.",
          )}
        </small>
      </>
    );
  }
  if (result.status === "unavailable" || result.status === "unknown") {
    return (
      <>
        <strong>{tr("Недоступно", "Unavailable")}</strong>
        <small>
          {tr("Prometheus не вернул подтверждённых значений.", "No verified sample was returned.")}
        </small>
      </>
    );
  }
  const active = result.samples.filter((sample) => sample.value > 0).length;
  const failed = result.samples.filter((sample) => sample.value <= 0).length;
  return (
    <>
      <strong>
        {kind === "alerts" ? active : `${active}/${result.samples.length}`}
        <span>{kind === "alerts" ? tr(" активн.", " firing") : tr(" доступно", " up")}</span>
      </strong>
      <small>
        {kind === "alerts"
          ? active
            ? tr(
                "Prometheus сообщает об активных тревогах.",
                "Prometheus reports active firing alerts.",
              )
            : tr("Активных тревог не обнаружено.", "No firing alert samples returned.")
          : failed
            ? currentUiLanguage() === "ru"
              ? `${failed} целей недоступно.`
              : `${failed} target${failed === 1 ? "" : "s"} down.`
            : result.samples.length
              ? tr("Все полученные цели доступны.", "All returned targets are up.")
              : tr("Данные по целям не получены.", "No target samples returned.")}
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
          <span className="eyebrow">
            {tr("Запросы контролирует сервер", "Server-owned PromQL")}
          </span>
          <h2 id="prometheus-evidence-title">
            {tr("Состояние по данным Prometheus", "Prometheus operational evidence")}
          </h2>
        </span>
        <GrafanaLink url={data.summary.grafanaUrl} />
      </div>
      <div className="prometheus-evidence-grid">
        <Panel
          eyebrow="probe_success"
          title={tr("Доступность по регионам", "Regional reachability")}
        >
          <div className="metric-evidence-value">
            <strong>
              {reachabilityConfigured && data.reachability.length
                ? `${reachable}/${data.reachability.length}`
                : reachabilityConfigured
                  ? tr("Нет данных", "No samples")
                  : tr("Не настроено", "Not configured")}
              {reachabilityConfigured && data.reachability.length ? (
                <span>{tr(" доступны", " reachable")}</span>
              ) : null}
            </strong>
            <small>
              {data.reachabilityMeta.detail ||
                tr("Результаты проверок ещё не получены.", "No verified probe result returned.")}
            </small>
          </div>
        </Panel>
        <Panel
          eyebrow='ALERTS{alertstate="firing"}'
          title={tr("Активные тревоги", "Firing alerts")}
        >
          <div className="metric-evidence-value">
            <MetricEvidenceValue result={data.fixedMetrics.firingAlerts} kind="alerts" />
          </div>
        </Panel>
        <Panel
          eyebrow={tr("up · ключевые сервисы", "up · key jobs")}
          title="Prometheus / Alertmanager / Blackbox"
        >
          <div className="metric-evidence-value">
            <MetricEvidenceValue result={data.fixedMetrics.keyJobsUp} kind="jobs" />
          </div>
        </Panel>
        <Panel
          eyebrow={tr("up · сервисы Alert Hub", "up · Alert Hub jobs")}
          title={tr("Синхронизация и состояние Alert Hub", "Alert Hub sync / app health")}
        >
          <div className="metric-evidence-value">
            <MetricEvidenceValue result={data.fixedMetrics.alertHubHealth} kind="health" />
            <small>
              {reportedLags.length
                ? currentUiLanguage() === "ru"
                  ? `Максимальная задержка синхронизации: ${Math.max(...reportedLags).toFixed(1)} сек.`
                  : `Cluster projection max sync lag ${Math.max(...reportedLags).toFixed(1)}s.`
                : tr("Задержка синхронизации не передана.", "Cluster sync lag was not reported.")}
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
  const active = data.incidents.filter((incident) => incident.status !== "resolved");
  const critical = active.filter((incident) => incident.severity === "critical");
  const criticalWithoutOwner = critical.filter((incident) => incident.status === "open");
  const oldestCritical = [...criticalWithoutOwner].sort(
    (left, right) => Date.parse(left.startsAt) - Date.parse(right.startsAt),
  )[0];
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
        eyebrow={tr("Оперативная сводка", "Operational console")}
        title={tr("Состояние системы", "System overview")}
        description={
          currentUiLanguage() === "ru"
            ? `${data.sources.length} источн. · ${data.channels.filter((channel) => channel.enabled).length} активных каналов · ${data.nodes.length} узл. Данные собраны в одном месте, даже если часть сети недоступна.`
            : `${data.sources.length} sources · ${data.channels.filter((channel) => channel.enabled).length} active channels · ${data.nodes.length} nodes. A single operational view, even when part of the network is unavailable.`
        }
        actions={
          <>
            <button className="button button--quiet" onClick={onNotifications} disabled={readOnly}>
              <Icon symbol="◉" />
              {tr("Включить оповещения", "Enable alerts")}
            </button>
            <button className="button button--primary" onClick={() => navigate("/incidents")}>
              <Icon symbol="!" />
              {tr("Открыть инциденты", "Open incidents")}
            </button>
          </>
        }
      />

      <div className="kpi-grid">
        <KpiCard
          label={tr("Активны сейчас", "Firing now")}
          value={data.summary.open}
          note={
            criticalWithoutOwner.length
              ? currentUiLanguage() === "ru"
                ? `${criticalWithoutOwner.length} критических без реакции · старейший ${formatRelative(oldestCritical.startsAt)}`
                : `${criticalWithoutOwner.length} critical unacknowledged · oldest ${formatRelative(oldestCritical.startsAt)}`
              : critical.length
                ? currentUiLanguage() === "ru"
                  ? `${critical.length} критических уже в работе`
                  : `${critical.length} critical acknowledged`
                : tr("Критических тревог нет", "No critical alerts")
          }
          tone={critical.length ? "critical" : "success"}
          spark={readOnly ? [2, 2, 3, 2, 4, 3, data.summary.open] : []}
        />
        <KpiCard
          label={tr("Приняты в работу", "Acknowledged")}
          value={data.summary.acknowledged}
          note={tr("По журналу инцидентов", "From the incident log")}
          tone={data.summary.acknowledged ? "warning" : "neutral"}
          spark={readOnly ? [0, 1, 1, 2, 1, 1, data.summary.acknowledged] : []}
        />
        <KpiCard
          label={tr("Узлы кластера", "Cluster nodes")}
          value={data.nodes.length ? data.nodes.length : tr("Нет данных", "No data")}
          note={
            !data.nodes.length
              ? tr("Сведения об узлах не получены", "Node inventory was not returned")
              : unknownNodes
                ? currentUiLanguage() === "ru"
                  ? `${unknownNodes} без актуального статуса`
                  : `${unknownNodes} without a current status`
                : healthyNodes === data.nodes.length
                  ? reportedLags.length
                    ? currentUiLanguage() === "ru"
                      ? `Все работают · макс. задержка ${Math.max(...reportedLags).toFixed(1)} сек.`
                      : `All healthy · max lag ${Math.max(...reportedLags).toFixed(1)}s`
                    : tr("Все узлы работают", "All nodes healthy")
                  : currentUiLanguage() === "ru"
                    ? `${impairedNodes} требуют внимания`
                    : `${impairedNodes} need attention`
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
          label={tr("Доставка уведомлений", "Delivery rate")}
          value={
            data.summary.deliveryRate == null
              ? tr("Нет данных", "No data")
              : `${data.summary.deliveryRate.toFixed(1)}%`
          }
          note={
            data.summary.deliveries24h == null
              ? tr("Метрики доставки недоступны", "Delivery metrics unavailable")
              : data.summary.deliveries24h === 0
                ? tr("За 24 часа попыток не было", "No attempts in the last 24 hours")
                : currentUiLanguage() === "ru"
                  ? `${data.summary.deliveries24h} попыток · в очереди ${data.summary.outboxPending ?? tr("нет данных", "no data")}`
                  : `${data.summary.deliveries24h} attempts · ${data.summary.outboxPending ?? "no data"} queued`
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
          eyebrow={tr("Требуют внимания", "Needs attention")}
          title={tr("Активные инциденты", "Active incidents")}
          action={
            <button className="text-button" onClick={() => navigate("/incidents")}>
              {tr("Показать все", "View all")} <Icon symbol="→" />
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
              title={tr("Активных инцидентов нет", "No active incidents")}
              message={tr(
                "В последнем подтверждённом снимке нет активных записей.",
                "There are no active records in the latest verified snapshot.",
              )}
            />
          )}
        </Panel>

        <Panel
          className="overview-cluster"
          eyebrow={tr("Состояние узлов", "Peer health")}
          title={tr("Кластер", "Cluster nodes")}
          action={
            <button className="text-button" onClick={() => navigate("/cluster")}>
              {tr("Подробнее", "Details")} <Icon symbol="→" />
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
                  <small>{tr("Задержка синхронизации", "Sync lag")}</small>
                  <b className={node.syncLag != null && node.syncLag > 10 ? "text-warning" : ""}>
                    {node.syncLag == null
                      ? tr("Нет данных", "No data")
                      : currentUiLanguage() === "ru"
                        ? `${node.syncLag.toFixed(1)} сек.`
                        : `${node.syncLag.toFixed(1)}s`}
                  </b>
                </span>
                <span className="node-row__health">
                  <StatusDot health={node.health} />
                  {healthLabel(node.health)}
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
                  : tr("Нет данных", "No data")}
              </b>{" "}
              {tr("в очереди", "queued")}
            </span>
            <span>
              <Icon symbol="⌖" />
              <b>
                {reportedLags.length
                  ? currentUiLanguage() === "ru"
                    ? `${Math.max(...reportedLags).toFixed(1)} сек.`
                    : `${Math.max(...reportedLags).toFixed(1)}s`
                  : tr("Нет данных", "No data")}
              </b>{" "}
              {tr("макс. задержка", "max lag")}
            </span>
          </div>
        </Panel>
      </div>

      <div className="overview-grid overview-grid--lower">
        <Panel
          eyebrow="Prometheus · probe_success"
          title={tr("Доступность по регионам", "Regional reachability")}
          action={
            <button className="text-button" onClick={() => navigate("/reachability")}>
              {reachRate == null
                ? tr("Нет данных", "No data")
                : `${reachRate}% ${tr("доступно", "reachable")}`}{" "}
              <Icon symbol="→" />
            </button>
          }
        >
          <ReachabilityMatrix cells={data.reachability} compact />
          <div className="panel-footnote">
            <span>
              <i className="legend-dot legend-dot--healthy" />
              {tr("Доступно", "Reachable")}
            </span>
            <span>
              <i className="legend-dot legend-dot--failed" />
              {tr("Недоступно", "Failed")}
            </span>
            <span>
              {tr("Обновлено", "Updated")} {formatRelative(data.reachability[0]?.checkedAt ?? "")}
            </span>
          </div>
        </Panel>
        <Panel
          eyebrow={tr("За последние 24 часа", "Last 24 hours")}
          title={tr("Каналы доставки", "Delivery channels")}
          action={
            <button className="text-button" onClick={() => navigate("/channels")}>
              {tr("Управлять", "Manage")} <Icon symbol="→" />
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
                      {channel.delivered24h} {tr("доставлено", "delivered")} ·{" "}
                      {channel.successRate == null
                        ? tr("не проверено", "not exercised")
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
              <b>{tr("Получать оповещения на этом устройстве", "Receive alerts on this device")}</b>
              <small>
                {tr(
                  "Включите Web Push — доставка продолжится при переключении узлов.",
                  "Enable Web Push so delivery continues across node failover.",
                )}
              </small>
            </span>
            <Icon symbol="→" />
          </button>
        </Panel>
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
        eyebrow={tr("Единый журнал", "Unified journal")}
        title={tr("Инциденты", "Incidents")}
        description={tr(
          "Вся история тревог, действий операторов и доставки уведомлений с каждого узла.",
          "Alert history, operator actions, and delivery evidence from every node.",
        )}
      />
      <div
        className="incident-tabs"
        role="tablist"
        aria-label={tr("Статус инцидента", "Incident status")}
      >
        <button className={status === "active" ? "active" : ""} onClick={() => setStatus("active")}>
          {tr("Активные", "Active")} <span>{counts.active}</span>
        </button>
        <button
          className={status === "acknowledged" ? "active" : ""}
          onClick={() => setStatus("acknowledged")}
        >
          {tr("В работе", "Acknowledged")} <span>{counts.acknowledged}</span>
        </button>
        <button
          className={status === "resolved" ? "active" : ""}
          onClick={() => setStatus("resolved")}
        >
          {tr("Решённые", "Resolved")} <span>{counts.resolved}</span>
        </button>
        <button className={status === "all" ? "active" : ""} onClick={() => setStatus("all")}>
          {tr("Все", "All")} <span>{incidents.length}</span>
        </button>
      </div>
      <Panel className="incident-table-panel">
        <div className="filter-bar">
          <label className="search-field">
            <Icon symbol="⌕" />
            <span className="sr-only">{tr("Поиск инцидентов", "Search incidents")}</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={tr("Название, источник или метка…", "Title, source, or label…")}
            />
            {query && (
              <button
                onClick={() => setQuery("")}
                aria-label={tr("Очистить поиск", "Clear search")}
              >
                ×
              </button>
            )}
          </label>
          <label className="select-field">
            <span>{tr("Критичность", "Severity")}</span>
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value as "all" | Severity)}
            >
              <option value="all">{tr("Любая", "Any")}</option>
              <option value="critical">{tr("Критическая", "Critical")}</option>
              <option value="warning">{tr("Предупреждение", "Warning")}</option>
              <option value="info">{tr("Информация", "Info")}</option>
              <option value="unknown">{tr("Неизвестно", "Unknown")}</option>
            </select>
          </label>
          <span className="filter-result">
            {tr("Найдено", "Found")}: {filtered.length}
          </span>
        </div>
        {filtered.length ? (
          <div className="incidents-table-wrap">
            <table className="incidents-table">
              <thead>
                <tr>
                  <th>{tr("Инцидент", "Incident")}</th>
                  <th>{tr("Статус", "Status")}</th>
                  <th>{tr("Источник / регион", "Source / region")}</th>
                  <th>{tr("Цель", "Target")}</th>
                  <th>{tr("Последнее событие", "Last event")}</th>
                  <th>
                    <span className="sr-only">{tr("Открыть", "Open")}</span>
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
                      <button
                        className="row-open"
                        aria-label={`${tr("Открыть", "Open")} ${incident.title}`}
                      >
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
            title={tr("Ничего не найдено", "No incidents found")}
            message={tr(
              "Сбросьте фильтры или измените поисковый запрос.",
              "Clear the filters or adjust your search query.",
            )}
            action={
              <button
                className="button button--quiet"
                onClick={() => {
                  setQuery("");
                  setStatus("all");
                  setSeverity("all");
                }}
              >
                {tr("Сбросить фильтры", "Reset filters")}
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
        title={tr("Инцидент не найден", "Incident not found")}
        message={tr(
          "Возможно, его нет в текущем локальном снимке.",
          "It may not be present in the current local snapshot.",
        )}
        action={
          <button className="button button--quiet" onClick={() => navigate("/incidents")}>
            {tr("Вернуться к инцидентам", "Back to incidents")}
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось изменить инцидент.", "Unable to update the incident."),
      );
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось сохранить комментарий.", "Unable to save the comment."),
      );
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="page-stack incident-detail-page">
      <button className="breadcrumb-button" onClick={() => navigate("/incidents")}>
        <Icon symbol="←" />
        {tr("Инциденты", "Incidents")}
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
              {tr("Начался", "Started")} {formatRelative(incident.startsAt)}
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
              {busy === "acknowledge"
                ? tr("Сохраняем…", "Saving…")
                : tr("Принять в работу", "Acknowledge")}
            </button>
          )}
          {incident.status !== "resolved" && (
            <button
              className="button button--quiet"
              disabled={busy !== null || readOnly}
              onClick={() => void mutate("resolve")}
            >
              <Icon symbol="◎" />
              {tr("Решить", "Resolve")}
            </button>
          )}
          {incident.status !== "silenced" && incident.status !== "resolved" && (
            <button
              className="button button--quiet button--icon-only"
              disabled={busy !== null || readOnly}
              onClick={() => void mutate("silence")}
              aria-label={tr("Приглушить инцидент", "Silence incident")}
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
          eyebrow={tr("Неизменяемая история", "Immutable history")}
          title={tr("Хронология инцидента", "Incident timeline")}
          action={
            readOnly ? null : (
              <button
                className="button button--quiet button--small"
                onClick={() => setCommentOpen((value) => !value)}
              >
                <Icon symbol="+" />
                {tr("Добавить комментарий", "Add comment")}
              </button>
            )
          }
        >
          {commentOpen && (
            <form className="comment-composer" onSubmit={submitComment}>
              <label>
                <span className="sr-only">{tr("Комментарий к инциденту", "Incident comment")}</span>
                <textarea
                  value={comment}
                  onChange={(event) => setComment(event.target.value)}
                  autoFocus
                  placeholder={tr(
                    "Добавьте контекст для следующего оператора…",
                    "Add context for the next operator…",
                  )}
                />
              </label>
              <div>
                <button type="button" className="text-button" onClick={() => setCommentOpen(false)}>
                  {tr("Отмена", "Cancel")}
                </button>
                <button
                  className="button button--primary button--small"
                  disabled={!comment.trim() || busy === "comment"}
                >
                  {busy === "comment"
                    ? tr("Публикуем…", "Publishing…")
                    : tr("Опубликовать", "Publish")}
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
              title={tr("Хронология пуста", "Timeline is empty")}
              message={tr(
                "Узел не вернул события для выбранного инцидента.",
                "The node returned no events for this incident.",
              )}
            />
          )}
        </Panel>
        <div className="incident-detail-side">
          <Panel
            eyebrow={tr("Текущее состояние", "Current state")}
            title={tr("Контекст инцидента", "Incident context")}
          >
            <dl className="detail-list">
              <div>
                <dt>{tr("ID инцидента", "Incident ID")}</dt>
                <dd>
                  <code>{compactId(incident.id)}</code>
                </dd>
              </div>
              <div>
                <dt>{tr("Источник", "Source")}</dt>
                <dd>{incident.source}</dd>
              </div>
              <div>
                <dt>{tr("Первое событие", "First event")}</dt>
                <dd>{formatDate(incident.startsAt, true)}</dd>
              </div>
              <div>
                <dt>{tr("Последнее событие", "Last event")}</dt>
                <dd>{formatDate(incident.lastEventAt, true)}</dd>
              </div>
              <div>
                <dt>{tr("Событий в хронологии", "Timeline events")}</dt>
                <dd>{incident.events.length}</dd>
              </div>
            </dl>
          </Panel>
          <Panel
            eyebrow={tr("Исходные данные", "Raw metadata")}
            title={tr("Метки и аннотации", "Labels and annotations")}
          >
            <div className="metadata-block">
              <h3>
                {tr("Метки", "Labels")} <span>{Object.keys(incident.labels).length}</span>
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
                {tr("Аннотации", "Annotations")}{" "}
                <span>{Object.keys(incident.annotations).length}</span>
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
        title={tr("Данных проверок пока нет", "No probe data yet")}
        message={tr(
          "Подключите Prometheus, чтобы заполнить матрицу доступности.",
          "Connect Prometheus to populate the reachability matrix.",
        )}
      />
    );
  return (
    <div
      className={`reachability-matrix ${compact ? "reachability-matrix--compact" : ""}`}
      style={{ ["--target-count" as string]: targets.length }}
      role="region"
      aria-label={tr("Матрица доступности по регионам", "Regional reachability matrix")}
      tabIndex={0}
    >
      <div className="reachability-matrix__corner">{tr("Проверка из", "Probe from")}</div>
      {targets.map((target) => (
        <div className="reachability-matrix__target" key={target}>
          <b>{target}</b>
          {!compact && <small>{tr("цель", "target")}</small>}
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
                            ? tr("доступно", "reachable")
                            : `${cell.latency} ms`
                          : tr("недоступно", "failed")
                      }`
                    : tr("Нет данных", "No data")
                }
              >
                <span aria-hidden="true">
                  {status === "failed" ? "×" : status === "unknown" ? "·" : "✓"}
                </span>
                <b>
                  {cell?.success
                    ? cell.latency == null
                      ? tr("Доступно", "Reachable")
                      : `${cell.latency} ms`
                    : status === "failed"
                      ? tr("Недоступно", "Failed")
                      : tr("Нет данных", "No data")}
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось обновить источник данных.", "Unable to update the datasource."),
      );
    } finally {
      setBusy(null);
    }
  };
  const removeDatasource = async (datasource: PrometheusDatasource) => {
    if (
      !window.confirm(
        currentUiLanguage() === "ru"
          ? `Удалить источник данных Prometheus «${datasource.name}»?`
          : `Delete Prometheus datasource “${datasource.name}”?`,
      )
    )
      return;
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось удалить источник данных.", "Unable to delete the datasource."),
      );
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
        currentUiLanguage() === "ru"
          ? `${datasource.name}: проверка завершена · значений: ${Number(body.samples ?? 0)}`
          : `${datasource.name}: test completed · samples: ${Number(body.samples ?? 0)}`,
      );
    } catch (reason) {
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось проверить источник данных.", "Unable to test the datasource."),
      );
    } finally {
      setTesting(null);
    }
  };
  return (
    <div className="page-stack reachability-page">
      <PageHeading
        eyebrow={tr("Данные Prometheus", "Prometheus evidence")}
        title={tr("Доступность по регионам", "Regional reachability")}
        description={tr(
          "Сравнение одних и тех же целей из каждого региона проверки без копирования временных рядов в Alert Hub.",
          "Compare the same targets from every probe region without copying time series into Alert Hub.",
        )}
        actions={
          <>
            <GrafanaLink url={grafanaUrl} />
            <button className="button button--quiet" type="button" onClick={onRefresh}>
              <Icon symbol="↻" /> {tr("Обновить данные", "Refresh evidence")}
            </button>
            <button
              className="button button--primary"
              type="button"
              onClick={() => setAdding(true)}
              disabled={readOnly}
            >
              <Icon symbol="+" /> {tr("Добавить Prometheus", "Add Prometheus")}
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
            <small>{tr("Доступные маршруты", "Reachable paths")}</small>
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
            <small>{tr("Недоступные маршруты", "Failed paths")}</small>
            <b>{failed}</b>
          </span>
        </div>
        <div>
          <span className="reach-summary__icon">
            <Icon symbol="∿" />
          </span>
          <span>
            <small>{tr("Опрошено источников", "Datasources queried")}</small>
            <b>{meta.datasources == null ? tr("Нет данных", "No data") : meta.datasources}</b>
          </span>
        </div>
        <div>
          <span className="reach-summary__icon">
            <Icon symbol="◷" />
          </span>
          <span>
            <small>{tr("Статус запроса", "Query status")}</small>
            <b>
              {meta.status === "ok"
                ? tr("Готово", "Ready")
                : meta.status === "partial"
                  ? tr("Частично", "Partial")
                  : meta.status === "not_configured"
                    ? tr("Не настроено", "Not configured")
                    : tr("Недоступно", "Unavailable")}
            </b>
          </span>
        </div>
      </div>
      <Panel
        className="reach-matrix-panel"
        eyebrow="probe_success"
        title={tr("Регион проверки × цель", "Probe region × target")}
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
            {meta.detail || tr("Статус доступности не получен", "No reachability status returned")}
          </span>
        }
      >
        <ReachabilityMatrix cells={cells} />
        <div className="matrix-legend">
          <span>
            <i className="legend-dot legend-dot--healthy" />
            {tr("Доступно", "Reachable")}
          </span>
          <span>
            <i className="legend-dot legend-dot--slow" />
            {tr("Доступно, но медленнее 200 мс", "Reachable, slower than 200 ms")}
          </span>
          <span>
            <i className="legend-dot legend-dot--failed" />
            {tr("Проверка не прошла", "Probe failed")}
          </span>
          <span>
            <i className="legend-dot legend-dot--unknown" />
            {tr("Нет данных", "No data")}
          </span>
        </div>
      </Panel>
      <div className="reach-detail-grid">
        <Panel
          eyebrow={tr("Активные проблемы", "Active failures")}
          title={tr("Маршруты, требующие внимания", "Paths needing attention")}
        >
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
                      <small>
                        {tr("Проверка вернула 0", "Probe returned 0")} ·{" "}
                        {formatRelative(cell.checkedAt)}
                      </small>
                    </span>
                    {cell.datasourceName && <code>{cell.datasourceName}</code>}
                  </div>
                ))}
            </div>
          ) : (
            <EmptyState
              icon="✓"
              title={
                cells.length
                  ? tr("Недоступных маршрутов нет", "No failed paths")
                  : tr("Нет данных о доступности", "No reachability data")
              }
              message={
                cells.length
                  ? tr(
                      "В текущем ответе probe_success нет недоступных маршрутов.",
                      "The current probe_success response contains no failed paths.",
                    )
                  : meta.detail ||
                    tr(
                      "Настройте и проверьте источник данных Prometheus.",
                      "Configure and test a Prometheus datasource.",
                    )
              }
            />
          )}
        </Panel>
        <Panel
          eyebrow={tr("Фиксированный запрос сервера", "Server-owned query")}
          title={tr("Источники данных Prometheus", "Prometheus datasources")}
        >
          <p className="settings-intro">
            {tr("Браузер запрашивает только предопределённый", "The browser can request only the")}{" "}
            <code>probe_success</code>{" "}
            {tr(
              "и не может отправлять произвольный PromQL.",
              "query and cannot submit arbitrary PromQL.",
            )}
          </p>
          {datasources.length ? (
            <div className="live-resource-list">
              {datasources.map((datasource) => (
                <div key={datasource.id} className="live-resource-row">
                  <span className="datasource-logo">P</span>
                  <span>
                    <b>{datasource.name}</b>
                    <small>
                      {datasource.url} · {datasource.region ?? tr("Без региона", "No region")} ·{" "}
                      {datasource.authType}
                    </small>
                  </span>
                  <StatusDot health={datasource.enabled ? "unknown" : "paused"} />
                  <span className="live-resource-actions">
                    <button
                      className="button button--quiet button--small"
                      onClick={() => void testDatasource(datasource)}
                      disabled={readOnly || testing === datasource.id || !datasource.enabled}
                    >
                      {testing === datasource.id
                        ? tr("Проверяем…", "Testing…")
                        : tr("Проверить", "Test")}
                    </button>
                    <button
                      className="button button--quiet button--small"
                      onClick={() => void toggleDatasource(datasource)}
                      disabled={readOnly || busy === datasource.id}
                    >
                      {datasource.enabled ? tr("Отключить", "Disable") : tr("Включить", "Enable")}
                    </button>
                    <button
                      className="text-button text-button--danger"
                      onClick={() => void removeDatasource(datasource)}
                      disabled={readOnly || busy === datasource.id}
                    >
                      {tr("Удалить", "Delete")}
                    </button>
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon="P"
              title={tr("Prometheus не подключён", "No Prometheus datasource")}
              message={tr(
                "Добавьте HTTPS-источник, чтобы заполнить матрицу доступности.",
                "Add an HTTPS datasource to populate the reachability matrix.",
              )}
            />
          )}
        </Panel>
      </div>
      {meta.errors.length > 0 && (
        <Panel
          eyebrow={tr("Частичные результаты", "Partial result")}
          title={tr("Ошибки источников данных", "Datasource errors")}
        >
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
      ? tr("Готовый фрагмент receiver для Alertmanager", "Ready-to-use Alertmanager receiver")
      : credential.kind === "generic_json"
        ? tr("Готовый запрос JSON", "Ready-to-use JSON request")
        : tr("Готовый контрольный запрос", "Ready-to-use heartbeat request");
  return (
    <>
      <div className="one-time-warning">
        <Icon symbol="!" />
        <span>
          <b>{tr("Скопируйте токен сейчас.", "Copy the token now.")}</b>
          <small>
            {tr(
              "После закрытия окна его нельзя будет посмотреть снова.",
              "It cannot be viewed again after this dialog closes.",
            )}
          </small>
        </span>
      </div>
      <label className="secret-field">
        <span>{tr("Bearer-токен", "Bearer token")}</span>
        <div>
          <code>{tokenVisible ? credential.token : "•".repeat(32)}</code>
          <button
            onClick={() => setTokenVisible((value) => !value)}
            aria-label={
              tokenVisible ? tr("Скрыть токен", "Hide token") : tr("Показать токен", "Show token")
            }
          >
            <Icon symbol={tokenVisible ? "◉" : "⊘"} />
          </button>
          <CopyButton value={credential.token} />
        </div>
      </label>
      <label className="secret-field">
        <span>{tr("Полный URL вебхука", "Full webhook URL")}</span>
        <div>
          <code>{credential.webhookUrl}</code>
          <CopyButton value={credential.webhookUrl} />
        </div>
      </label>
      <div className="config-snippet">
        <div>
          <span>{exampleLabel}</span>
          <CopyButton value={credential.example} label={tr("Копировать пример", "Copy example")} />
        </div>
        <pre>{credential.example}</pre>
      </div>
      {credential.kind === "generic_json" && (
        <div className="config-snippet">
          <div>
            <span>
              {tr(
                "Схема JSON · обязательны dedup_key и status",
                "JSON schema · dedup_key and status are required",
              )}
            </span>
            <CopyButton
              value={GENERIC_JSON_SCHEMA_EXAMPLE}
              label={tr("Копировать схему", "Copy schema")}
            />
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
    <Modal onClose={onClose} size="large" label={tr("Новый токен источника", "New source token")}>
      <div className="modal-head">
        <div>
          <span className="eyebrow">{tr("Доступ источника", "Source access")}</span>
          <h2>{tr("Токен обновлён", "Token rotated")}</h2>
        </div>
        <button className="icon-button" onClick={onClose} aria-label={tr("Закрыть", "Close")}>
          <Icon symbol="×" />
        </button>
      </div>
      <div className="wizard-body wizard-success">
        <SourceCredentialDetails credential={credential} />
      </div>
      <div className="modal-foot">
        <button className="button button--primary" onClick={onClose}>
          {tr("Я сохранил новый токен", "I saved the new token")}
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
        currentUiLanguage() === "ru"
          ? `${source.name}: принято ${Number(body.accepted ?? 0)}, дубликатов ${Number(body.duplicates ?? 0)}`
          : `${source.name}: accepted ${Number(body.accepted ?? 0)}, duplicates ${Number(body.duplicates ?? 0)}`,
      );
    } catch (reason) {
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось проверить источник.", "Unable to test the source."),
      );
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось обновить источник.", "Unable to update the source."),
      );
    } finally {
      setBusy(null);
    }
  };
  const removeSource = async (source: Source) => {
    if (
      !window.confirm(
        currentUiLanguage() === "ru"
          ? `Удалить источник «${source.name}»? Его токен перестанет работать.`
          : `Delete source “${source.name}”? Its token will stop working.`,
      )
    )
      return;
    setBusy(source.id);
    setActionError(null);
    try {
      await mutationJson(`/sources/${encodeURIComponent(source.id)}`, { method: "DELETE" });
      setData((current) => ({
        ...current,
        sources: current.sources.filter((item) => item.id !== source.id),
      }));
    } catch (reason) {
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось удалить источник.", "Unable to delete the source."),
      );
    } finally {
      setBusy(null);
    }
  };
  const rotateSourceToken = async (source: Source) => {
    if (
      !window.confirm(
        currentUiLanguage() === "ru"
          ? `Обновить токен для «${source.name}»? Текущий токен сразу перестанет работать.`
          : `Rotate the token for “${source.name}”? The current token will stop working immediately.`,
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось обновить токен источника.", "Unable to rotate the source token."),
      );
    } finally {
      setBusy(null);
    }
  };
  const reportedEvents = sources.flatMap((source) => source.events24h ?? []);
  return (
    <div className="page-stack sources-page">
      <PageHeading
        eyebrow={tr("Приём событий", "Event ingestion")}
        title={tr("Источники", "Sources")}
        description={tr(
          "Alertmanager, контрольные сигналы и JSON-события принимаются ближайшим доступным узлом.",
          "Alertmanager, heartbeat, and JSON events are accepted by the nearest available node.",
        )}
        actions={
          <button className="button button--primary" onClick={onAdd} disabled={readOnly}>
            <Icon symbol="+" />
            {tr("Добавить источник", "Add source")}
          </button>
        }
      />
      <div className="section-summary-bar">
        <span>
          <StatusDot health={sources.length ? "unknown" : "paused"} />
          <b>{sources.filter((source) => source.enabled).length}</b> {tr("включено", "enabled")}
        </span>
        <span>
          <Icon symbol="⇣" />
          <b>
            {reportedEvents.length
              ? reportedEvents.reduce((sum, count) => sum + count, 0).toLocaleString()
              : tr("Нет данных", "No data")}
          </b>{" "}
          {tr("событий за 24 ч.", "events in 24h")}
        </span>
        <span>
          <Icon symbol="✓" />
          <b>{sources.filter((source) => source.health === "healthy").length}</b>{" "}
          {tr("работают", "healthy")} ·{" "}
          <b>
            {sources.filter((source) => ["degraded", "offline"].includes(source.health)).length}
          </b>{" "}
          {tr("требуют внимания", "need attention")}
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
                    {sourceKindLabel(source.kind)} · {source.region}
                  </small>
                </span>
              </div>
              <div className="source-card__status">
                <span>
                  <StatusDot health={source.health} />
                  {source.enabled ? healthLabel(source.health) : tr("Отключён", "Disabled")}
                </span>
                <span>
                  {tr("Последнее событие", "Last event")}{" "}
                  <b>
                    {source.lastEvent
                      ? formatRelative(source.lastEvent)
                      : tr("Нет данных", "No data")}
                  </b>
                </span>
              </div>
              <div className="source-card__metrics">
                <span>
                  <small>{tr("События · 24 ч.", "Events · 24h")}</small>
                  <b>
                    {source.events24h == null
                      ? tr("Нет данных", "No data")
                      : source.events24h.toLocaleString(
                          currentUiLanguage() === "ru" ? "ru-RU" : "en-US",
                        )}
                  </b>
                </span>
                <span>
                  <small>{tr("ID источника", "Source ID")}</small>
                  <code>{compactId(source.id)}</code>
                </span>
              </div>
              <div className="source-card__endpoint">
                <span>{tr("Полный URL вебхука", "Full webhook URL")}</span>
                <code>{sourceWebhookUrl(source)}</code>
                <CopyButton
                  value={sourceWebhookUrl(source)}
                  label={tr("Копировать URL", "Copy URL")}
                />
              </div>
              <div className="source-card__actions">
                <button
                  className="button button--quiet button--small"
                  disabled={readOnly || !source.enabled || testing === source.id}
                  onClick={() => void testSource(source)}
                >
                  <Icon symbol="▷" />
                  {testing === source.id ? tr("Проверяем…", "Testing…") : tr("Проверить", "Test")}
                </button>
                <button
                  className="text-button"
                  disabled={readOnly || busy === source.id}
                  onClick={() => void rotateSourceToken(source)}
                >
                  {tr("Обновить токен", "Rotate token")}
                </button>
                <button
                  className="text-button"
                  disabled={readOnly || busy === source.id}
                  onClick={() => void toggleSource(source)}
                >
                  {source.enabled ? tr("Отключить", "Disable") : tr("Включить", "Enable")}
                </button>
                <button
                  className="text-button text-button--danger"
                  disabled={readOnly || busy === source.id}
                  onClick={() => void removeSource(source)}
                >
                  {tr("Удалить", "Delete")}
                </button>
              </div>
            </Panel>
          ))}
        </div>
      ) : (
        <Panel>
          <EmptyState
            icon="→"
            title={tr("Источников пока нет", "No sources yet")}
            message={tr(
              "Добавьте Alertmanager, JSON-вебхук или монитор контрольного сигнала.",
              "Add an Alertmanager, JSON webhook, or heartbeat monitor.",
            )}
            action={
              <button className="button button--primary" onClick={onAdd} disabled={readOnly}>
                {tr("Добавить первый источник", "Add the first source")}
              </button>
            }
          />
        </Panel>
      )}
      <details className="reference-details">
        <summary>
          <span>
            <span className="eyebrow">{tr("Формат приёма", "Ingestion contract")}</span>
            <b>{tr("Схема JSON и пример запроса", "JSON schema and request example")}</b>
          </span>
          <span className="reference-details__action">
            {tr("Показать справочник", "Show reference")}
          </span>
        </summary>
        <div className="reference-details__body">
          <p className="panel-description">
            {tr(
              "Отправляйте один JSON-объект в запросе. Поля",
              "Send one JSON object per request. Fields",
            )}{" "}
            <code>dedup_key</code> {tr("и", "and")} <code>status</code>{" "}
            {tr("обязательны; status должен быть", "are required; status must be")}{" "}
            <code>firing</code> {tr("или", "or")} <code>resolved</code>.
          </p>
          <div className="config-snippet">
            <div>
              <span>{tr("Пример схемы версии 1", "Version 1 schema example")}</span>
              <CopyButton
                value={GENERIC_JSON_SCHEMA_EXAMPLE}
                label={tr("Копировать схему", "Copy schema")}
              />
            </div>
            <pre>{GENERIC_JSON_SCHEMA_EXAMPLE}</pre>
          </div>
        </div>
      </details>
      <div className="info-callout">
        <Icon symbol="i" />
        <span>
          <b>{tr("События сначала сохраняются локально.", "Events are stored locally first.")}</b>{" "}
          {tr(
            "Любой активный узел приёма может получить и сохранить их, а затем синхронизировать с соседями — кворум не требуется.",
            "Any active ingest node can accept and persist them, then synchronize with peers without requiring quorum.",
          )}
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
      const detail = String(
        body.detail ?? tr("Проверка провайдера завершена.", "Provider check completed."),
      );
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось проверить канал.", "Unable to test the channel."),
      );
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось обновить канал.", "Unable to update the channel."),
      );
    } finally {
      setBusy(null);
    }
  };
  const removeChannel = async (channel: Channel) => {
    if (
      !window.confirm(
        currentUiLanguage() === "ru"
          ? `Удалить канал уведомлений «${channel.name}»?`
          : `Delete notification channel “${channel.name}”?`,
      )
    )
      return;
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось удалить канал.", "Unable to delete the channel."),
      );
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
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось обновить маршрут.", "Unable to update the route."),
      );
    } finally {
      setBusy(null);
    }
  };
  const removeRoute = async (route: NotificationRoute) => {
    if (
      !window.confirm(
        currentUiLanguage() === "ru"
          ? `Удалить маршрут уведомлений «${route.name}»?`
          : `Delete notification route “${route.name}”?`,
      )
    )
      return;
    setBusy(route.id);
    setActionError(null);
    try {
      await mutationJson(`/routes/${encodeURIComponent(route.id)}`, { method: "DELETE" });
      setData((current) => ({
        ...current,
        routes: current.routes.filter((item) => item.id !== route.id),
      }));
    } catch (reason) {
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось удалить маршрут.", "Unable to delete the route."),
      );
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
        eyebrow={tr("Доставка уведомлений", "Notification delivery")}
        title={tr("Каналы уведомлений", "Notification channels")}
        description={tr(
          "Настройте доставку, повторные попытки и переключение между регионами для каждого типа оповещений.",
          "Configure delivery, retries, and regional failover for each alert type.",
        )}
        actions={
          <button
            className="button button--primary"
            onClick={() => setAddingChannel(true)}
            disabled={readOnly}
          >
            <Icon symbol="+" />
            {tr("Добавить канал", "Add channel")}
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
          <b>
            {deliveryRate == null
              ? tr("Попыток доставки не было", "No delivery attempts")
              : tr("Результаты доставки", "Delivery performance")}
          </b>
          <small>
            {currentUiLanguage() === "ru"
              ? `Успешно ${delivered} из ${attempts} попыток за последние 24 часа`
              : `${delivered} of ${attempts} attempts succeeded in the last 24 hours`}
          </small>
        </span>
        <span className="channel-health-banner__metrics">
          <b>{outboxPending == null ? tr("Нет данных", "No data") : outboxPending}</b>
          <small>{tr("в очереди", "queued")}</small>
        </span>
        <span className="channel-health-banner__metrics">
          <b>{channels.filter((channel) => channel.enabled).length}</b>
          <small>{tr("активных каналов", "active channels")}</small>
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
                <small>{channelKindLabel(channel.kind)}</small>
              </span>
              <span className={`health-label health-label--${channel.health}`}>
                <StatusDot health={channel.health} />
                {channel.enabled ? healthLabel(channel.health) : tr("Приостановлен", "Paused")}
              </span>
            </div>
            <dl className="channel-card__details">
              <div>
                <dt>{tr("Маршрут", "Route")}</dt>
                <dd>
                  {routes.filter((route) => route.channelIds.includes(channel.id)).length
                    ? routes
                        .filter((route) => route.channelIds.includes(channel.id))
                        .map((route) => route.name)
                        .join(", ")
                    : tr("Не используется", "Not routed")}
                </dd>
              </div>
              <div>
                <dt>{tr("Узлы доставки", "Eligible nodes")}</dt>
                <dd>{channel.eligible}</dd>
              </div>
            </dl>
            <div className="channel-card__performance">
              <span>
                <small>{tr("Доставлено · 24 ч.", "Delivered · 24h")}</small>
                <b>{channel.delivered24h}</b>
              </span>
              <span>
                <small>{tr("Успешность", "Success rate")}</small>
                <b>
                  {channel.successRate == null
                    ? tr("Не проверено", "Not exercised")
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
                {testing === channel.id ? tr("Отправляем…", "Sending…") : tr("Проверить", "Test")}
              </button>
              <button
                className="text-button"
                disabled={readOnly || busy === channel.id}
                onClick={() => void toggleChannel(channel)}
              >
                {channel.enabled ? tr("Отключить", "Disable") : tr("Включить", "Enable")}
              </button>
              <button
                className="text-button text-button--danger"
                disabled={readOnly || busy === channel.id}
                onClick={() => void removeChannel(channel)}
              >
                {tr("Удалить", "Delete")}
              </button>
            </div>
          </Panel>
        ))}
      </div>
      <Panel
        className="routing-panel"
        eyebrow={tr("Порядок обработки", "Evaluation order")}
        title={tr("Маршруты уведомлений", "Notification routes")}
        action={
          <button
            className="button button--quiet button--small"
            onClick={() => setAddingRoute(true)}
            disabled={readOnly || channels.length === 0}
          >
            <Icon symbol="+" />
            {tr("Добавить маршрут", "Add route")}
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
                    {tr("приоритет", "priority")} {route.priority} · {tr("источники", "sources")}{" "}
                    {route.sourceFilter.join(", ") || tr("любые", "any")} ·{" "}
                    {tr("критичность", "severity")}{" "}
                    {route.severityFilter.join(", ") || tr("любая", "any")}
                  </small>
                </span>
                <span className="route-destinations">
                  {route.channelIds.map((channelId) => {
                    const channel = channels.find((item) => item.id === channelId);
                    return channel ? <ChannelIcon key={channelId} kind={channel.kind} /> : null;
                  })}
                </span>
                <span className="route-continue">
                  {route.continueMatching ? tr("Продолжить", "Continue") : tr("Остановить", "Stop")}
                </span>
                <span className="live-resource-actions">
                  <button
                    className="text-button"
                    disabled={readOnly || busy === route.id}
                    onClick={() => void toggleRoute(route)}
                  >
                    {route.enabled ? tr("Отключить", "Disable") : tr("Включить", "Enable")}
                  </button>
                  <button
                    className="text-button text-button--danger"
                    disabled={readOnly || busy === route.id}
                    onClick={() => void removeRoute(route)}
                  >
                    {tr("Удалить", "Delete")}
                  </button>
                </span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon="⇢"
            title={tr("Маршрутов пока нет", "No routes yet")}
            message={tr(
              "Создайте маршрут, чтобы связать фильтры инцидентов с каналами.",
              "Create a route to connect incident filters to delivery channels.",
            )}
          />
        )}
      </Panel>
      <button className="onboarding-callout" onClick={onNotifications} disabled={readOnly}>
        <span className="onboarding-callout__icon">
          <Icon symbol="◉" />
        </span>
        <span>
          <b>{tr("Подключить Web Push в этом браузере", "Set up Web Push in this browser")}</b>
          <small>
            {tr(
              "Запрос разрешения появится только после этого действия.",
              "The permission prompt appears only after this action.",
            )}
          </small>
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
      setOutcome(
        currentUiLanguage() === "ru"
          ? `Сессия устройства «${device.name}» отозвана.`
          : `Session for “${device.name}” was revoked.`,
      );
    } catch (reason) {
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось отозвать сессию.", "Unable to revoke the session."),
      );
    } finally {
      setBusy(null);
    }
  };
  const revokeOthers = async () => {
    const targets = devices.filter((device) => !device.current);
    if (
      !targets.length ||
      !window.confirm(
        currentUiLanguage() === "ru"
          ? `Отозвать остальные сессии (${targets.length})?`
          : `Revoke the other sessions (${targets.length})?`,
      )
    )
      return;
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
      setOutcome(
        currentUiLanguage() === "ru"
          ? `Отозвано сессий: ${targets.length}.`
          : `Sessions revoked: ${targets.length}.`,
      );
    } catch (reason) {
      setActionError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось отозвать все остальные сессии.", "Unable to revoke all other sessions."),
      );
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="page-stack devices-page">
      <PageHeading
        eyebrow={tr("Безопасность аккаунта", "Account security")}
        title={tr("Устройства и сессии", "Devices & sessions")}
        description={tr(
          "Управляйте активными сессиями и подписками Web Push отдельно на каждом устройстве.",
          "Manage active sessions and Web Push subscriptions for each device.",
        )}
        actions={
          <button className="button button--primary" onClick={onNotifications} disabled={readOnly}>
            <Icon symbol="◉" />
            {tr("Включить уведомления", "Enable notifications")}
          </button>
        }
      />
      <Panel className="device-readiness">
        <div>
          <span className="eyebrow">{tr("Готовность Web Push", "Web Push readiness")}</span>
          <h2>
            {pushReady
              ? tr("Это устройство получает Web Push", "This device receives Web Push")
              : tr("Настройка Push не завершена", "Push setup is incomplete")}
          </h2>
          <p>
            {tr(
              "Разрешение, service worker и подписка в кластере проверяются отдельно.",
              "Permission, service worker, and the cluster subscription are checked separately.",
            )}
          </p>
        </div>
        <div className="readiness-checks">
          <span>
            <Icon symbol={secureContext ? "✓" : "×"} />
            {tr("Защищённое соединение", "Secure context")}:{" "}
            {secureContext ? tr("да", "yes") : tr("нет", "no")}
          </span>
          <span>
            <Icon symbol={serviceWorkerAvailable ? "✓" : "×"} />
            Service worker:{" "}
            {serviceWorkerAvailable
              ? tr("поддерживается", "supported")
              : tr("не поддерживается", "unsupported")}
          </span>
          <span>
            <Icon symbol={currentPush ? "✓" : "×"} />
            {tr("Подписка API", "API subscription")}:{" "}
            {currentPush
              ? tr("зарегистрирована", "registered")
              : tr("не зарегистрирована", "not registered")}{" "}
            · {tr("разрешение", "permission")}{" "}
            {permission === "granted"
              ? tr("выдано", "granted")
              : permission === "denied"
                ? tr("запрещено", "denied")
                : permission === "default"
                  ? tr("не запрошено", "not requested")
                  : tr("не поддерживается", "unsupported")}
          </span>
        </div>
      </Panel>
      <Panel
        className="device-sessions"
        eyebrow={`${tr("Активных устройств", "Active devices")}: ${devices.length}`}
        title={tr("Устройства с активной сессией", "Devices with an active session")}
        action={
          <button
            className="text-button text-button--danger"
            disabled={readOnly || busy !== null || !devices.some((device) => !device.current)}
            onClick={() => void revokeOthers()}
          >
            {busy === "others"
              ? tr("Отзываем…", "Revoking…")
              : tr("Завершить другие сессии", "Revoke other sessions")}
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
                    {device.current && <em>{tr("Текущее устройство", "Current device")}</em>}
                  </span>
                  <small>{device.platform}</small>
                </span>
                <span className="device-row__meta">
                  <small>{tr("Последняя активность", "Last active")}</small>
                  <b>{formatRelative(device.lastUsed)}</b>
                  <span>{device.location}</span>
                </span>
                <span className={`push-state ${device.push ? "push-state--on" : ""}`}>
                  <Icon symbol={device.push ? "◉" : "⊘"} />
                  {device.push
                    ? tr("Push включён", "Push enabled")
                    : tr("Push выключен", "Push off")}
                </span>
                {!device.current && (
                  <button
                    className="button button--quiet button--small"
                    disabled={readOnly || busy !== null}
                    onClick={() => void revoke(device)}
                  >
                    {busy === device.id ? tr("Завершаем…", "Revoking…") : tr("Завершить", "Revoke")}
                  </button>
                )}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon="▣"
            title={tr("Активных устройств нет", "No active devices")}
            message={tr(
              "Новые сессии появятся здесь после входа.",
              "New sessions appear here after sign-in.",
            )}
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
          <b>
            {tr(
              "Refresh-токены обновляются при использовании.",
              "Refresh tokens rotate when used.",
            )}
          </b>{" "}
          {tr(
            "После отзыва устройство выйдет из системы, как только событие дойдёт до узла подключения.",
            "After revocation, the device signs out as soon as the event reaches its connected node.",
          )}
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
  const healthyNodes = nodes.filter((node) => node.health === "healthy").length;
  const impairedNodes = nodes.filter((node) =>
    ["degraded", "offline"].includes(node.health),
  ).length;
  const reportedLags = nodes.flatMap((node) => node.syncLag ?? []);
  return (
    <div className="page-stack cluster-page">
      <PageHeading
        eyebrow={tr("Согласование данных", "Data convergence")}
        title={tr("Кластер", "Cluster")}
        description={tr(
          "Каждый узел работает автономно, а курсоры показывают, как синхронизируется общая история событий.",
          "Each node operates independently while cursors show how the shared event history converges.",
        )}
        actions={
          <button className="button button--quiet" onClick={onRefresh}>
            <Icon symbol="⇄" />
            {tr("Обновить данные", "Refresh data")}
          </button>
        }
      />
      <div className="section-summary-bar cluster-summary-bar">
        <span>
          <Icon symbol="⌘" />
          <b>{nodes.length}</b> {tr("узл. в составе", "nodes in inventory")}
        </span>
        <span>
          <StatusDot health={impairedNodes ? "degraded" : nodes.length ? "healthy" : "unknown"} />
          <b>{healthyNodes}</b> {tr("работают", "healthy")} · <b>{impairedNodes}</b>{" "}
          {tr("с проблемами", "impaired")}
        </span>
        <span>
          <Icon symbol="⇄" />
          {tr("макс. задержка", "max lag")}{" "}
          <b>
            {reportedLags.length
              ? currentUiLanguage() === "ru"
                ? `${Math.max(...reportedLags).toFixed(1)} сек.`
                : `${Math.max(...reportedLags).toFixed(1)}s`
              : tr("нет данных", "no data")}
          </b>
        </span>
        <span>
          <Icon symbol="⇡" /> {tr("в очереди", "queued")}{" "}
          <b>{outboxPending == null ? tr("нет данных", "no data") : outboxPending}</b>
        </span>
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
              aria-label={`${tr("Открыть сведения об узле", "Open details for node")} ${node.name}`}
            />
            <div className="node-card__head">
              <span className={`flag-tag flag-tag--${node.health}`}>{node.region}</span>
              <span>
                <b>{node.name}</b>
                <small>{node.city}</small>
              </span>
              <span className={`health-label health-label--${node.health}`}>
                <StatusDot health={node.health} />
                {healthLabel(node.health)}
              </span>
            </div>
            <div className="node-card__metrics">
              <span>
                <small>{tr("Задержка синхронизации", "Sync lag")}</small>
                <b className={node.syncLag != null && node.syncLag > 10 ? "text-warning" : ""}>
                  {node.syncLag == null
                    ? tr("Нет данных", "No data")
                    : currentUiLanguage() === "ru"
                      ? `${node.syncLag.toFixed(1)} сек.`
                      : `${node.syncLag.toFixed(1)}s`}
                </b>
              </span>
              <span>
                <small>{tr("Очередь отправки", "Outbox queue")}</small>
                <b>{node.queue == null ? tr("Нет данных", "No data") : node.queue}</b>
              </span>
              <span>
                <small>{tr("Последняя связь", "Last seen")}</small>
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
          eyebrow={tr("Локальный векторный курсор", "Local vector cursor")}
          title={
            current
              ? `${current.name} · ${tr("последние данные", "latest data")}`
              : tr("Синхронизация", "Replication")
          }
          action={
            <span className="live-stamp">
              <StatusDot health={current?.health ?? "unknown"} /> {tr("Данные API", "API data")}
            </span>
          }
        >
          <div className="cursor-table">
            <div className="cursor-table__head">
              <span>{tr("Источник", "Origin")}</span>
              <span>{tr("Локальный курсор", "Local cursor")}</span>
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
                title={tr("Нет данных курсора", "No cursor data")}
                message={tr(
                  "Текущий узел не вернул сведения о векторном курсоре.",
                  "The current node returned no vector cursor data.",
                )}
              />
            )}
          </div>
        </Panel>
        <Panel
          eyebrow={tr("Состояние узлов", "Node runtime")}
          title={tr("Рабочие показатели", "Operational signals")}
        >
          <div className="runtime-signals">
            <span>
              <small>{tr("События кластера", "Cluster events")}</small>
              <b>
                {meta.eventCount == null
                  ? tr("Нет данных", "No data")
                  : meta.eventCount.toLocaleString(
                      currentUiLanguage() === "ru" ? "ru-RU" : "en-US",
                    )}
              </b>
            </span>
            <span>
              <small>{tr("Источники курсора", "Cursor origins")}</small>
              <b>{cursorEntries.length}</b>
            </span>
            <span>
              <small>{tr("Очередь отправки", "Outbox queue")}</small>
              <b>{outboxPending == null ? tr("Нет данных", "No data") : outboxPending}</b>
            </span>
            <span>
              <small>{tr("Известные узлы", "Known nodes")}</small>
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
            {tr("Открыть метрики приложения", "Open application metrics")}
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
            (scope === "system" ? isSystemActor(item.actor) : !isSystemActor(item.actor))) &&
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
        eyebrow={tr("Неизменяемая история", "Immutable history")}
        title={tr("Журнал действий", "Audit log")}
        description={tr(
          "Входы, изменения конфигурации и действия с инцидентами, записанные обслуживающим API-узлом.",
          "Sign-ins, configuration changes, and incident actions recorded by the serving API node.",
        )}
        actions={
          <button className="button button--quiet" onClick={exportLoaded} disabled={!items.length}>
            <Icon symbol="⇩" />
            {tr("Скачать загруженный JSONL", "Download loaded JSONL")}
          </button>
        }
      />
      <div className={`audit-current-health audit-current-health--${clusterHealth}`}>
        <StatusDot health={clusterHealth} />
        <span>
          <b>{tr("Текущее состояние кластера", "Current cluster health")}</b>
          <small>
            {nodes.length
              ? currentUiLanguage() === "ru"
                ? `${healthyNodes}/${nodes.length} узлов работают. Ошибки ниже — исторические события, а не активные тревоги.`
                : `${healthyNodes}/${nodes.length} nodes are healthy. Errors below are historical events, not active alerts.`
              : tr(
                  "Актуальная телеметрия кластера недоступна.",
                  "Current cluster telemetry is unavailable.",
                )}
          </small>
        </span>
      </div>
      <Panel className="audit-panel">
        <div className="filter-bar">
          <label className="search-field">
            <Icon symbol="⌕" />
            <span className="sr-only">{tr("Поиск в журнале действий", "Search audit log")}</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={tr("Оператор, действие или узел…", "Operator, action, or node…")}
            />
          </label>
          <div className="segmented">
            <button className={scope === "all" ? "active" : ""} onClick={() => setScope("all")}>
              {tr("Все", "All")}
            </button>
            <button
              className={scope === "operator" ? "active" : ""}
              onClick={() => setScope("operator")}
            >
              {tr("Оператор", "Operator")}
            </button>
            <button
              className={scope === "system" ? "active" : ""}
              onClick={() => setScope("system")}
            >
              {tr("Система", "System")}
            </button>
          </div>
          <label className="compact-select">
            <span className="sr-only">{tr("Период журнала", "Audit range")}</span>
            <select value={range} onChange={(event) => setRange(event.target.value)}>
              <option value="7d">{tr("Последние 7 дней", "Last 7 days")}</option>
              <option value="30d">{tr("Последние 30 дней", "Last 30 days")}</option>
              <option value="all">{tr("Вся загруженная история", "All loaded history")}</option>
            </select>
          </label>
        </div>
        <div className="audit-date-row">
          <span>
            {filtered[0]
              ? `${formatDay(filtered[0].at)} · ${tr("событий", "events")}: ${filtered.length}`
              : tr("Журнал действий", "Audit log")}
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
                      ? tr("Отклонённая попытка входа в кластер", "Rejected cluster sign-in")
                      : item.action}
                  </b>
                  <p>{item.detail}</p>
                  <small>
                    <span className="avatar avatar--tiny">
                      {isSystemActor(item.actor) ? "AH" : "OP"}
                    </span>
                    {item.actor} <i /> <code>{item.node}</code>
                  </small>
                </span>
                <time>{formatDate(item.at)}</time>
                {item.count > 1 ? (
                  <span
                    className="audit-item__count"
                    title={
                      currentUiLanguage() === "ru"
                        ? `${item.count} одинаковых событий с ${formatDate(item.oldestAt)} по ${formatDate(item.at)}`
                        : `${item.count} identical events from ${formatDate(item.oldestAt)} through ${formatDate(item.at)}`
                    }
                    aria-label={
                      currentUiLanguage() === "ru"
                        ? `${item.count} одинаковых событий в этой группе`
                        : `${item.count} identical events in this group`
                    }
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
            title={tr("Записи не найдены", "No entries found")}
            message={tr(
              "Измените фильтр или поисковый запрос.",
              "Adjust the filter or search query.",
            )}
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
                ? tr("Загружаем старые события…", "Loading older events…")
                : `${tr("Загрузить старые события", "Load older events")} (${items.length}/${knownTotal})`}
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
            <b>{tr("Хранение журнала", "Audit retention")}</b>
            <small>
              {tr(
                "Записи на узле только добавляются. Группировка повторов меняет лишь отображение; экспорт сохраняет все поля API. Секреты и заголовки авторизации не записываются.",
                "Node records are append-only. Grouping repeated events changes only the display; export preserves every API field. Secrets and authorization headers are not recorded.",
              )}
            </small>
          </span>
          <span>
            <StatusDot health="unknown" />
            {tr("Загружено", "Loaded")} {items.length}/{knownTotal}
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
        eyebrow={tr("Локальная и общая конфигурация", "Local and shared configuration")}
        title={tr("Настройки", "Settings")}
        description={tr(
          "Параметры устройства хранятся локально, а изменения кластера записываются в журнал и реплицируются.",
          "Device preferences stay local while cluster changes are audited and replicated.",
        )}
      />
      <div className="settings-grid settings-grid--single">
        <div className="settings-content">
          <Panel
            eyebrow={tr("Внешний вид", "Appearance")}
            title={tr("Параметры интерфейса", "Interface preferences")}
          >
            <div className="setting-row">
              <span>
                <b>{tr("Тема", "Theme")}</b>
                <small>
                  {appName}{" "}
                  {tr(
                    "использует тёмную контрастную палитру.",
                    "uses a high-contrast dark palette.",
                  )}
                </small>
              </span>
              <span className="theme-picker">
                <button className="active" disabled>
                  <i />
                  {tr("Тёмная", "Dark")}
                </button>
                <button disabled>
                  <i />
                  {tr("Системная", "System")}
                </button>
              </span>
            </div>
          </Panel>
          <Panel
            eyebrow={tr("Отказоустойчивый клиент", "Failover-aware client")}
            title={tr("Сохранённые адреса API", "Saved API endpoints")}
          >
            <p className="settings-intro">
              {tr(
                "Если текущий узел недоступен, PWA может прочитать данные через другой доверенный адрес кластера.",
                "If the current node is unavailable, the PWA can read through another trusted cluster endpoint.",
              )}
            </p>
            <div className="endpoint-list">
              {availableEndpoints.map((item, index) => (
                <div key={item}>
                  <span className="endpoint-order">{index + 1}</span>
                  <span>
                    <b>{item}</b>
                    <small>
                      {tr(
                        "Подтверждено авторизованным ответом кластера",
                        "Verified by an authenticated cluster response",
                      )}
                    </small>
                  </span>
                  <StatusDot health={enabledEndpoints.includes(item) ? "unknown" : "paused"} />
                  <button
                    className="button button--quiet button--small"
                    onClick={() => toggleEndpoint(item)}
                    disabled={readOnly}
                    aria-label={`${enabledEndpoints.includes(item) ? tr("Отключить", "Disable") : tr("Включить", "Enable")} ${tr("переключение на", "failover to")} ${item}`}
                  >
                    {enabledEndpoints.includes(item)
                      ? tr("Отключить", "Disable")
                      : tr("Включить", "Enable")}
                  </button>
                </div>
              ))}
              {!availableEndpoints.length && (
                <EmptyState
                  icon="⇄"
                  title={tr("Нет сохранённых адресов узлов", "No saved node endpoints")}
                  message={tr(
                    "Здесь появятся публичные HTTPS-адреса API, подтверждённые данными кластера.",
                    "Public HTTPS API endpoints verified by cluster data appear here.",
                  )}
                />
              )}
            </div>
            <div className="setting-row setting-row--border">
              <span>
                <b>{tr("Автоматическое переключение чтения", "Automatic read failover")}</b>
                <small>
                  {tr(
                    "Использовать активные авторизованные адреса кластера, если текущий API-узел недоступен.",
                    "Use active authenticated cluster endpoints when the current API node is unavailable.",
                  )}
                </small>
              </span>
              <Toggle
                checked={autoFailover}
                onChange={(checked) => {
                  setAutoFailover(checked);
                  localStorage.setItem("alert-hub-auto-failover", String(checked));
                }}
                label={tr("Автоматическое переключение чтения", "Automatic read failover")}
                disabled={readOnly}
              />
            </div>
          </Panel>
          <Panel
            eyebrow={tr("Идентификация кластера", "Cluster identity")}
            title={tr("Параметры приложения", "Application settings")}
          >
            <div className="form-grid">
              <label>
                <span>{tr("Название", "Name")}</span>
                <input value={appName} readOnly aria-readonly="true" />
              </label>
            </div>
            <div className="settings-actions">
              <span>
                <Icon symbol="i" />
                {tr(
                  "Название задаётся серверной переменной APP_NAME и доступно здесь только для чтения.",
                  "The name comes from the APP_NAME server variable and is read-only here.",
                )}
              </span>
            </div>
          </Panel>
          <Panel
            className="danger-panel"
            eyebrow={tr("Обслуживание", "Maintenance")}
            title={tr("Локальные данные приложения", "Local application data")}
          >
            <div className="setting-row">
              <span>
                <b>{tr("Очистить сохранённый снимок", "Clear saved snapshot")}</b>
                <small>
                  {tr(
                    "Удаляет с устройства локальную копию данных. Данные кластера не изменятся.",
                    "Removes the local data copy from this device. Cluster data is unchanged.",
                  )}
                </small>
              </span>
              <button
                className="button button--danger"
                disabled={readOnly}
                onClick={() => {
                  pruneReadCaches(null);
                  setCacheMessage(
                    tr(
                      "Локальный кэш данных очищен на этом устройстве.",
                      "The local data cache was cleared on this device.",
                    ),
                  );
                }}
              >
                {tr("Очистить кэш", "Clear cache")}
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

function CopyButton({
  value,
  label = tr("Копировать", "Copy"),
}: {
  value: string;
  label?: string;
}) {
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
      {copied ? tr("Скопировано", "Copied") : label}
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
                  labels: parseKeyValueLines(
                    heartbeatLabels,
                    tr("Метки контрольного сигнала", "Heartbeat labels"),
                  ),
                }
              : {},
        }),
      });
      const body = asRecord(payload);
      setCreated(sourceCredential(body, kind));
      onCreated(normalizeSource(body, 0));
      setStep(3);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось создать источник.", "Source could not be created."),
      );
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
        currentUiLanguage() === "ru"
          ? `Принято событий: ${Number(body.accepted ?? 0)}; инцидент: ${String(body.incident_id ?? "возвращён API")}.`
          : `Accepted ${Number(body.accepted ?? 0)} event; incident ${String(body.incident_id ?? "returned by API")}.`,
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось проверить источник.", "Source test failed."),
      );
    }
  };
  return (
    <Modal onClose={onClose} size="large" label={tr("Добавить источник", "Add source")}>
      <div className="modal-head">
        <div>
          <span className="eyebrow">{tr("Подключение источника", "Source onboarding")}</span>
          <h2>
            {step === 3
              ? tr("Источник создан", "Source created")
              : tr("Добавить источник событий", "Add event source")}
          </h2>
        </div>
        <button className="icon-button" onClick={onClose} aria-label={tr("Закрыть", "Close")}>
          <Icon symbol="×" />
        </button>
      </div>
      <div className="wizard-progress">
        <span className={step >= 1 ? "active" : ""}>
          <i>{step > 1 ? "✓" : "1"}</i>
          {tr("Тип", "Type")}
        </span>
        <b />
        <span className={step >= 2 ? "active" : ""}>
          <i>{step > 2 ? "✓" : "2"}</i>
          {tr("Настройка", "Configure")}
        </span>
        <b />
        <span className={step >= 3 ? "active" : ""}>
          <i>3</i>
          {tr("Подключение", "Connect")}
        </span>
      </div>
      {step === 1 && (
        <div className="wizard-body">
          <p className="wizard-intro">
            {tr(
              "Выберите способ приёма событий. Маршрутизацию можно изменить позже без обновления токена источника.",
              "Choose how events will enter this cluster. You can change routing later without rotating the source token.",
            )}
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
                  {tr(
                    "Официальный сгруппированный вебхук. Каждая тревога обрабатывается отдельно.",
                    "Official grouped webhook payload. Each alert is normalized independently.",
                  )}
                </small>
                <em>{tr("Рекомендуется", "Recommended")}</em>
              </span>
              <i />
            </button>
            <button
              className={kind === "generic_json" ? "active" : ""}
              onClick={() => setKind("generic_json")}
            >
              <SourceKindIcon kind="generic_json" />
              <span>
                <b>{tr("JSON-вебхук", "Generic JSON")}</b>
                <small>
                  {currentUiLanguage() === "ru"
                    ? `Отправляйте события по стабильной схеме ${appName}.`
                    : `Send events using the stable ${appName} schema.`}
                </small>
              </span>
              <i />
            </button>
            <button
              className={kind === "heartbeat" ? "active" : ""}
              onClick={() => setKind("heartbeat")}
            >
              <SourceKindIcon kind="heartbeat" />
              <span>
                <b>{tr("Контрольный сигнал", "Heartbeat")}</b>
                <small>
                  {tr(
                    "Создаёт тревогу, если ожидаемый сигнал не пришёл вовремя.",
                    "Fire when a scheduled signal misses its grace window.",
                  )}
                </small>
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
              <span>{tr("Название источника", "Source name")}</span>
              <input
                required
                autoFocus
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder={
                  kind === "heartbeat"
                    ? tr("Контроль биллинга", "Billing heartbeat")
                    : "Prometheus EU"
                }
              />
            </label>
            <label>
              <span>{tr("Ближайший регион", "Nearest region")}</span>
              <input
                value={region}
                onChange={(event) => setRegion(event.target.value)}
                placeholder={tr("Метка региона (необязательно)", "Region label (optional)")}
              />
            </label>
          </div>
          {kind !== "heartbeat" && (
            <label className="full-field">
              <span>
                {tr("Разрешённый IP / CIDR", "Allowed source IP / CIDR")}{" "}
                <em>{tr("Необязательно", "Optional")}</em>
              </span>
              <input
                value={cidr}
                onChange={(event) => setCidr(event.target.value)}
                placeholder="10.14.0.0/16"
              />
              <small>
                {tr(
                  "Bearer-токен всё равно обязателен. Рекомендуются приватные CIDR.",
                  "Requests still require the bearer token. Private CIDRs are recommended.",
                )}
              </small>
            </label>
          )}
          {kind === "heartbeat" && (
            <>
              <div className="form-grid">
                <label>
                  <span>{tr("Ожидаемый интервал", "Expected interval")}</span>
                  <div className="input-suffix">
                    <input
                      type="number"
                      min="10"
                      value={interval}
                      onChange={(event) => setIntervalValue(event.target.value)}
                    />
                    <span>{tr("секунд", "seconds")}</span>
                  </div>
                </label>
                <label>
                  <span>{tr("Допустимая задержка", "Grace period")}</span>
                  <div className="input-suffix">
                    <input
                      type="number"
                      min="0"
                      value={grace}
                      onChange={(event) => setGrace(event.target.value)}
                    />
                    <span>{tr("секунд", "seconds")}</span>
                  </div>
                </label>
                <label>
                  <span>{tr("Критичность пропуска", "Missed heartbeat severity")}</span>
                  <select
                    value={heartbeatSeverity}
                    onChange={(event) => setHeartbeatSeverity(event.target.value as Severity)}
                  >
                    <option value="critical">{tr("Критическая", "Critical")}</option>
                    <option value="warning">{tr("Предупреждение", "Warning")}</option>
                    <option value="info">{tr("Информация", "Info")}</option>
                    <option value="unknown">{tr("Неизвестно", "Unknown")}</option>
                  </select>
                </label>
              </div>
              <label className="full-field">
                <span>
                  {tr(
                    "Метки сигнала · одна пара key=value в строке",
                    "Heartbeat labels · one key=value per line",
                  )}
                </span>
                <textarea
                  value={heartbeatLabels}
                  onChange={(event) => setHeartbeatLabels(event.target.value)}
                  placeholder={"service=billing\nenvironment=production"}
                  rows={3}
                />
                <small>
                  {tr(
                    "Эти метки добавляются к инциденту о пропущенном сигнале.",
                    "These labels are attached to the missed-heartbeat incident.",
                  )}
                </small>
              </label>
            </>
          )}
          <div className="token-safety-note">
            <Icon symbol="◇" />
            <span>
              <b>
                {tr("Bearer-токен хранится в виде хэша.", "The bearer token is stored as a hash.")}
              </b>{" "}
              {tr(
                "После создания он показывается один раз. Если токен потерян, его придётся обновить.",
                "It will be shown exactly once after creation. Losing it requires rotation.",
              )}
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
              <b>1</b>
              {tr("Скопировать данные доступа", "Copy the credential")}
            </span>
            <i />
            <span>
              <b>2</b>
              {tr("Применить и проверить конфигурацию", "Apply and validate config")}
            </span>
            <i />
            <span>
              <b>3</b>
              {tr("Отправить тестовое событие", "Send a test event")}
            </span>
          </div>
        </div>
      )}
      <div className="modal-foot">
        {step === 1 && (
          <>
            <button className="text-button" onClick={onClose}>
              {tr("Отмена", "Cancel")}
            </button>
            <button className="button button--primary" onClick={() => setStep(2)}>
              {tr("Продолжить", "Continue")} <Icon symbol="→" />
            </button>
          </>
        )}
        {step === 2 && (
          <>
            <button className="text-button" onClick={() => setStep(1)}>
              <Icon symbol="←" />
              {tr("Назад", "Back")}
            </button>
            <button
              className="button button--primary"
              type="submit"
              form="source-config-form"
              disabled={!name.trim() || saving}
            >
              {saving ? tr("Создаём…", "Creating…") : tr("Создать источник", "Create source")}
            </button>
          </>
        )}
        {step === 3 && created && (
          <>
            <button className="button button--quiet" onClick={() => void testCreatedSource()}>
              <Icon symbol="▷" />
              {tr("Отправить тестовое событие", "Send test event")}
            </button>
            <button className="button button--primary" onClick={onClose}>
              {tr("Я сохранил токен", "I saved the token")}
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
    if (separator <= 0)
      throw new Error(
        currentUiLanguage() === "ru"
          ? `${label}: строка ${index + 1} должна иметь вид key=value.`
          : `${label} line ${index + 1} must use key=value.`,
      );
    const key = line.slice(0, separator).trim();
    const item = line.slice(separator + 1).trim();
    if (!key || !item)
      throw new Error(
        currentUiLanguage() === "ru"
          ? `${label}: строка ${index + 1} не может быть пустой.`
          : `${label} line ${index + 1} cannot be blank.`,
      );
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
      throw new Error(
        currentUiLanguage() === "ru"
          ? `Строка заголовка вебхука ${index + 1} должна иметь вид Header-Name: value.`
          : `Webhook header line ${index + 1} must use Header-Name: value.`,
      );
    const name = line.slice(0, separator).trim();
    const item = line.slice(separator + 1).trim();
    if (!name || !item)
      throw new Error(
        currentUiLanguage() === "ru"
          ? `Строка заголовка вебхука ${index + 1} не может быть пустой.`
          : `Webhook header line ${index + 1} cannot be blank.`,
      );
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
      setError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось создать канал.", "Channel could not be created."),
      );
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal
      onClose={onClose}
      size="large"
      label={tr("Добавить канал уведомлений", "Add notification channel")}
    >
      <div className="modal-head">
        <div>
          <span className="eyebrow">{tr("Провайдер доставки", "Live delivery provider")}</span>
          <h2>{tr("Добавить канал уведомлений", "Add notification channel")}</h2>
        </div>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label={tr("Закрыть окно канала", "Close channel dialog")}
        >
          <Icon symbol="×" />
        </button>
      </div>
      <form id="channel-create-form" className="wizard-body source-config-form" onSubmit={submit}>
        <div className="form-grid">
          <label>
            <span>{tr("Название канала", "Channel name")}</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              autoFocus
            />
          </label>
          <label>
            <span>{tr("Тип провайдера", "Provider type")}</span>
            <select
              value={kind}
              onChange={(event) => setKind(event.target.value as Channel["kind"])}
            >
              <option value="web_push">Web Push</option>
              <option value="telegram">Telegram</option>
              <option value="smtp">SMTP</option>
              <option value="generic_webhook">{tr("Вебхук", "Generic webhook")}</option>
            </select>
          </label>
        </div>
        {kind === "telegram" && (
          <div className="form-grid">
            <label>
              <span>{tr("Токен бота · только для записи", "Bot token · write-only field")}</span>
              <input
                type="password"
                autoComplete="new-password"
                value={botToken}
                onChange={(event) => setBotToken(event.target.value)}
                required
              />
            </label>
            <label>
              <span>{tr("ID чата", "Chat ID")}</span>
              <input value={chatId} onChange={(event) => setChatId(event.target.value)} required />
            </label>
          </div>
        )}
        {kind === "smtp" && (
          <>
            <div className="form-grid">
              <label>
                <span>{tr("Сервер SMTP", "SMTP host")}</span>
                <input
                  value={smtpHost}
                  onChange={(event) => setSmtpHost(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>{tr("Порт", "Port")}</span>
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
                <span>{tr("Режим TLS", "TLS mode")}</span>
                <select value={smtpTls} onChange={(event) => setSmtpTls(event.target.value)}>
                  <option value="starttls">STARTTLS</option>
                  <option value="implicit">{tr("Неявный TLS", "Implicit TLS")}</option>
                </select>
              </label>
              <label>
                <span>{tr("Адрес отправителя", "From address")}</span>
                <input
                  type="email"
                  value={smtpFrom}
                  onChange={(event) => setSmtpFrom(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>{tr("Получатели · через запятую", "Recipients · comma separated")}</span>
                <input
                  value={smtpTo}
                  onChange={(event) => setSmtpTo(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>{tr("Имя пользователя · необязательно", "Username · optional")}</span>
                <input
                  autoComplete="username"
                  value={smtpUsername}
                  onChange={(event) => setSmtpUsername(event.target.value)}
                />
              </label>
              <label>
                <span>{tr("Пароль · только для записи", "Password · write-only field")}</span>
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
                <span>{tr("HTTPS URL вебхука", "HTTPS webhook URL")}</span>
                <input
                  type="url"
                  value={webhookUrl}
                  onChange={(event) => setWebhookUrl(event.target.value)}
                  required
                />
              </label>
              <label>
                <span>
                  {tr(
                    "Секрет HMAC · необязательно, только для записи",
                    "HMAC secret · optional, write-only field",
                  )}
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={hmacSecret}
                  onChange={(event) => setHmacSecret(event.target.value)}
                />
              </label>
              <label>
                <span>{tr("Заголовок подписи HMAC", "HMAC signature header")}</span>
                <input
                  value={signatureHeader}
                  onChange={(event) => setSignatureHeader(event.target.value)}
                  disabled={!hmacSecret}
                  required={Boolean(hmacSecret)}
                />
              </label>
            </div>
            <label className="full-field">
              <span>
                {tr(
                  "Свои заголовки · один Header-Name: value в строке",
                  "Custom headers · one Header-Name: value per line",
                )}
              </span>
              <textarea
                value={webhookHeaders}
                onChange={(event) => setWebhookHeaders(event.target.value)}
                placeholder={"Authorization: Bearer secret\nX-Tenant-ID: operations"}
                rows={3}
                autoComplete="off"
              />
              <small>
                {tr(
                  "Значения шифруются как данные доступа провайдера и не возвращаются через API.",
                  "Header values are encrypted as provider credentials and never returned by the API.",
                )}
              </small>
            </label>
          </>
        )}
        {kind === "web_push" && (
          <div className="token-safety-note">
            <Icon symbol="i" />
            <span>
              {tr(
                "Web Push использует серверную конфигурацию VAPID и подписки браузеров.",
                "Web Push uses server VAPID configuration and registered browser subscriptions.",
              )}
            </span>
          </div>
        )}
        <div className="form-grid">
          <label>
            <span>{tr("Допустимые регионы · необязательно", "Eligible regions · optional")}</span>
            <input
              value={regions}
              onChange={(event) => setRegions(event.target.value)}
              placeholder="region-a, region-b"
            />
          </label>
          <label>
            <span>{tr("ID допустимых узлов · необязательно", "Eligible node IDs · optional")}</span>
            <input
              value={nodeIds}
              onChange={(event) => setNodeIds(event.target.value)}
              placeholder="node-id-1, node-id-2"
            />
          </label>
        </div>
        <div className="token-safety-note">
          <Icon symbol="◇" />
          <span>
            {tr(
              "Секреты провайдера шифруются и больше не возвращаются после этого запроса.",
              "Provider secrets are encrypted at rest and never returned after this request.",
            )}
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
          {tr("Отмена", "Cancel")}
        </button>
        <button
          className="button button--primary"
          type="submit"
          form="channel-create-form"
          disabled={saving || !name.trim()}
        >
          {saving ? tr("Создаём…", "Creating…") : tr("Создать канал", "Create channel")}
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
      setError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось создать маршрут.", "Route could not be created."),
      );
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
    <Modal
      onClose={onClose}
      size="large"
      label={tr("Добавить маршрут уведомлений", "Add notification route")}
    >
      <div className="modal-head">
        <div>
          <span className="eyebrow">{tr("Порядок обработки", "Ordered evaluation")}</span>
          <h2>{tr("Добавить маршрут уведомлений", "Add notification route")}</h2>
        </div>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label={tr("Закрыть окно маршрута", "Close route dialog")}
        >
          <Icon symbol="×" />
        </button>
      </div>
      <form id="route-create-form" className="wizard-body source-config-form" onSubmit={submit}>
        <div className="form-grid">
          <label>
            <span>{tr("Название маршрута", "Route name")}</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              autoFocus
            />
          </label>
          <label>
            <span>
              {tr("Приоритет · меньшее число раньше", "Priority · lower evaluates first")}
            </span>
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
          <span>
            {tr(
              "ID источников · необязательно, через запятую",
              "Source IDs · optional, comma separated",
            )}
          </span>
          <input
            value={sources}
            onChange={(event) => setSources(event.target.value)}
            placeholder={tr(
              "Пустое поле соответствует любому источнику",
              "Empty matches any source",
            )}
          />
        </label>
        <fieldset className="choice-fieldset">
          <legend>
            {tr("Критичность · пустой выбор соответствует любой", "Severities · empty matches any")}
          </legend>
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
              {severityLabel(severity as Severity)}
            </label>
          ))}
        </fieldset>
        <fieldset className="matcher-builder">
          <legend>
            {tr(
              "Условия по меткам · должны выполниться все",
              "Label matchers · all configured matchers must pass",
            )}
          </legend>
          {labelMatchers.map((matcher, index) => (
            <div className="matcher-builder__row" key={index}>
              <label>
                <span>{tr("Название метки", "Label name")}</span>
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
                <span>{tr("Оператор", "Operator")}</span>
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
                  <option value="equals">{tr("Равно", "Equals")}</option>
                  <option value="not_equals">{tr("Не равно", "Does not equal")}</option>
                  <option value="regex">{tr("Полное совпадение regex", "Regex full match")}</option>
                  <option value="not_regex">
                    {tr("Не совпадает с regex", "Does not regex-match")}
                  </option>
                  <option value="exists">{tr("Существует", "Exists")}</option>
                  <option value="not_exists">{tr("Не существует", "Does not exist")}</option>
                </select>
              </label>
              <label>
                <span>{tr("Значение", "Value")}</span>
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
                aria-label={
                  currentUiLanguage() === "ru"
                    ? `Удалить условие по метке ${index + 1}`
                    : `Remove label matcher ${index + 1}`
                }
              >
                {tr("Удалить", "Remove")}
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
            <Icon symbol="+" /> {tr("Добавить условие", "Add label matcher")}
          </button>
        </fieldset>
        <fieldset className="choice-fieldset">
          <legend>{tr("Каналы назначения", "Destination channels")}</legend>
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
              {channel.name} · {channelKindLabel(channel.kind)}
            </label>
          ))}
        </fieldset>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={continueMatching}
            onChange={(event) => setContinueMatching(event.target.checked)}
          />{" "}
          {tr(
            "После совпадения проверять следующие маршруты",
            "Continue evaluating later routes after a match",
          )}
        </label>
        {error && (
          <div className="permission-message permission-message--warning" role="alert">
            <Icon symbol="!" /> {error}
          </div>
        )}
      </form>
      <div className="modal-foot">
        <button className="text-button" onClick={onClose}>
          {tr("Отмена", "Cancel")}
        </button>
        <button
          className="button button--primary"
          type="submit"
          form="route-create-form"
          disabled={saving || !name.trim() || channelIds.length === 0 || invalidMatcher}
        >
          {saving ? tr("Создаём…", "Creating…") : tr("Создать маршрут", "Create route")}
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
      setError(
        reason instanceof Error
          ? reason.message
          : tr("Не удалось добавить источник данных.", "Datasource could not be created."),
      );
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal
      onClose={onClose}
      size="large"
      label={tr("Добавить источник данных Prometheus", "Add Prometheus datasource")}
    >
      <div className="modal-head">
        <div>
          <span className="eyebrow">
            {tr("Интеграция с фиксированными запросами", "Fixed-query integration")}
          </span>
          <h2>{tr("Добавить Prometheus", "Add Prometheus datasource")}</h2>
        </div>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label={tr("Закрыть окно источника данных", "Close datasource dialog")}
        >
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
            <span>{tr("Название источника", "Datasource name")}</span>
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
            <span>{tr("ID обслуживающего узла · необязательно", "Owning node ID · optional")}</span>
            <input value={nodeId} onChange={(event) => setNodeId(event.target.value)} />
          </label>
          <label>
            <span>{tr("Регион · необязательно", "Region · optional")}</span>
            <input value={region} onChange={(event) => setRegion(event.target.value)} />
          </label>
          <label>
            <span>{tr("Аутентификация", "Authentication")}</span>
            <select
              value={authType}
              onChange={(event) => setAuthType(event.target.value as "none" | "bearer" | "basic")}
            >
              <option value="none">{tr("Без аутентификации", "None")}</option>
              <option value="bearer">{tr("Bearer-токен", "Bearer token")}</option>
              <option value="basic">{tr("Логин и пароль", "Basic auth")}</option>
            </select>
          </label>
        </div>
        {authType === "bearer" && (
          <label className="full-field">
            <span>{tr("Bearer-токен · только для записи", "Bearer token · write-only field")}</span>
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
              <span>
                {tr("Имя пользователя · только для записи", "Username · write-only field")}
              </span>
              <input
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
              />
            </label>
            <label>
              <span>{tr("Пароль · только для записи", "Password · write-only field")}</span>
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
            {tr(
              "Данные доступа шифруются. В ответах видны только тип аутентификации и названия настроенных полей.",
              "Credentials are encrypted and responses expose only the authentication type and configured field names.",
            )}
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
          {tr("Отмена", "Cancel")}
        </button>
        <button
          className="button button--primary"
          type="submit"
          form="datasource-create-form"
          disabled={saving || !name.trim() || !url.trim()}
        >
          {saving ? tr("Создаём…", "Creating…") : tr("Добавить источник", "Create datasource")}
        </button>
      </div>
    </Modal>
  );
}

type PushSetupMessage = { tone: "success" | "warning"; text: string };

function localizedBlockedPermissionHelp(
  environment: ReturnType<typeof currentPushClientEnvironment>,
) {
  let english: string;
  if (environment.ios) {
    english =
      "Notifications are blocked for this Home Screen app. Open iOS/iPadOS Settings → Notifications, select this installed app, allow notifications, then reopen it.";
  } else if (environment.browser === "safari") {
    english =
      "Notifications are blocked. Open Safari → Settings → Websites → Notifications, set this site to Allow, then reload.";
  } else if (environment.browser === "firefox") {
    english =
      "Notifications are blocked. Open the site permissions beside the address bar, reset Notifications, then reload and allow the prompt.";
  } else {
    english =
      "Notifications are blocked. Open this site's permissions beside the address bar, set Notifications to Allow, then reload.";
  }
  return tr(blockedPermissionHelp(environment), english);
}

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
      ? { tone: "warning", text: localizedBlockedPermissionHelp(environment) }
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
        text: tr(
          "Этот браузер не поддерживает Notifications, Service Worker и Push API, необходимые для Web Push.",
          "This browser does not expose the Notifications, Service Worker, and Push APIs required for Web Push.",
        ),
      });
      return;
    }
    if (!window.isSecureContext) {
      setMessage({
        tone: "warning",
        text: tr(
          "Для Web Push требуется защищённое HTTPS-соединение. Откройте Alert Hub по HTTPS-адресу.",
          "Web Push requires a secure HTTPS context. Reopen Alert Hub through its HTTPS address.",
        ),
      });
      return;
    }
    if (environment.ios && !environment.standalone) {
      setMessage({
        tone: "warning",
        text: tr(
          "На iPhone и iPad установите Alert Hub через «Поделиться» → «На экран Домой», откройте приложение, войдите и включите уведомления там.",
          "On iPhone and iPad, install Alert Hub with Share → Add to Home Screen, open that installed app, sign in, and enable notifications there.",
        ),
      });
      return;
    }
    if (Notification.permission === "denied") {
      setPermission("denied");
      setMessage({ tone: "warning", text: localizedBlockedPermissionHelp(environment) });
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
              ? localizedBlockedPermissionHelp(environment)
              : tr(
                  "Разрешение на уведомления не выдано. Повторите, когда будете готовы подтвердить запрос браузера.",
                  "Notification permission was not granted. Try again when you are ready to accept the browser prompt.",
                ),
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
        tr(
          "Регистрация service worker заняла слишком много времени. Перезагрузите страницу и повторите.",
          "Service worker registration timed out. Reload the page and try again.",
        ),
      );
      assertActive();
      const keyResponse = await pushApiRequest(
        "/push/vapid-public-key",
        {},
        tr(
          "API не успел вернуть ключ Web Push.",
          "The API did not return its Web Push key in time.",
        ),
        controller.signal,
        operationGeneration,
        operationSessionId,
      );
      assertActive();
      if (!keyResponse.ok) {
        const detail = await apiError(
          keyResponse,
          currentUiLanguage() === "ru"
            ? `Этот узел API не может выдать ключ Web Push (${keyResponse.status}).`
            : `This API node cannot publish a Web Push key (${keyResponse.status}).`,
        );
        assertActive();
        throw new Error(detail);
      }
      const keyBody = asRecord(await keyResponse.json().catch(() => ({})));
      assertActive();
      const vapidKey = String(keyBody.public_key ?? keyBody.vapid_public_key ?? "");
      const applicationServerKey = decodeApplicationServerKey(vapidKey, currentUiLanguage());
      let subscription = await withPushTimeout(
        registration.pushManager.getSubscription(),
        10_000,
        tr(
          "Браузер не успел вернуть текущую Push-подписку.",
          "The browser did not return its current Push subscription in time.",
        ),
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
          tr(
            "Браузер не успел заменить устаревшую Push-подписку.",
            "The browser could not replace its outdated Push subscription in time.",
          ),
        );
        assertActive();
        if (!removed)
          throw new Error(
            tr(
              "Браузер отказался заменить устаревший Push-ключ.",
              "The browser refused to replace its outdated Push key.",
            ),
          );
        subscription = null;
      }
      if (!subscription) {
        createdSubscription = await withPushTimeout(
          registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey,
          }),
          15_000,
          tr(
            "Push-сервис браузера не успел создать подписку.",
            "The browser Push service did not create a subscription in time.",
          ),
        );
        subscription = createdSubscription;
        assertActive();
      }
      const body = subscription.toJSON();
      if (!body.endpoint || !body.keys?.p256dh || !body.keys.auth) {
        throw new Error(
          tr(
            "Браузер вернул неполную Push-подписку.",
            "The browser returned an incomplete Push subscription.",
          ),
        );
      }
      assertActive();
      registrationStarted = true;
      const response = await pushApiRequest(
        "/push/subscriptions",
        {
          method: "POST",
          body: JSON.stringify({
            ...body,
            device_name: currentPushDeviceName(currentUiLanguage()),
            user_agent: navigator.userAgent,
          }),
        },
        tr(
          "API не успел сохранить Push-подписку.",
          "The API did not save this Push subscription in time.",
        ),
        controller.signal,
        operationGeneration,
        operationSessionId,
      );
      assertActive();
      if (!response.ok) {
        const detail = await apiError(
          response,
          currentUiLanguage() === "ru"
            ? `API отклонил Push-подписку (${response.status}).`
            : `The API rejected this Push subscription (${response.status}).`,
        );
        assertActive();
        throw new Error(detail);
      }
      subscriptionSaved = true;
      assertActive();
      setMessage({
        tone: "success",
        text: tr(
          "Устройство подписано. Откройте «Каналы» → «Проверить», чтобы убедиться в доставке.",
          "This device is subscribed. Use Channels → Send test to verify visible delivery.",
        ),
      });
      assertActive();
      onSubscribed();
    } catch (reason) {
      if (reason instanceof PushSetupCancelledError || !mounted.current) {
        if (createdSubscription && !registrationStarted && !subscriptionSaved) {
          await withPushTimeout(
            createdSubscription.unsubscribe(),
            2_000,
            tr(
              "Очистка Push-подписки заняла слишком много времени.",
              "Push subscription cleanup timed out.",
            ),
          ).catch(() => undefined);
        }
        if (
          mounted.current &&
          (authGeneration !== operationGeneration || memorySessionId !== operationSessionId)
        ) {
          setMessage({
            tone: "warning",
            text: tr(
              "Во время настройки уведомлений изменилась активная сессия. Перезагрузите страницу и повторите.",
              "Your authenticated session changed while notifications were being configured. Reload the page and try again.",
            ),
          });
        }
        return;
      }
      const detail =
        reason instanceof DOMException && reason.name === "NotAllowedError"
          ? localizedBlockedPermissionHelp(environment)
          : reason instanceof Error && reason.message
            ? reason.message
            : tr(
                "Браузер или API не смог завершить настройку Push-подписки.",
                "The browser or API could not complete the Push subscription.",
              );
      setMessage({ tone: "warning", text: detail });
    } finally {
      if (activeOperation.current === controller) activeOperation.current = null;
      if (mounted.current) setBusy(false);
    }
  };
  return (
    <Modal onClose={requestClose} label={tr("Включить уведомления", "Enable notifications")}>
      <div className="modal-head">
        <div>
          <span className="eyebrow">{tr("Настройка Web Push", "Web Push onboarding")}</span>
          <h2>{tr("Получайте важные оповещения вовремя", "Never miss a cluster alert")}</h2>
        </div>
        <button
          className="icon-button"
          onClick={requestClose}
          aria-label={tr("Закрыть", "Close")}
          disabled={busy}
        >
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
            <small>
              {appName.toUpperCase()} · {tr("СЕЙЧАС", "NOW")}
            </small>
            <b>{tr("Высокая задержка основного API", "Core API latency breach")}</b>
            <p>{tr("Критический · NL → api-core", "Critical · NL → api-core")}</p>
          </span>
        </div>
      </div>
      <div className="notification-body">
        <p>
          {environment.ios
            ? environment.standalone
              ? tr(
                  "Установленное приложение может запросить доступ к Web Push после действия ниже.",
                  "This installed Home Screen app can request Web Push after the action below.",
                )
              : tr(
                  "На iPhone и iPad Web Push работает только в приложении, установленном на экран «Домой».",
                  "On iPhone and iPad, Web Push works only from the installed Home Screen app.",
                )
            : tr(
                "Разрешение будет запрошено только после действия ниже. Затем Alert Hub зарегистрирует браузер в кластере.",
                "Permission is requested only after the action below. Alert Hub then registers this browser with the cluster.",
              )}
        </p>
        <ol className="onboarding-steps">
          {environment.ios && !environment.standalone ? (
            <>
              <li>
                <span>1</span>
                <p>
                  <b>{tr("Откройте в Safari", "Open in Safari")}</b>
                  <small>
                    {tr(
                      "Используйте меню «Поделиться» на этой странице.",
                      "Use the Share menu for this site.",
                    )}
                  </small>
                </p>
              </li>
              <li>
                <span>2</span>
                <p>
                  <b>{tr("Добавьте на экран «Домой»", "Add to Home Screen")}</b>
                  <small>
                    {currentUiLanguage() === "ru"
                      ? `Запустите ${appName} с нового значка и войдите.`
                      : `Launch ${appName} from its new icon and sign in.`}
                  </small>
                </p>
              </li>
              <li>
                <span>3</span>
                <p>
                  <b>{tr("Включите уведомления", "Enable notifications")}</b>
                  <small>
                    {tr(
                      "Подтвердите системный запрос в установленном приложении.",
                      "Approve the system prompt from the installed app.",
                    )}
                  </small>
                </p>
              </li>
            </>
          ) : (
            <>
              <li>
                <span>1</span>
                <p>
                  <b>{tr("Разрешите уведомления", "Allow notifications")}</b>
                  <small>
                    {tr(
                      "Подтвердите запрос браузера или системы.",
                      "Approve the browser or system prompt.",
                    )}
                  </small>
                </p>
              </li>
              <li>
                <span>2</span>
                <p>
                  <b>{tr("Зарегистрируйте устройство", "Register this device")}</b>
                  <small>
                    {tr(
                      "Подписка шифруется и сохраняется в кластере.",
                      "The subscription is encrypted and stored by the cluster.",
                    )}
                  </small>
                </p>
              </li>
              <li>
                <span>3</span>
                <p>
                  <b>{tr("Отправьте проверку", "Send a test")}</b>
                  <small>
                    {tr(
                      "Убедитесь, что канал Web Push доставляет уведомления.",
                      "Verify delivery from the Web Push channel.",
                    )}
                  </small>
                </p>
              </li>
            </>
          )}
        </ol>
        {permission === "unsupported" && (
          <div className="permission-message permission-message--warning">
            <Icon symbol="!" />
            {tr(
              "Этот браузер не поддерживает Notifications и Service Worker.",
              "This browser does not expose Notifications and Service Worker support.",
            )}
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
          {tr("Позже", "Maybe later")}
        </button>
        <button
          className="button button--primary"
          disabled={busy || permission === "unsupported"}
          onClick={() => void enable()}
        >
          <Icon symbol="◉" />
          {busy
            ? tr("Подключаем…", "Connecting…")
            : message?.tone === "success" || permission === "granted"
              ? tr("Проверить подписку", "Verify subscription")
              : permission === "denied"
                ? tr("Как вернуть разрешение", "Show recovery steps")
                : tr("Включить уведомления", "Enable notifications")}
        </button>
      </div>
    </Modal>
  );
}
