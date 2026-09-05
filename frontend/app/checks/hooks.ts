import { useCallback, useEffect, useRef, useState } from "react";

import {
  buildChecksQuery,
  type CheckDetail,
  type CheckFilters,
  type CheckListItem,
  type ChecksDataState,
  type ChecksMeta,
  type CheckSummary,
  normalizeCheckDetail,
  normalizeChecksList,
  normalizeChecksSummary,
} from "./model";

export type ChecksRequestResult = {
  status: number;
  payload: unknown;
};

export type ChecksRequest = (path: string, signal: AbortSignal) => Promise<ChecksRequestResult>;
export type ChecksRuntimeMode = "active" | "disabled" | "unavailable";

export type ChecksOverviewState = {
  phase: "loading" | ChecksDataState;
  enabled: boolean | null;
  meta: ChecksMeta | null;
  summary: CheckSummary | null;
  problems: CheckListItem[];
  error: string | null;
  refreshing: boolean;
};

export type ChecksListState = {
  phase: "loading" | ChecksDataState;
  meta: ChecksMeta | null;
  items: CheckListItem[];
  summary: CheckSummary | null;
  total: number;
  limit: number;
  offset: number;
  error: string | null;
  refreshing: boolean;
};

export type CheckDetailState = {
  phase: "loading" | ChecksDataState | "not_found";
  meta: ChecksMeta | null;
  check: CheckDetail | null;
  error: string | null;
  refreshing: boolean;
};

function localState(mode: ChecksRuntimeMode): ChecksDataState | null {
  if (mode === "disabled") return "disabled";
  if (mode === "unavailable") return "unavailable";
  return null;
}

export function checksEnabledForRuntime(
  mode: ChecksRuntimeMode,
  knownEnabled: boolean | null,
): boolean | null {
  if (mode === "disabled") return false;
  if (mode === "unavailable") return knownEnabled === false ? false : true;
  return knownEnabled;
}

function responseError(status: number, fallback: string): string {
  return status >= 500 ? "prometheus_unavailable" : fallback;
}

function mergeChecksMeta(primary: ChecksMeta, secondary: ChecksMeta): ChecksMeta {
  return {
    ...primary,
    code: primary.code ?? secondary.code,
    warningCodes: [...new Set([...primary.warningCodes, ...secondary.warningCodes])],
  };
}

export function useChecksOverview(
  request: ChecksRequest,
  mode: ChecksRuntimeMode,
): [ChecksOverviewState, () => void] {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<ChecksOverviewState>(() => {
    const phase = localState(mode) ?? "loading";
    return {
      phase,
      enabled: checksEnabledForRuntime(mode, null),
      meta: null,
      summary: null,
      problems: [],
      error: phase === "unavailable" ? "network_unavailable" : null,
      refreshing: false,
    };
  });
  const requestEpoch = useRef(0);
  const refresh = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    const local = localState(mode);
    if (local) {
      requestEpoch.current += 1;
      return undefined;
    }

    const epoch = ++requestEpoch.current;
    const controller = new AbortController();
    queueMicrotask(() => {
      if (controller.signal.aborted || epoch !== requestEpoch.current) return;
      setState((current) => ({
        ...current,
        phase: "loading",
        enabled: current.meta?.enabled ?? null,
        summary: null,
        problems: [],
        error: null,
        refreshing: current.meta !== null,
      }));
    });
    void request("/checks/summary", controller.signal)
      .then((summaryResponse) => {
        if (controller.signal.aborted || epoch !== requestEpoch.current) return;
        const summary = normalizeChecksSummary(summaryResponse.payload);
        if (!summary.meta.enabled) {
          setState({
            phase: "disabled",
            enabled: false,
            meta: summary.meta,
            summary: null,
            problems: [],
            error: null,
            refreshing: false,
          });
          return;
        }
        if (
          summaryResponse.status >= 500 ||
          summary.meta.dataState === "unavailable" ||
          !summary.summary
        ) {
          setState({
            phase: "unavailable",
            enabled: true,
            meta: summary.meta,
            summary: null,
            problems: [],
            error: summary.meta.code ?? responseError(summaryResponse.status, "checks_unavailable"),
            refreshing: false,
          });
          return;
        }
        const phase: ChecksDataState =
          summary.meta.dataState === "stale"
            ? "stale"
            : summary.summary.total === 0
              ? "empty"
              : "ready";
        setState({
          phase,
          enabled: true,
          meta: summary.meta,
          summary: summary.summary,
          problems: summary.problemChecks,
          error: summary.meta.code,
          refreshing: false,
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || epoch !== requestEpoch.current) return;
        setState((current) => ({
          phase: "unavailable",
          enabled: current.enabled === false ? false : true,
          meta: null,
          summary: null,
          problems: [],
          error:
            error instanceof Error && error.name !== "AbortError"
              ? error.message
              : "checks_unavailable",
          refreshing: false,
        }));
      });
    return () => controller.abort();
  }, [mode, request, revision]);

  if (mode !== "active") {
    const phase = localState(mode) ?? "unavailable";
    return [
      {
        phase,
        enabled: checksEnabledForRuntime(mode, state.enabled),
        meta: null,
        summary: null,
        problems: [],
        error: phase === "unavailable" ? "network_unavailable" : null,
        refreshing: false,
      },
      refresh,
    ];
  }
  return [state, refresh];
}

export function useChecksList(
  request: ChecksRequest,
  mode: ChecksRuntimeMode,
  filters: CheckFilters,
): [ChecksListState, () => void] {
  const [revision, setRevision] = useState(0);
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  const [state, setState] = useState<ChecksListState>(() => ({
    phase: localState(mode) ?? "loading",
    meta: null,
    items: [],
    summary: null,
    total: 0,
    limit: filters.limit,
    offset: filters.offset,
    error: mode === "unavailable" ? "network_unavailable" : null,
    refreshing: false,
  }));
  const requestEpoch = useRef(0);
  const query = buildChecksQuery(filters);
  const summaryQuery = buildChecksQuery(filters, false);

  useEffect(() => {
    const local = localState(mode);
    if (local) {
      requestEpoch.current += 1;
      return undefined;
    }
    const epoch = ++requestEpoch.current;
    const controller = new AbortController();
    queueMicrotask(() => {
      if (controller.signal.aborted || epoch !== requestEpoch.current) return;
      setState((current) => ({
        ...current,
        phase: "loading",
        items: [],
        summary: null,
        total: 0,
        error: null,
        refreshing: current.meta !== null,
      }));
    });
    void Promise.all([
      request(`/checks${query}`, controller.signal),
      request(`/checks/summary${summaryQuery}`, controller.signal),
    ])
      .then(([listResponse, summaryResponse]) => {
        if (controller.signal.aborted || epoch !== requestEpoch.current) return;
        const list = normalizeChecksList(listResponse.payload);
        const summary = normalizeChecksSummary(summaryResponse.payload);
        const meta = mergeChecksMeta(list.meta, summary.meta);
        if (!list.meta.enabled || !summary.meta.enabled) {
          setState({
            phase: "disabled",
            meta,
            items: [],
            summary: null,
            total: 0,
            limit: filters.limit,
            offset: filters.offset,
            error: null,
            refreshing: false,
          });
          return;
        }
        if (
          listResponse.status >= 500 ||
          summaryResponse.status >= 500 ||
          list.meta.dataState === "unavailable" ||
          summary.meta.dataState === "unavailable" ||
          !summary.summary
        ) {
          setState({
            phase: "unavailable",
            meta,
            items: [],
            summary: null,
            total: 0,
            limit: filters.limit,
            offset: filters.offset,
            error: meta.code ?? "checks_unavailable",
            refreshing: false,
          });
          return;
        }
        const phase: ChecksDataState =
          list.meta.dataState === "stale" || summary.meta.dataState === "stale"
            ? "stale"
            : list.total === 0
              ? "empty"
              : "ready";
        setState({
          phase,
          meta,
          items: list.items,
          summary: summary.summary,
          total: list.total,
          limit: list.limit,
          offset: list.offset,
          error: meta.code,
          refreshing: false,
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || epoch !== requestEpoch.current) return;
        setState({
          phase: "unavailable",
          meta: null,
          items: [],
          summary: null,
          total: 0,
          limit: filters.limit,
          offset: filters.offset,
          error:
            error instanceof Error && error.name !== "AbortError"
              ? error.message
              : "checks_unavailable",
          refreshing: false,
        });
      });
    return () => controller.abort();
  }, [filters.limit, filters.offset, mode, query, request, revision, summaryQuery]);

  if (mode !== "active") {
    const phase = localState(mode) ?? "unavailable";
    return [
      {
        phase,
        meta: null,
        items: [],
        summary: null,
        total: 0,
        limit: filters.limit,
        offset: filters.offset,
        error: phase === "unavailable" ? "network_unavailable" : null,
        refreshing: false,
      },
      refresh,
    ];
  }
  return [state, refresh];
}

export function useCheckDetail(
  request: ChecksRequest,
  mode: ChecksRuntimeMode,
  checkId: string,
): [CheckDetailState, () => void] {
  const [revision, setRevision] = useState(0);
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  const [state, setState] = useState<CheckDetailState>(() => ({
    phase: localState(mode) ?? "loading",
    meta: null,
    check: null,
    error: mode === "unavailable" ? "network_unavailable" : null,
    refreshing: false,
  }));
  const requestEpoch = useRef(0);

  useEffect(() => {
    const local = localState(mode);
    if (local) {
      requestEpoch.current += 1;
      return undefined;
    }
    const epoch = ++requestEpoch.current;
    const controller = new AbortController();
    queueMicrotask(() => {
      if (controller.signal.aborted || epoch !== requestEpoch.current) return;
      setState((current) => ({
        ...current,
        phase: "loading",
        check: null,
        error: null,
        refreshing: current.meta !== null,
      }));
    });
    void request(`/checks/${encodeURIComponent(checkId)}`, controller.signal)
      .then((response) => {
        if (controller.signal.aborted || epoch !== requestEpoch.current) return;
        const detail = normalizeCheckDetail(response.payload);
        if (!detail.meta.enabled) {
          setState({
            phase: "disabled",
            meta: detail.meta,
            check: null,
            error: null,
            refreshing: false,
          });
          return;
        }
        if (response.status === 404) {
          setState({
            phase: "not_found",
            meta: detail.meta,
            check: null,
            error: detail.meta.code ?? "check_not_found",
            refreshing: false,
          });
          return;
        }
        if (response.status >= 500 || detail.meta.dataState === "unavailable" || !detail.check) {
          setState({
            phase: "unavailable",
            meta: detail.meta,
            check: null,
            error: detail.meta.code ?? "checks_unavailable",
            refreshing: false,
          });
          return;
        }
        setState({
          phase: detail.meta.dataState,
          meta: detail.meta,
          check: detail.check,
          error: detail.meta.code,
          refreshing: false,
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted || epoch !== requestEpoch.current) return;
        setState({
          phase: "unavailable",
          meta: null,
          check: null,
          error:
            error instanceof Error && error.name !== "AbortError"
              ? error.message
              : "checks_unavailable",
          refreshing: false,
        });
      });
    return () => controller.abort();
  }, [checkId, mode, request, revision]);

  if (mode !== "active") {
    const phase = localState(mode) ?? "unavailable";
    return [
      {
        phase,
        meta: null,
        check: null,
        error: phase === "unavailable" ? "network_unavailable" : null,
        refreshing: false,
      },
      refresh,
    ];
  }
  return [state, refresh];
}
