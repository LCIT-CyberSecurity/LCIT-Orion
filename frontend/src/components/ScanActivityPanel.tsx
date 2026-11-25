import { ChevronDown, Clock3 } from "lucide-react";
import { useId, useState } from "react";
import { Link } from "react-router-dom";
import type { Run, RunActivityEvent } from "../api/types";
import { useI18n } from "../i18n";
import { formatDate, formatDuration } from "../lib/utils";
import { StatusBadge } from "./common";
import { Card } from "./ui/card";

const ACTIVE = new Set<Run["status"]>(["queued", "running"]);
const RECENT_FINAL_MS = 90_000;

function eventText(event: RunActivityEvent, t: (key: string, vars?: Record<string, string | number>) => string): string {
  if (event.event === "phase") return t(`phase.${event.phase ?? ""}`);
  if (event.event === "target_done") return t("scanActivity.targetDone", { done: event.hosts_done ?? event.target_index ?? "?", total: event.hosts_total ?? "?" });
  return t("scanActivity.finished", { status: t(`status.${event.status ?? "completed"}`) });
}

function controls(run: Run): string {
  const selected = run.plan?.controls ?? (run.control_type ? [run.control_type] : []);
  return selected.map((control) => control.toUpperCase()).join(" · ") || "—";
}

/** Small, collapsible overview of persisted scan activity. It never starts or controls a scan. */
export function ScanActivityPanel({ runs }: { runs: Run[] }) {
  const { t, locale } = useI18n();
  const tr = t as unknown as (key: string, vars?: Record<string, string | number>) => string;
  const [open, setOpen] = useState(false);
  const detailsId = useId();
  const now = Date.now();
  const active = runs.filter((run) => ACTIVE.has(run.status));
  const recent = runs.filter((run) => !ACTIVE.has(run.status) && run.finished_at
    && now - new Date(run.finished_at).getTime() <= RECENT_FINAL_MS)
    .sort((a, b) => (b.finished_at ?? "").localeCompare(a.finished_at ?? "")).slice(0, 3);
  const items = [...active, ...recent];
  const progressRuns = active.filter((run) => run.progress?.hosts_total != null);
  const done = progressRuns.reduce((sum, run) => sum + (run.progress?.hosts_done ?? 0), 0);
  const total = progressRuns.reduce((sum, run) => sum + (run.progress?.hosts_total ?? 0), 0);
  const allProgressKnown = active.length > 0 && progressRuns.length === active.length && total > 0;

  return (
    <section aria-label={t("scanActivity.title" as never)} className="mb-4">
      <Card className="overflow-hidden">
        <button type="button" aria-expanded={open} aria-controls={detailsId} onClick={() => setOpen((value) => !value)} className="group flex w-full items-center justify-between gap-3 p-3 text-left text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary">
          <span className="min-w-0">
            <strong>{active.length ? t("scanActivity.count" as never, { n: active.length }) : t("scanActivity.none" as never)}</strong>
            {active.length > 0 && <span className="ml-2 text-muted">{allProgressKnown ? t("scanActivity.targets" as never, { done, total }) : t("scanActivity.noProgress" as never)}</span>}
          </span>
          <span className="flex shrink-0 items-center gap-2 text-muted">
            <span>{t(open ? "scanActivity.hide" as never : "scanActivity.show" as never)}</span>
            <ChevronDown className={`size-4 transition-transform ${open ? "rotate-180" : ""}`} aria-hidden />
          </span>
        </button>
        <div id={detailsId} hidden={!open} className="border-t border-hairline p-3">
          {items.length === 0 ? <p className="text-sm text-muted">{t("scanActivity.noActivity" as never)}</p> : (
            <ul className="space-y-3">
              {items.map((run) => {
                const activeRun = ACTIVE.has(run.status);
                const events = (run.progress?.events ?? []).slice(-5);
                return (
                  <li key={run.id} className="rounded-sm border border-hairline p-3">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0">
                        <Link className="row-link font-medium" to={`/scans/${run.id}`}>{run.name}</Link>
                        <p className="mt-1 text-xs text-muted">{controls(run)} · {t("scanActivity.started" as never)} {formatDate(run.started_at ?? run.queued_at, locale)}</p>
                      </div>
                      <StatusBadge status={run.status} />
                    </div>
                    {activeRun && <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
                      <span>{run.status === "queued" ? t("prog.queued" as never) : tr(`phase.${run.phase}`)}</span>
                      {run.started_at && <span>{t("prog.elapsed" as never)} {formatDuration(run.duration_seconds ?? Math.max(0, Math.round((now - Date.parse(run.started_at)) / 1000)))}</span>}
                      {run.progress?.hosts_total != null
                        ? <span>{t("scanActivity.targets" as never, { done: run.progress.hosts_done, total: run.progress.hosts_total })}</span>
                        : <span>{t("scanActivity.noProgress" as never)}</span>}
                    </div>}
                    {events.length > 0 ? <ol className="mt-3 space-y-1 border-l border-hairline pl-3">
                      {events.map((event, index) => <li key={`${event.at}-${event.event}-${index}`} className="flex flex-wrap items-center gap-x-2 text-xs">
                        <Clock3 className="size-3 text-muted" aria-hidden />
                        <time dateTime={event.at} className="text-muted">{formatDate(event.at, locale)}</time>
                        <span>{eventText(event, tr)}</span>
                      </li>)}
                    </ol> : <p className="mt-2 text-xs text-muted">{t("scanActivity.noEvents" as never)}</p>}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </Card>
    </section>
  );
}
