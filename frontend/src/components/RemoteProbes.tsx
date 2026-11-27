import { useState } from "react";
import { api } from "../api/client";
import type { MapZone, Target } from "../api/types";
import { Empty, ErrorNote, Note, useLoad } from "./common";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Dialog } from "./ui/dialog";
import { Field, Input, Select, Textarea } from "./ui/input";
import { Table, Td, Th } from "./ui/table";
import { useI18n } from "../i18n";
import { formatDate } from "../lib/utils";

interface RemoteProbe {
  id: string;
  name: string;
  address: string;
  api_port: number;
  network_zone_id: string;
  certificate_sha256: string;
  status: "pairing" | "active" | "disabled" | "revoked";
  capabilities: string[];
  last_seen_at: string | null;
}

interface ProbeForm {
  name: string;
  address: string;
  api_port: number;
  network_zone_id: string;
  certificate_sha256: string;
  certificate_pem: string;
}

interface ProbeTask {
  id: string;
  kind: string;
  status: string;
  error: string;
  target_ids: string[];
  targets: string[];
  ports: number[];
  created_at: string;
  finished_at: string | null;
}

const EMPTY_FORM: ProbeForm = {
  name: "",
  address: "",
  api_port: 9443,
  network_zone_id: "",
  certificate_sha256: "",
  certificate_pem: "",
};

export function RemoteProbes() {
  const { t, locale } = useI18n();
  const { data, reload, error } = useLoad(() => api<RemoteProbe[]>("/remote-probes"));
  const { data: zones } = useLoad(() => api<MapZone[]>("/map/zones"));
  const { data: targets } = useLoad(() => api<Target[]>("/targets"));
  const [form, setForm] = useState(EMPTY_FORM);
  const [pairingProbe, setPairingProbe] = useState<RemoteProbe | null>(null);
  const [pairingCode, setPairingCode] = useState("");
  const [taskProbe, setTaskProbe] = useState<RemoteProbe | null>(null);
  const [tasks, setTasks] = useState<ProbeTask[]>([]);
  const [taskKind, setTaskKind] = useState("tls");
  const [taskTargets, setTaskTargets] = useState<string[]>([]);
  const [taskPorts, setTaskPorts] = useState("443");
  const [message, setMessage] = useState("");
  const [actionError, setActionError] = useState<unknown>();
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<unknown>, success?: string) {
    setBusy(true);
    setActionError(undefined);
    setMessage("");
    try {
      await action();
      if (success) setMessage(success);
      await reload();
    } catch (cause) {
      setActionError(cause);
    } finally {
      setBusy(false);
    }
  }

  async function createProbe() {
    await run(async () => {
      await api<RemoteProbe>("/remote-probes", { method: "POST", body: form });
      setForm(EMPTY_FORM);
    }, t("probe.created"));
  }

  async function pair() {
    if (!pairingProbe) return;
    await run(async () => {
      await api(`/remote-probes/${pairingProbe.id}/pair`, {
        method: "POST",
        body: { pairing_code: pairingCode },
      });
      setPairingCode("");
      setPairingProbe(null);
    }, t("probe.paired"));
  }

  async function openTasks(probe: RemoteProbe) {
    setBusy(true);
    setActionError(undefined);
    try {
      setTasks(await api<ProbeTask[]>(`/remote-probes/${probe.id}/tasks`));
      setTaskProbe(probe);
      setTaskTargets([]);
      const firstKind = ["tls", "ssh", "ipsec", "dns"].find((kind) => probe.capabilities.includes(kind)) ?? "tls";
      setTaskKind(firstKind);
      setTaskPorts(firstKind === "ssh" ? "22" : firstKind === "ipsec" ? "500,4500" : firstKind === "dns" ? "" : "443");
    } catch (cause) {
      setActionError(cause);
    } finally {
      setBusy(false);
    }
  }

  async function refreshTasks() {
    if (!taskProbe) return;
    setActionError(undefined);
    try {
      setTasks(await api<ProbeTask[]>(`/remote-probes/${taskProbe.id}/tasks`));
    } catch (cause) {
      setActionError(cause);
    }
  }

  async function syncTasks() {
    if (!taskProbe) return;
    setBusy(true);
    setActionError(undefined);
    setMessage("");
    try {
      await api(`/remote-probes/${taskProbe.id}/sync`, { method: "POST" });
      setTasks(await api<ProbeTask[]>(`/remote-probes/${taskProbe.id}/tasks`));
      setMessage(t("probe.syncDone"));
      await reload();
    } catch (cause) {
      setActionError(cause);
    } finally {
      setBusy(false);
    }
  }

  async function dispatchTask() {
    if (!taskProbe) return;
    const ports = taskPorts.split(/[\s,;]+/).filter(Boolean).map(Number);
    setBusy(true);
    setActionError(undefined);
    setMessage("");
    try {
      await api(`/remote-probes/${taskProbe.id}/tasks`, {
        method: "POST",
        body: { kind: taskKind, target_ids: taskTargets, ports, timeout_seconds: 5, workers: 4, policy: {} },
      });
      setMessage(t("probe.taskQueued"));
      setTaskTargets([]);
      await refreshTasks();
      await reload();
    } catch (cause) {
      setActionError(cause);
    } finally {
      setBusy(false);
    }
  }

  const canCreate = form.name.trim() && form.address.trim() && form.network_zone_id
    && form.certificate_sha256.trim() && form.certificate_pem.trim();
  const allowedTargets = taskProbe
    ? targets?.filter((target) => zones?.find((zone) => zone.id === taskProbe.network_zone_id)?.target_ids.includes(target.id)) ?? []
    : [];
  const parsedPorts = taskPorts.split(/[\s,;]+/).filter(Boolean).map(Number);
  const validPorts = taskKind === "dns" ? parsedPorts.length === 0 : parsedPorts.length > 0 && parsedPorts.length <= 64
    && parsedPorts.every((port) => Number.isInteger(port) && port >= 1 && port <= 65535)
    && (taskKind !== "ipsec" || parsedPorts.every((port) => port === 500 || port === 4500));

  return (
    <div className="space-y-4">
      <ErrorNote error={error ?? actionError} />
      {message && <p role="status" className="text-sm text-success">{message}</p>}
      <Card className="p-4">
        <h2 className="mb-3 text-base font-semibold">{t("probe.register")}</h2>
        <p className="mb-4 text-sm text-muted">{t("probe.registerHint")}</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("col.name")}><Input maxLength={120} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label={t("probe.address")}><Input inputMode="url" value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} /></Field>
          <Field label={t("probe.zone")}><Select value={form.network_zone_id} onChange={(e) => setForm({ ...form, network_zone_id: e.target.value })}><option value="">—</option>{zones?.map((zone) => <option key={zone.id} value={zone.id}>{zone.name}{zone.cidr ? ` (${zone.cidr})` : ""}</option>)}</Select></Field>
          <Field label={t("probe.port")}><Input type="number" min={1} max={65535} value={form.api_port} onChange={(e) => setForm({ ...form, api_port: Number(e.target.value) })} /></Field>
          <Field label={t("probe.fingerprint")} hint={t("probe.fingerprintHint")}><Input autoComplete="off" value={form.certificate_sha256} onChange={(e) => setForm({ ...form, certificate_sha256: e.target.value })} /></Field>
          <Field label={t("probe.certificate")} hint={t("probe.certificateHint")}><Textarea rows={4} className="font-mono text-xs" value={form.certificate_pem} onChange={(e) => setForm({ ...form, certificate_pem: e.target.value })} /></Field>
        </div>
        <div className="mt-3 flex justify-end"><Button disabled={!canCreate || busy} onClick={() => void createProbe()}>{t("probe.register")}</Button></div>
      </Card>

      <Card>
        {data?.length ? (
          <Table><thead><tr><Th>{t("col.name")}</Th><Th>{t("probe.zone")}</Th><Th>{t("col.status")}</Th><Th>{t("probe.capabilities")}</Th><Th>{t("probe.lastSeen")}</Th><Th /></tr></thead>
            <tbody>{data.map((probe) => {
              const zoneName = zones?.find((zone) => zone.id === probe.network_zone_id)?.name ?? probe.network_zone_id;
              return <tr key={probe.id}>
                <Td className="font-medium">{probe.name}<div className="font-mono text-xs text-muted">{probe.address}:{probe.api_port}</div></Td>
                <Td>{zoneName}</Td>
                <Td><Badge tone={probe.status === "active" ? "success" : probe.status === "revoked" ? "danger" : "neutral"}>{t(`probe.status.${probe.status}` as never)}</Badge></Td>
                <Td>{probe.capabilities.length ? probe.capabilities.join(", ") : "—"}</Td>
                <Td className="whitespace-nowrap">{probe.last_seen_at ? formatDate(probe.last_seen_at, locale) : "—"}</Td>
                <Td><div className="flex flex-wrap justify-end gap-2">
                  {probe.status === "pairing" && <Button size="sm" variant="outline" onClick={() => setPairingProbe(probe)}>{t("probe.pair")}</Button>}
                  {probe.status === "active" && <>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(async () => { await api(`/remote-probes/${probe.id}/health`, { method: "POST" }); }, t("probe.healthOk"))}>{t("probe.check")}</Button>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(async () => { await api(`/remote-probes/${probe.id}/sync`, { method: "POST" }); }, t("probe.syncDone"))}>{t("probe.sync")}</Button>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => void openTasks(probe)}>{t("probe.tasks")}</Button>
                  </>}
                  {probe.status !== "revoked" && <Button size="sm" variant="outline" disabled={busy} onClick={() => { if (window.confirm(t("probe.confirmRevoke"))) void run(() => api(`/remote-probes/${probe.id}/revoke`, { method: "POST" }), t("probe.revoked")); }}>{t("probe.revoke")}</Button>}
                </div></Td>
              </tr>;
            })}</tbody></Table>
        ) : <Empty>—</Empty>}
      </Card>

      {pairingProbe && <Dialog open onOpenChange={(open) => { if (!open) { setPairingProbe(null); setPairingCode(""); } }} title={t("probe.pairTitle")}>
        <div className="space-y-4">
          <p className="text-sm text-muted">{t("probe.pairHint", { name: pairingProbe.name })}</p>
          <Field label={t("probe.pairCode")}><Input type="password" autoComplete="new-password" value={pairingCode} onChange={(e) => setPairingCode(e.target.value)} /></Field>
          <div className="flex justify-end gap-2"><Button variant="outline" onClick={() => { setPairingProbe(null); setPairingCode(""); }}>{t("action.cancel")}</Button><Button disabled={pairingCode.length < 32 || busy} onClick={() => void pair()}>{t("probe.pair")}</Button></div>
        </div>
      </Dialog>}

      {taskProbe && <Dialog open onOpenChange={(open) => { if (!open) setTaskProbe(null); }} title={`${t("probe.tasks")} — ${taskProbe.name}`} wide>
        <div className="space-y-4">
          <p className="text-sm text-muted">{t("probe.taskScopeHint")}</p>
          {!taskProbe.capabilities.length && <Note tone="warning">{t("probe.noCapabilities")}</Note>}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t("probe.taskKind")}><Select disabled={!taskProbe.capabilities.length} value={taskKind} onChange={(e) => { setTaskKind(e.target.value); setTaskPorts(e.target.value === "ssh" ? "22" : e.target.value === "ipsec" ? "500,4500" : e.target.value === "dns" ? "" : "443"); }}>
              {["tls", "ssh", "ipsec", "dns"].filter((kind) => taskProbe.capabilities.includes(kind)).map((kind) => <option key={kind} value={kind}>{kind.toUpperCase()}</option>)}
            </Select></Field>
            <Field label={t("probe.taskPorts")} hint={t("probe.taskPortsHint")}><Input disabled={taskKind === "dns" || !taskProbe.capabilities.length} value={taskPorts} onChange={(e) => setTaskPorts(e.target.value)} /></Field>
          </div>
          <fieldset className="space-y-2">
            <legend className="field-label">{t("probe.taskTargets")}</legend>
            {allowedTargets.length ? allowedTargets.map((target) => <label key={target.id} className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={taskTargets.includes(target.id)} disabled={!taskTargets.includes(target.id) && taskTargets.length >= 256} onChange={(e) => setTaskTargets(e.target.checked ? [...taskTargets, target.id] : taskTargets.filter((id) => id !== target.id))} />
              <span>{target.name || target.value} <span className="font-mono text-xs text-muted">{target.value}</span></span>
            </label>) : <p className="text-sm text-muted">{t("probe.noAssignedTargets")}</p>}
          </fieldset>
          {taskTargets.length >= 256 && <p className="text-xs text-muted">{t("probe.targetLimit")}</p>}
          <div className="flex justify-end"><Button disabled={!taskProbe.capabilities.includes(taskKind) || !taskTargets.length || !validPorts || busy} onClick={() => void dispatchTask()}>{t("probe.dispatch")}</Button></div>
          <div>
            <div className="mb-2 flex items-center justify-between"><h3 className="font-semibold">{t("probe.recentTasks")}</h3><div className="flex gap-2"><Button size="sm" variant="outline" disabled={busy} onClick={() => void syncTasks()}>{t("probe.syncAndRefresh")}</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => void refreshTasks()}>{t("probe.refreshTasks")}</Button></div></div>
            {tasks.length ? <Table><thead><tr><Th>{t("probe.taskKind")}</Th><Th>{t("probe.taskTargets")}</Th><Th>{t("probe.taskPorts")}</Th><Th>{t("probe.taskStatus")}</Th><Th>{t("probe.taskCreated")}</Th></tr></thead><tbody>{tasks.map((task) => <tr key={task.id}>
              <Td>{task.kind.toUpperCase()}</Td><Td>{task.targets.join(", ")}</Td><Td>{task.ports.join(", ") || "—"}</Td><Td><Badge tone={task.status === "completed" ? "success" : task.status === "failed" ? "danger" : "neutral"}>{task.status}</Badge>{task.error && <div className="text-xs text-danger">{task.error}</div>}</Td><Td className="whitespace-nowrap">{formatDate(task.created_at, locale)}</Td>
            </tr>)}</tbody></Table> : <p className="text-sm text-muted">{t("probe.noTasks")}</p>}
          </div>
        </div>
      </Dialog>}
    </div>
  );
}
