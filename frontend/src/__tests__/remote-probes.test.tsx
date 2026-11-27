// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "../test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RemoteProbes } from "../components/RemoteProbes";
import { I18nProvider } from "../i18n";

const calls: { path: string; method: string; body?: unknown }[] = [];
let responses: Record<string, unknown> = {};
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: vi.fn(async (path: string, options: { method?: string; body?: unknown } = {}) => {
    const method = options.method ?? "GET";
    calls.push({ path, method, body: options.body });
    const key = `${method} ${path}`;
    if (!(key in responses)) throw new Error(`unexpected call ${key}`);
    const value = responses[key];
    if (value instanceof Error) throw value;
    return value;
  }),
}));

afterEach(cleanup);
beforeEach(() => { calls.length = 0; responses = {}; vi.spyOn(window, "confirm").mockReturnValue(true); });
const wrap = () => render(<I18nProvider initial="en"><RemoteProbes /></I18nProvider>);

const zone = { id: "zone-1", name: "DMZ", cidr: "192.0.2.0/24", description: "", zone_type: "dmz", parent_zone_id: null, si_ids: [], target_ids: ["target-1"], primary_target_ids: [] };
const targets = [
  { id: "target-1", name: "Authorized host", value: "192.0.2.10", kind: "host", ports: "443", description: "", owner_id: null, tags: [], si_ids: [] },
  { id: "target-2", name: "Other zone", value: "198.51.100.10", kind: "host", ports: "443", description: "", owner_id: null, tags: [], si_ids: [] },
];
const pairing = { id: "probe-1", name: "dmz-probe", address: "192.0.2.40", api_port: 9443, network_zone_id: zone.id, certificate_sha256: "ab".repeat(32), status: "pairing" as const, capabilities: [], last_seen_at: null };
const active = { ...pairing, status: "active" as const, capabilities: ["tls", "ssh"], last_seen_at: "2026-11-27T08:00:00Z" };

describe("Administration → remote probes", () => {
  it("registers a probe with its pinned certificate and observation zone", async () => {
    responses["GET /remote-probes"] = [];
    responses["GET /map/zones"] = [zone];
    responses["GET /targets"] = targets;
    responses["POST /remote-probes"] = pairing;
    wrap();
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "dmz-probe" } });
    fireEvent.change(screen.getByLabelText("Probe IPv4 address"), { target: { value: "192.0.2.40" } });
    fireEvent.change(screen.getByLabelText("Observation zone"), { target: { value: zone.id } });
    fireEvent.change(screen.getByLabelText("Certificate SHA-256 fingerprint"), { target: { value: pairing.certificate_sha256 } });
    fireEvent.change(screen.getByLabelText("Server certificate PEM"), { target: { value: "-----BEGIN CERTIFICATE-----\\npublic\\n-----END CERTIFICATE-----" } });
    fireEvent.click(screen.getByRole("button", { name: "Register a probe" }));
    await screen.findByRole("status");
    const request = calls.find((call) => call.method === "POST" && call.path === "/remote-probes");
    expect(request?.body).toEqual(expect.objectContaining({
      address: "192.0.2.40",
      network_zone_id: zone.id,
      certificate_sha256: pairing.certificate_sha256,
    }));
  });

  it("pairs with a one-time code, then allows health and result synchronization", async () => {
    responses["GET /remote-probes"] = [pairing];
    responses["GET /map/zones"] = [zone];
    responses["GET /targets"] = targets;
    responses[`POST /remote-probes/${pairing.id}/pair`] = { ...active, encrypted_token: undefined };
    responses[`POST /remote-probes/${pairing.id}/health`] = { probe: active, health: { status: "ok" } };
    responses[`POST /remote-probes/${pairing.id}/sync`] = { events_received: 1, events_imported: 1, acknowledged_cursor: 1, acknowledgement_pending: false };
    wrap();
    const row = (await screen.findByText("dmz-probe")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Pair" }));
    const dialog = await screen.findByRole("dialog");
    const secret = "one-time-pairing-code-with-high-entropy";
    fireEvent.change(within(dialog).getByLabelText("Temporary code"), { target: { value: secret } });
    responses["GET /remote-probes"] = [active];
    fireEvent.click(within(dialog).getByRole("button", { name: "Pair" }));
    await screen.findByText(/Probe paired/);
    expect(calls.find((call) => call.path.endsWith("/pair"))?.body).toEqual({ pairing_code: secret });
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
    const activeRow = (await screen.findByText("dmz-probe")).closest("tr")!;
    expect(within(activeRow).getByText("tls, ssh")).toBeInTheDocument();
    fireEvent.click(within(activeRow).getByRole("button", { name: "Check" }));
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/health"))).toBe(true));
    fireEvent.click(within(activeRow).getByRole("button", { name: "Sync" }));
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/sync"))).toBe(true));
  });

  it("dispatches only assigned targets and displays the task status", async () => {
    responses["GET /remote-probes"] = [active];
    responses["GET /map/zones"] = [zone];
    responses["GET /targets"] = targets;
    const task = {
      id: "task-1", kind: "tls", status: "queued", error: "", target_ids: ["target-1"],
      targets: ["192.0.2.10"], ports: [443], created_at: "2026-11-27T08:00:00Z", finished_at: null,
    };
    responses[`GET /remote-probes/${active.id}/tasks`] = [task];
    responses[`POST /remote-probes/${active.id}/tasks`] = { task_id: task.id, status: "queued" };
    responses[`POST /remote-probes/${active.id}/sync`] = { events_received: 0, events_imported: 0, acknowledged_cursor: 0, acknowledgement_pending: false };
    wrap();
    const row = (await screen.findByText("dmz-probe")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Tasks" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Authorized host/)).toBeInTheDocument();
    expect(within(dialog).queryByText(/Other zone/)).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByLabelText(/Authorized host/));
    fireEvent.click(within(dialog).getByRole("button", { name: "Run on this probe" }));
    await screen.findByText("Task submitted. Refresh tasks after synchronization to see its status.");
    const request = calls.find((call) => call.method === "POST" && call.path.endsWith("/tasks"));
    expect(request?.body).toEqual({
      kind: "tls", target_ids: ["target-1"], ports: [443], timeout_seconds: 5, workers: 4, policy: {},
    });
    expect(within(dialog).getByText("queued")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Sync probe and refresh" }));
    await waitFor(() => expect(calls.some((call) => call.method === "POST" && call.path.endsWith("/sync"))).toBe(true));
    expect(calls.filter((call) => call.path === `/remote-probes/${active.id}/tasks`).length).toBeGreaterThanOrEqual(2);
  });

  it("limits task selection to each engine's bounded target-port workload", async () => {
    const assigned = Array.from({ length: 17 }, (_, index) => ({
      id: `target-${index + 1}`, name: `Host ${index + 1}`, value: `192.0.2.${index + 10}`,
      kind: "host", ports: "443", description: "", owner_id: null, tags: [], si_ids: [],
    }));
    responses["GET /remote-probes"] = [active];
    responses["GET /map/zones"] = [{ ...zone, target_ids: assigned.map((target) => target.id) }];
    responses["GET /targets"] = assigned;
    responses[`GET /remote-probes/${active.id}/tasks`] = [];
    wrap();
    const row = (await screen.findByText("dmz-probe")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Tasks" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Ports"), { target: { value: "443,8443" } });
    const checkboxes = within(dialog).getAllByRole("checkbox");
    for (const checkbox of checkboxes.slice(0, 16)) fireEvent.click(checkbox);
    expect(checkboxes[16]).toBeDisabled();
    expect(within(dialog).getByText("Maximum 16 targets for this task, based on the engine work limit.")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Run on this probe" })).toBeEnabled();
  });
});
