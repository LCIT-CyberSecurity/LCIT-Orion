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

const zone = { id: "zone-1", name: "DMZ", cidr: "192.0.2.0/24", description: "", zone_type: "dmz", parent_zone_id: null, si_ids: [], target_ids: [], primary_target_ids: [] };
const pairing = { id: "probe-1", name: "dmz-probe", address: "192.0.2.40", api_port: 9443, network_zone_id: zone.id, certificate_sha256: "ab".repeat(32), status: "pairing" as const, capabilities: [], last_seen_at: null };
const active = { ...pairing, status: "active" as const, capabilities: ["tls", "ssh"], last_seen_at: "2026-11-27T08:00:00Z" };

describe("Administration → remote probes", () => {
  it("registers a probe with its pinned certificate and observation zone", async () => {
    responses["GET /remote-probes"] = [];
    responses["GET /map/zones"] = [zone];
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
});
