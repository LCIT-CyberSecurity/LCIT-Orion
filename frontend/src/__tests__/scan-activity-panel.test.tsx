// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, within } from "../test-utils";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import type { Run } from "../api/types";
import { ScanActivityPanel } from "../components/ScanActivityPanel";
import { I18nProvider } from "../i18n";

afterEach(cleanup);
const now = Date.now();
const runs = [
  { id: "tls", name: "TLS perimeter", status: "running", control_type: "tls", phase: "tls_scan", queued_at: new Date(now - 30_000).toISOString(), started_at: new Date(now - 25_000).toISOString(), progress: { hosts_total: 4, hosts_done: 2, events: [{ event: "target_done", at: new Date(now - 1000).toISOString(), target: "web.example.test", hosts_done: 2, hosts_total: 4 }] } },
  { id: "ssh", name: "SSH inventory", status: "queued", control_type: "ssh", phase: "starting", queued_at: new Date(now - 10_000).toISOString(), started_at: null, progress: null },
  { id: "done", name: "Finished scan", status: "completed", control_type: "tls", queued_at: new Date(now - 60_000).toISOString(), started_at: new Date(now - 58_000).toISOString(), finished_at: new Date(now - 1000).toISOString(), progress: { hosts_total: 1, hosts_done: 1, events: [{ event: "finished", status: "completed", at: new Date(now - 1000).toISOString() }] } },
] as unknown as Run[];

function renderPanel(items: Run[]) {
  return render(<MemoryRouter><I18nProvider><ScanActivityPanel runs={items} /></I18nProvider></MemoryRouter>);
}

describe("scan activity panel", () => {
  it("stays collapsed by default and shows concurrent scans, real counts and event times when opened", () => {
    renderPanel(runs);
    const panel = screen.getByLabelText("Scan activity");
    const toggle = within(panel).getByRole("button", { name: /Show details/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(panel).toHaveTextContent("Scans in progress (2)");
    fireEvent.click(toggle);
    expect(within(panel).getByRole("button", { name: /Hide details/ })).toHaveAttribute("aria-expanded", "true");
    expect(within(panel).getByRole("link", { name: "TLS perimeter" })).toHaveAttribute("href", "/scans/tls");
    expect(within(panel).getByRole("link", { name: "SSH inventory" })).toBeInTheDocument();
    expect(within(panel).getAllByText("Progress data unavailable")).toHaveLength(2);
    expect(within(panel).getByText("2/4 targets processed")).toBeInTheDocument();
    expect(within(panel).getByText("Target 2/4 processed")).toBeInTheDocument();
    expect(within(panel).queryByText("web.example.test")).toBeNull();
    expect(within(panel).getAllByText(/TLS|SSH/).length).toBeGreaterThan(0);
    expect(within(panel).getByRole("link", { name: "Finished scan" })).toBeInTheDocument();
  });

  it("shows a clear idle state and no fabricated progress", () => {
    renderPanel([]);
    const panel = screen.getByLabelText("Scan activity");
    expect(panel).toHaveTextContent("No scan in progress");
    fireEvent.click(within(panel).getByRole("button", { name: /Show details/ }));
    expect(within(panel).getByText("No current or recently completed scans.")).toBeInTheDocument();
    expect(within(panel).queryByRole("progressbar")).toBeNull();
  });
});
