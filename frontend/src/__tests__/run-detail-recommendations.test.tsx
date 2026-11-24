// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "../test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { I18nProvider } from "../i18n";
import RunDetail from "../pages/RunDetail";

const run = {
  id: "r1", name: "TLS audit", status: "completed", control_type: "tls", queued_at: "2026-11-24T10:00:00Z", duration_seconds: 5,
  initiated_by: "u", summary: null, reports: [], endpoints: [], policy_versions: [], trust_stores: [], skipped_hosts: [],
  findings: [
    { finding_id: "TLS_WEAK_CIPHER", title: "Weak cipher accepted", severity: "high", status: "open", category: "TLS", evidence: "TLS 1.2 CBC suite negotiated", remediation: "Disable CBC cipher suites and allow only approved AEAD suites.", affected_endpoint_ids: [] },
    { finding_id: "TLS_UNKNOWN_REMEDIATION", title: "Unmapped observation", severity: "low", status: "open", category: "TLS", evidence: "No remediation supplied", remediation: "  ", affected_endpoint_ids: [] },
  ],
};

vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u", role: "USER" }, atLeast: (role: string) => role !== "OPERATOR" && role !== "ADMIN" }) }));
vi.mock("../api/client", async (original) => ({ ...(await original<object>()), api: vi.fn(async () => run) }));

afterEach(cleanup);

describe("scan findings recommendations", () => {
  it("shows actionable remediation in its own column and labels missing recommendations", async () => {
    render(<I18nProvider initial="en"><MemoryRouter initialEntries={["/scans/r1"]}><Routes>
      <Route path="/scans/:id" element={<RunDetail />} />
    </Routes></MemoryRouter></I18nProvider>);

    const table = await screen.findByRole("table");
    expect(within(table).getByRole("columnheader", { name: "Recommendation" })).toBeInTheDocument();
    expect(within(table).getByText("Disable CBC cipher suites and allow only approved AEAD suites.")).toBeInTheDocument();
    expect(within(table).getByText("No recommendation documented")).toBeInTheDocument();
    expect(within(table).getByText("TLS 1.2 CBC suite negotiated")).toBeInTheDocument();
  });
});
