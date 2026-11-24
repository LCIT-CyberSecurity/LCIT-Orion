// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "../test-utils";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { I18nProvider } from "../i18n";
import RunDetail from "../pages/RunDetail";

const run = {
  id: "ssh-run", name: "SSH scan", status: "completed", control_type: "ssh", queued_at: "2026-11-24T10:00:00Z", duration_seconds: 5,
  initiated_by: "u", summary: null, reports: [], endpoints: [], policy_versions: [], trust_stores: [], skipped_hosts: [], findings: [
    { finding_id: "SSH_WEAK_CIPHER", title: "Weak SSH Cipher Offered", severity: "high", status: "KO", category: "SSH", evidence: "aes128-cbc", remediation: "Remove the weak cipher.", affected_endpoint_ids: ["192.0.2.5:22/tcp"] },
  ],
  ssh_observations: [{ target: "192.0.2.5", port: 22, status: "observed", verdict: "non_compliant", banner: "SSH-2.0-test", algorithms: { encryption: ["aes128-cbc"] }, host_keys: [], fingerprints: {}, evidence: {} }],
};

vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u", role: "USER" }, atLeast: () => false }) }));
vi.mock("../api/client", async (original) => ({ ...(await original<object>()), api: vi.fn(async () => run) }));

afterEach(cleanup);

describe("SSH grade in scan details", () => {
  it("shows a severity-based grade badge and header sort/filter controls", async () => {
    render(<I18nProvider initial="en"><MemoryRouter initialEntries={["/scans/ssh-run"]}><Routes>
      <Route path="/scans/:id" element={<RunDetail />} />
    </Routes></MemoryRouter></I18nProvider>);

    const header = await screen.findByRole("columnheader", { name: "Grade" });
    const table = header.closest("table");
    expect(table).not.toBeNull();
    expect(within(table!).getByText("D", { selector: ".security-grade" })).toHaveClass("grade-d");
    expect(within(table!).getByRole("button", { name: /Grade/ })).toBeInTheDocument();
    expect(within(table!).getAllByRole("button", { name: "Filter" }).length).toBeGreaterThan(0);
  });
});
