// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "../test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { I18nProvider } from "../i18n";
import RunDetail from "../pages/RunDetail";

const run = {
  id: "r1", name: "TLS audit", status: "completed", control_type: "tls", queued_at: "2026-11-24T10:00:00Z", duration_seconds: 5,
  initiated_by: "u", summary: null, reports: [], endpoints: [
    { endpoint_id: "good:443/tcp", hostname: "good", ip_address: "192.0.2.10", port: "443", grade: "A", crypto_grade: "A", pki_status: "TRUSTED_PUBLIC", compliance_status: "compliant", highest_severity: "", tls_versions: ["TLSv1.3"], certificate: { subject: "CN=good", valid_until: "2027-01-01", trust_classification: "PUBLIC_TRUSTED" }, errors: [], untested_checks: [] },
    { endpoint_id: "untrusted:443/tcp", hostname: "untrusted", ip_address: "192.0.2.11", port: "443", grade: "T", crypto_grade: "A+", pki_status: "UNTRUSTED", pki_issues: ["chain_untrusted"], compliance_status: "non_compliant", highest_severity: "high", tls_versions: ["TLSv1.3"], certificate: { subject: "CN=untrusted", valid_until: "2027-01-01", trust_classification: "UNTRUSTED" }, errors: [], untested_checks: [] },
  ], policy_versions: [], trust_stores: [], skipped_hosts: [],
  findings: [
    { finding_id: "TLS_WEAK_CIPHER", title: "Weak cipher accepted", severity: "high", status: "open", category: "TLS", evidence: "TLS 1.2 CBC suite negotiated", remediation: "Disable CBC cipher suites and allow only approved AEAD suites.", affected_endpoint_ids: [] },
    { finding_id: "TLS_UNKNOWN_REMEDIATION", title: "Unmapped observation", severity: "low", status: "open", category: "TLS", evidence: "No remediation supplied", remediation: "  ", affected_endpoint_ids: [] },
  ],
};

vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ user: { id: "u", role: "USER" }, atLeast: (role: string) => role !== "OPERATOR" && role !== "ADMIN" }) }));
vi.mock("../api/client", async (original) => ({ ...(await original<object>()), api: vi.fn(async () => run) }));

afterEach(cleanup);

describe("scan findings recommendations", () => {
  it("separates the colored encryption grade from the T certificate indicator and keeps header controls", async () => {
    render(<I18nProvider initial="en"><MemoryRouter initialEntries={["/scans/r1"]}><Routes>
      <Route path="/scans/:id" element={<RunDetail />} />
    </Routes></MemoryRouter></I18nProvider>);

    const tables = await screen.findAllByRole("table");
    const endpoints = tables[0];
    expect(within(endpoints).getByRole("columnheader", { name: "Encryption grade" })).toBeInTheDocument();
    expect(within(endpoints).getByRole("columnheader", { name: "Certificate" })).toBeInTheDocument();
    expect(within(endpoints).getByText("A+", { selector: ".security-grade" })).toHaveClass("grade-a-plus");
    expect(within(endpoints).getByText("T", { selector: ".security-grade" })).toHaveClass("grade-t");
    expect(within(endpoints).getAllByRole("button", { name: "Filter" }).length).toBeGreaterThan(0);
    expect(within(endpoints).getByRole("button", { name: /Encryption grade/ })).toBeInTheDocument();
  });

  it("shows actionable remediation in its own column and labels missing recommendations", async () => {
    render(<I18nProvider initial="en"><MemoryRouter initialEntries={["/scans/r1"]}><Routes>
      <Route path="/scans/:id" element={<RunDetail />} />
    </Routes></MemoryRouter></I18nProvider>);

    const recommendationHeader = await screen.findByRole("columnheader", { name: "Recommendation" });
    const table = recommendationHeader.closest("table");
    expect(table).not.toBeNull();
    expect(within(table!).getByRole("columnheader", { name: "Recommendation" })).toBeInTheDocument();
    expect(within(table!).getByText("Disable CBC cipher suites and allow only approved AEAD suites.")).toBeInTheDocument();
    expect(within(table!).getByText("No recommendation documented")).toBeInTheDocument();
    expect(within(table!).getByText("TLS 1.2 CBC suite negotiated")).toBeInTheDocument();
  });
});
