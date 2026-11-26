import { cleanup, render, screen } from "../test-utils";
import { afterEach, describe, expect, it } from "vitest";
import type { IpsecObservation } from "../api/types";
import { IpsecObservations } from "../components/IpsecObservations";
import { I18nProvider } from "../i18n";

afterEach(cleanup);

const observations: IpsecObservation[] = [
  { target: "192.168.1.10", port: 500, status: "timeout", ike_version: "", exchange: "", proposal: {}, verdict: "indeterminate", evidence: {} },
  { target: "192.168.1.20", port: 500, status: "observed", ike_version: "IKEv2", exchange: "IKE_SA_INIT", proposal: { encryption: "AES-GCM" }, verdict: "indeterminate", evidence: {} },
  { target: "192.168.1.30", port: 4500, status: "error", ike_version: "", exchange: "", proposal: {}, verdict: "indeterminate", evidence: { error: "ike-scan failed" } },
];

describe("IPsec observation details", () => {
  it("lists only probes that received a protocol response", () => {
    render(<I18nProvider><IpsecObservations observations={observations} /></I18nProvider>);
    expect(screen.getByText("192.168.1.20")).toBeInTheDocument();
    expect(screen.queryByText("192.168.1.10")).toBeNull();
    expect(screen.getByText(/encryption: AES-GCM/)).toBeInTheDocument();
  });

  it("shows an empty state without listing probes when every probe times out", () => {
    render(<I18nProvider><IpsecObservations observations={[observations[0]]} /></I18nProvider>);
    expect(screen.getByRole("status")).toHaveTextContent(/No IKE response was received during discovery/i);
    expect(screen.getByRole("status")).toHaveTextContent(/1 silent or indeterminate probe results are retained/i);
    expect(screen.queryByText("192.168.1.10")).toBeNull();
  });

  it("keeps local probe errors separate from responding services", () => {
    render(<I18nProvider><IpsecObservations observations={[observations[2]]} /></I18nProvider>);
    expect(screen.getByRole("alert")).toHaveTextContent(/\(1\)$/);
    expect(screen.queryByText("192.168.1.30")).toBeNull();
  });
});
