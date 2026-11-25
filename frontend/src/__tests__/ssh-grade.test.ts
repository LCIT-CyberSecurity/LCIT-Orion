import { describe, expect, it } from "vitest";
import type { Finding, SshObservation } from "../api/types";
import { sshGrade } from "../lib/sshGrade";

const observation = (overrides: Partial<SshObservation> = {}): SshObservation => ({
  target: "192.0.2.5", port: 22, status: "observed", verdict: "non_compliant", banner: "SSH-2.0-test",
  algorithms: {}, host_keys: [], fingerprints: {}, evidence: {}, ...overrides,
});
const finding = (severity: string): Finding => ({
  finding_id: `SSH_${severity}`, title: "SSH policy finding", severity, status: "KO", category: "SSH",
  evidence: "observed algorithm", affected_endpoint_ids: ["192.0.2.5:22/tcp"], remediation: "Remove the weak algorithm.",
});

describe("SSH security grade", () => {
  it("shows policy compliance as A and maps the worst recorded finding to a colored grade", () => {
    expect(sshGrade(observation({ verdict: "compliant" }), [])).toBe("A");
    expect(sshGrade(observation(), [finding("medium")])).toBe("B");
    expect(sshGrade(observation(), [finding("medium"), finding("high")])).toBe("D");
    expect(sshGrade(observation(), [finding("critical")])).toBe("F");
  });

  it("leaves timeouts, insufficient evidence and unrelated findings ungraded", () => {
    expect(sshGrade(observation({ status: "timeout", verdict: "indeterminate" }), [finding("high")])).toBeNull();
    expect(sshGrade(observation({ verdict: "indeterminate" }), [])).toBeNull();
    expect(sshGrade(observation(), [{ ...finding("high"), affected_endpoint_ids: ["192.0.2.9:22/tcp"] }])).toBeNull();
    expect(sshGrade(observation(), [{ ...finding("high"), category: "TLS" }])).toBeNull();
  });

  it("uses the stored grade when a scan recorded one", () => {
    expect(sshGrade(observation({ evidence: { security_grade: "D" } }), [])).toBe("D");
  });
});
