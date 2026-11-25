import type { Finding, SshObservation } from "../api/types";

const SEVERITY_GRADE: Record<string, string> = { critical: "F", high: "D", medium: "B", low: "C" };

export function sshGrade(observation: SshObservation, findings: Finding[]): string | null {
  if (observation.status !== "observed") return null;
  const stored = observation.evidence?.security_grade;
  if (typeof stored === "string" && ["A", "B", "C", "D", "F"].includes(stored)) return stored;
  if (observation.verdict === "compliant") return "A";
  if (observation.verdict !== "non_compliant") return null;

  const endpoint = `${observation.target}:${observation.port}/tcp`;
  const relevant = findings.filter((finding) => finding.category.toLowerCase() === "ssh" && finding.affected_endpoint_ids.includes(endpoint));
  return relevant.map((finding) => SEVERITY_GRADE[finding.severity.toLowerCase()]).filter(Boolean)
    .sort((a, b) => ["A", "B", "C", "D", "F"].indexOf(b) - ["A", "B", "C", "D", "F"].indexOf(a))[0] ?? null;
}
