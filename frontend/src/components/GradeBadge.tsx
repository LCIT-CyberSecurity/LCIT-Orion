import { Badge } from "./ui/badge";

const GRADE_CLASS: Record<string, string> = {
  "A+": "grade-a-plus",
  A: "grade-a",
  B: "grade-b",
  C: "grade-c",
  D: "grade-d",
  E: "grade-e",
  F: "grade-f",
  T: "grade-t",
  M: "grade-m",
};

export function GradeBadge({ grade, title }: { grade: string | null | undefined; title?: string }) {
  const value = grade && GRADE_CLASS[grade] ? grade : "—";
  return <Badge className={`security-grade ${GRADE_CLASS[value] ?? "grade-unknown"}`} title={title}>{value}</Badge>;
}
