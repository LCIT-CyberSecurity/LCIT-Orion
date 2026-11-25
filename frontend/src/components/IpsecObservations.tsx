import type { IpsecObservation } from "../api/types";
import { useI18n } from "../i18n";
import { Badge } from "./ui/badge";
import { Card, CardHeader, CardTitle } from "./ui/card";
import { DataTable } from "./DataTable";

/** Show only IKE probes that received a protocol response; silence remains in the stored run data. */
export function IpsecObservations({ observations, id }: { observations: IpsecObservation[]; id?: string }) {
  const observed = observations.filter((observation) => observation.status === "observed");
  const errors = observations.filter((observation) => observation.status === "error");
  const { t } = useI18n();

  return (
    <Card id={id} className="mb-6">
      <CardHeader><CardTitle>{t("ipsec.results" as never)}</CardTitle></CardHeader>
      <p className="px-5 pb-3 text-xs text-muted">{t("ipsec.notice" as never)}</p>
      {errors.length > 0 && <p role="alert" className="px-5 pb-3 text-xs text-danger">{t("ipsec.probeErrors" as never)} ({errors.length})</p>}
      {observed.length === 0 && errors.length === 0 && <div role="status" className="mx-5 mb-5 rounded-lg border border-dashed p-4 text-sm">
        <p>{t("ipsec.noResponse" as never)}</p>
        {observations.length > 0 && <p className="mt-2 text-xs text-muted">{observations.length} {t("ipsec.rawProbesRetained" as never)}</p>}
      </div>}
      {observed.length > 0 && <DataTable rows={observed} rowKey={(row) => `${row.target}:${row.port}:${row.ike_version}`} columns={[
        { key: "target", header: "Target", values: (row) => [row.target], render: (row) => row.target },
        { key: "port", header: "UDP", values: (row) => [String(row.port)], render: (row) => row.port },
        { key: "version", header: "IKE", values: (row) => [row.ike_version], render: (row) => row.ike_version || "—" },
        { key: "status", header: "Probe", values: (row) => [row.status], render: (row) => row.status },
        { key: "verdict", header: "Policy", values: (row) => [row.verdict], render: (row) => <Badge tone={row.verdict === "compliant" ? "success" : row.verdict === "non_compliant" ? "danger" : "warning"}>{row.verdict}</Badge> },
        { key: "proposal", header: "Observed proposal", values: (row) => [JSON.stringify(row.proposal)], render: (row) => <span className="text-xs">{Object.entries(row.proposal).map(([key, value]) => `${key}: ${value}`).join(" · ") || "Non déterminable"}</span> },
      ]} />}
    </Card>
  );
}
