import { useEvidence } from "../api/hooks";
import type { Device } from "../api/types";
import { ErrorBox, Loading, Panel } from "../components/ui";

export function EvidenceTab({ d }: { d: Device }) {
  const ev = useEvidence(d.id);
  if (ev.isLoading) return <Loading />;
  if (ev.error) return <ErrorBox error={ev.error} />;
  const attrs = (ev.data?.sysfs_attributes ?? {}) as Record<string, string>;
  return (
    <div className="space-y-3">
      <Panel title={`Raw sysfs attributes read (${Object.keys(attrs).length})`}>
        <table className="mono w-full text-[11px]"><tbody>
          {Object.entries(attrs).map(([k, v]) => (
            <tr key={k} className="align-top border-b border-line/30"><td className="pr-3 text-dim break-all">{k}</td><td className="whitespace-pre-wrap break-all">{v}</td></tr>
          ))}
        </tbody></table>
      </Panel>
      <Panel title="Section provenance (JSON)">
        <pre className="mono max-h-[600px] overflow-auto text-[11px]">{JSON.stringify(ev.data, null, 1)}</pre>
      </Panel>
    </div>
  );
}
