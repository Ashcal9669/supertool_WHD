import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useSystem } from "../api/hooks";
import { Badge, ErrorBox, KV, Loading, Panel } from "../components/ui";
import { ago } from "../lib/format";

export function SystemPage() {
  const q = useSystem();
  const runs = useQuery({ queryKey: ["runs"], queryFn: () => api<Array<Record<string, unknown>>>("/discovery/runs") });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const s = q.data!;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title="Host">
        <KV rows={[
          ["Hostname", s.hostname], ["Kernel", s.kernel_release], ["Kernel build", s.kernel_version], ["Arch", s.arch],
          ["Distribution", s.distro], ["Python", s.python], ["WHD", s.whd_version], ["Mode", s.mode],
          ["Demo scenario", s.demo_scenario], ["Server uid/euid", `${s.uid}/${s.euid}${s.running_as_root ? " (ROOT!)" : ""}`],
        ]} />
      </Panel>
      <Panel title="Privileged helper">
        <KV rows={Object.entries(s.helper).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)])} />
      </Panel>
      <Panel title="Integrations" className="lg:col-span-2">
        <table className="w-full text-[12px]">
          <thead className="text-dim"><tr><th className="text-left">integration</th><th className="text-left">state</th><th className="text-left">enables</th><th className="text-left">detail</th></tr></thead>
          <tbody>{s.integrations.map((i) => (
            <tr key={i.name} className="border-b border-line/40">
              <td className="mono">{i.name}</td>
              <td><Badge tone={i.state === "ok" || i.state === "via_helper" ? "ok" : i.state === "missing" ? "dim" : "warn"}>{i.state}</Badge></td>
              <td>{i.enables}</td><td className="mono text-dim">{i.detail}</td>
            </tr>
          ))}</tbody>
        </table>
      </Panel>
      <Panel title="Discovery runs" className="lg:col-span-2">
        <table className="mono w-full text-[11px]"><tbody>
          {(runs.data ?? []).map((r) => (
            <tr key={String(r.id)}><td>#{String(r.id)}</td><td>{ago(r.started_at as number)}</td><td>{Number(r.duration_ms).toFixed(0)} ms</td><td>{String(r.device_count)} devices</td><td>{String(r.mode)}</td><td className="text-warn">{(r.issues as unknown[]).length ? `${(r.issues as unknown[]).length} issues` : ""}</td></tr>
          ))}
        </tbody></table>
      </Panel>
    </div>
  );
}
