import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post } from "../api/client";
import { Button } from "./ui";

interface ReplayStatus { active: boolean; session: string | null; position: number; total: number; speed: number | null }

/** Shown whenever a stored capture is being replayed through the live pipeline. */
export function ReplayBanner() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["replay"], queryFn: () => api<ReplayStatus>("/replay/status"), refetchInterval: 1500 });
  const stop = useMutation({ mutationFn: () => post("/replay/stop"), onSuccess: () => qc.invalidateQueries({ queryKey: ["replay"] }) });
  if (!q.data?.active) return null;
  const s = q.data;
  return (
    <div role="status" data-testid="replay-banner" className="sticky top-0 z-40 flex items-center gap-3 border-b-2 border-accent bg-accent/20 px-3 py-1 text-[12px] text-accent">
      <b className="uppercase tracking-wider">REPLAY</b>
      <span>recorded events from <span className="mono">{s.session?.replace("replay:", "")}</span> ({s.position}/{s.total}, ×{s.speed}) — not live hardware activity; replayed events are never stored</span>
      <div className="ml-auto"><Button tone="danger" onClick={() => stop.mutate()}>Stop replay</Button></div>
    </div>
  );
}
