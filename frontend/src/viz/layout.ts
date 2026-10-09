import type { TopoEdge, TopoNode } from "../api/types";

export interface Placed {
  id: string;
  x: number;
  y: number;
}

/**
 * Layered top-to-bottom layout: rank = longest path from a root; siblings ordered by the
 * parent's position (barycenter) so chains stay straight. Deterministic for stable rendering.
 */
export function layeredLayout(nodes: TopoNode[], edges: TopoEdge[], colW = 240, rowH = 96): Map<string, Placed> {
  const incoming = new Map<string, string[]>();
  const outgoing = new Map<string, string[]>();
  for (const n of nodes) {
    incoming.set(n.id, []);
    outgoing.set(n.id, []);
  }
  for (const e of edges) {
    if (!incoming.has(e.target) || !outgoing.has(e.source)) continue;
    incoming.get(e.target)!.push(e.source);
    outgoing.get(e.source)!.push(e.target);
  }
  const depth = new Map<string, number>();
  const visit = (id: string, seen: Set<string>): number => {
    if (depth.has(id)) return depth.get(id)!;
    if (seen.has(id)) return 0;
    seen.add(id);
    const ins = incoming.get(id) ?? [];
    const d = ins.length ? Math.max(...ins.map((p) => visit(p, seen))) + 1 : 0;
    depth.set(id, d);
    return d;
  };
  nodes.forEach((n) => visit(n.id, new Set()));
  const cols = new Map<number, string[]>();
  for (const n of nodes) {
    const d = depth.get(n.id) ?? 0;
    if (!cols.has(d)) cols.set(d, []);
    cols.get(d)!.push(n.id);
  }
  const row = new Map<string, number>();
  const out = new Map<string, Placed>();
  [...cols.keys()].sort((a, b) => a - b).forEach((d) => {
    const ids = cols.get(d)!;
    const key = (id: string) => {
      const ps = incoming.get(id) ?? [];
      return ps.length ? ps.reduce((s, p) => s + (row.get(p) ?? 0), 0) / ps.length : 0;
    };
    ids.sort((a, b) => key(a) - key(b) || a.localeCompare(b));
    let next = 0;
    ids.forEach((id) => {
      const r = Math.max(next, Math.round(key(id)));
      row.set(id, r);
      next = r + 1;
      // top-to-bottom: depth is the vertical rank, siblings spread horizontally
      out.set(id, { id, x: r * colW, y: d * rowH });
    });
  });
  return out;
}
