import { useState, type ReactNode } from "react";
import type { Availability, SectionMeta } from "../api/types";

export function Panel({ title, meta, right, children, className = "" }: {
  title?: ReactNode; meta?: SectionMeta | null; right?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || meta || right) && (
        <header className="flex items-center gap-2 border-b border-line px-3 py-2">
          <h3 className="text-[12px] font-semibold uppercase tracking-wider text-dim">{title}</h3>
          {meta && <AvailabilityBadge meta={meta} />}
          <div className="ml-auto flex items-center gap-2">{right}</div>
        </header>
      )}
      <div className="p-3">{children}</div>
    </section>
  );
}

const AV_STYLE: Record<Availability, string> = {
  ok: "bg-ok/15 text-ok border-ok/40",
  partial: "bg-warn/15 text-warn border-warn/40",
  unavailable: "bg-dim/15 text-dim border-dim/40",
  requires_privilege: "bg-accent/10 text-accent border-accent/40",
  unsupported: "bg-dim/15 text-dim border-dim/40",
  error: "bg-err/15 text-err border-err/40",
};

export function AvailabilityBadge({ meta }: { meta: SectionMeta }) {
  const [open, setOpen] = useState(false);
  return (
    <span className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={`rounded border px-1.5 py-0.5 text-[10px] uppercase ${AV_STYLE[meta.availability]}`}
        title="Show data sources and issues"
      >
        {meta.availability.replace("_", " ")}
        {meta.issues.length > 0 && ` · ${meta.issues.length}`}
      </button>
      {open && (
        <div className="absolute left-0 top-6 z-30 w-[520px] max-w-[80vw] rounded border border-line bg-panel2 p-2 text-[11px] shadow-xl">
          {meta.note && <p className="mb-1 text-warn">{meta.note}</p>}
          <p className="kv-key mb-1">Sources ({meta.sources.length})</p>
          <ul className="mono mb-2 max-h-40 overflow-auto">
            {meta.sources.map((s) => (
              <li key={s} className="truncate" title={s}>{s}</li>
            ))}
            {meta.sources.length === 0 && <li className="text-dim">none</li>}
          </ul>
          {meta.issues.length > 0 && (
            <>
              <p className="kv-key mb-1">Issues</p>
              <ul className="mono max-h-40 overflow-auto">
                {meta.issues.map((i, n) => (
                  <li key={n}>
                    <span className="text-warn">{i.kind}</span> {i.source}: {i.detail}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </span>
  );
}

export type KVRow = [string, ReactNode, string?];

/** Key/value table. A null/undefined value renders as "not exposed" (never a guess). */
export function KV({ rows, cols = 1 }: { rows: KVRow[]; cols?: 1 | 2 }) {
  return (
    <dl className={`grid gap-x-6 gap-y-1 ${cols === 2 ? "md:grid-cols-2" : ""}`}>
      {rows.map(([k, v, title]) => (
        <div key={k} className="flex min-w-0 gap-3 border-b border-line/40 py-0.5">
          <dt className="kv-key w-44 shrink-0 truncate" title={title ?? k}>{k}</dt>
          <dd className="mono min-w-0 break-all">
            {v === null || v === undefined || v === "" ? <span className="text-dim/70 italic">not exposed</span> : v}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function Badge({ children, tone = "dim", title }: {
  children: ReactNode; tone?: "dim" | "ok" | "warn" | "err" | "accent" | "demo"; title?: string;
}) {
  const t = {
    dim: "border-line text-dim",
    ok: "border-ok/50 text-ok",
    warn: "border-warn/50 text-warn",
    err: "border-err/50 text-err",
    accent: "border-accent/50 text-accent",
    demo: "border-demo text-demo",
  }[tone];
  return <span title={title} className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${t}`}>{children}</span>;
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: { id: T; label: ReactNode }[]; value: T; onChange: (t: T) => void;
}) {
  return (
    <div className="flex flex-wrap gap-1 border-b border-line">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onChange(t.id)}
          className={`-mb-px border-b-2 px-3 py-1.5 text-[12px] ${value === t.id ? "border-accent text-accent" : "border-transparent text-dim hover:text-text"}`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return <div className="rounded border border-err/50 bg-err/10 p-3 text-err">{msg}</div>;
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <div className="animate-pulse p-4 text-dim">{what}…</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded border border-dashed border-line p-4 text-center text-dim">{children}</div>;
}

export function Button({ children, onClick, disabled, tone = "default", title, type = "button" }: {
  children: ReactNode; onClick?: () => void; disabled?: boolean; tone?: "default" | "primary" | "danger";
  title?: string; type?: "button" | "submit";
}) {
  const t = {
    default: "border-line hover:border-accent/60 hover:text-accent",
    primary: "border-accent/60 bg-accent/10 text-accent hover:bg-accent/20",
    danger: "border-err/60 text-err hover:bg-err/10",
  }[tone];
  return (
    <button type={type} title={title} disabled={disabled} onClick={onClick}
      className={`rounded border px-2.5 py-1 text-[12px] transition disabled:cursor-not-allowed disabled:opacity-40 ${t}`}>
      {children}
    </button>
  );
}
