import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useSystem } from "../api/hooks";
import { post } from "../api/client";
import { DemoBanner } from "./DemoBanner";
import { ReplayBanner } from "./ReplayBanner";
import { pages } from "../pages/registry";

const NAV: [string, string][] = pages.filter((p) => p.nav).map((p) => [p.path, p.nav!]);

export function Layout({ children, onLogout }: { children: ReactNode; onLogout: () => void }) {
  const { data: sys } = useSystem();
  return (
    <div className="flex min-h-full flex-col">
      <DemoBanner system={sys} />
      <ReplayBanner />
      <header className="flex items-center gap-4 border-b border-line bg-panel px-4 py-2">
        <div className="flex items-center gap-2">
          <span className="text-accent text-lg font-bold tracking-tight">WHD</span>
          <span className="text-dim hidden sm:inline">Wireless Hardware Debugger</span>
        </div>
        <nav className="flex flex-wrap gap-1">
          {NAV.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"}
              className={({ isActive }) => `rounded px-2.5 py-1 text-[12px] ${isActive ? "bg-accent/15 text-accent" : "text-dim hover:text-text"}`}>
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3 text-[11px] text-dim">
          {sys && (
            <span className="mono hidden md:inline" title={sys.kernel_version ?? ""}>
              {sys.hostname} · {sys.kernel_release} · {sys.arch}
            </span>
          )}
          {sys && (
            <span className={`rounded px-1.5 py-0.5 ${sys.mode === "live" ? "bg-ok/15 text-ok" : "bg-demo/20 text-demo"}`}>
              {sys.mode.toUpperCase()}
            </span>
          )}
          <button className="hover:text-text" onClick={async () => { await post("/auth/logout"); onLogout(); }}>
            logout
          </button>
        </div>
      </header>
      <main className="flex-1 p-4">{children}</main>
    </div>
  );
}
