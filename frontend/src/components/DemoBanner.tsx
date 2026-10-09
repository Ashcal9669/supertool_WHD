import type { SystemInfo } from "../api/types";

/** Persistent, visually distinct banner whenever the backend serves fixture data. */
export function DemoBanner({ system }: { system: SystemInfo | undefined }) {
  if (!system || system.mode !== "demo") return null;
  const kind = system.fixture_kind ?? "synthetic";
  return (
    <div role="alert" data-testid="demo-banner" className="demo-stripes sticky top-0 z-50 border-b-2 border-demo text-black">
      <div className="mx-auto flex items-center gap-3 bg-demo/95 px-3 py-1 text-[12px] font-bold uppercase tracking-wider">
        <span>DEMO MODE — {kind === "recorded" ? "RECORDED" : kind === "derived" ? "DERIVED/RECORDED" : "SYNTHETIC"} DATA{system.fixture_events_kind === "synthetic" ? " + SYNTHETIC EVENT STREAM" : ""}</span>
        <span className="font-normal normal-case">
          scenario <b className="mono">{system.demo_scenario}</b> · not live hardware · {system.fixture_description}
          {system.fixture_events_description ? ` · events: ${system.fixture_events_description}` : ""}
        </span>
      </div>
    </div>
  );
}
