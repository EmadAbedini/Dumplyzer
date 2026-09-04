import type { Overview } from "../lib/types";
import { Badge } from "./ui/badge";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-2 border-b border-border/60 py-1.5 text-xs">
      <div className="text-muted">{label}</div>
      <div className="font-mono break-all">{value ?? "—"}</div>
    </div>
  );
}

export function OverviewView({ data }: { data: Overview | null }) {
  if (!data) {
    return (
      <div className="p-4 text-sm text-muted">
        Import a memory image to begin investigation.
      </div>
    );
  }
  const e = data.evidence;
  return (
    <div className="p-4">
      <div className="mb-3 flex items-center gap-2">
        <h2 className="text-sm font-semibold">Overview</h2>
        <Badge>{e.import_status ?? "unknown"}</Badge>
        <Badge>{e.symbol_status ?? "symbols?"}</Badge>
      </div>
      <Row label="Filename" value={e.filename} />
      <Row label="Path" value={e.path} />
      <Row label="Size" value={`${e.size_bytes.toLocaleString()} bytes`} />
      <Row label="SHA-256" value={e.sha256} />
      <Row label="OS" value={e.detected_os} />
      <Row label="Architecture" value={e.architecture} />
      <Row label="Symbol status" value={e.symbol_status} />
      <Row label="Symbol detail" value={e.symbol_detail} />
      <Row label="Processes" value={data.process_count} />
      <Row label="Network" value={data.network_count} />
      <Row label="Modules" value={data.module_count} />
      <Row label="Findings" value={data.finding_count} />
      <Row label="IOCs" value={data.ioc_count} />
      <div className="mt-4">
        <div className="mb-1 text-[10px] uppercase tracking-wide text-muted">
          Recent analysis runs
        </div>
        {data.recent_runs.length === 0 ? (
          <div className="text-xs text-muted">None yet</div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-muted">
              <tr>
                <th className="py-1 font-medium">Kind</th>
                <th className="py-1 font-medium">Status</th>
                <th className="py-1 font-medium">Started</th>
                <th className="py-1 font-medium">Vol</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_runs.map((r) => (
                <tr key={String(r.id)} className="border-t border-border/50">
                  <td className="py-1">{String(r.kind)}</td>
                  <td className="py-1">{String(r.status)}</td>
                  <td className="py-1 font-mono">{String(r.started_at ?? "")}</td>
                  <td className="py-1 font-mono">{String(r.volatility_version ?? "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
