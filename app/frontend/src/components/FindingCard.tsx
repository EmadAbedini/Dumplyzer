import {
  findingSeverity,
  findingSeverityClass,
  findingTitle,
} from "../lib/findings";
import type { Finding } from "../lib/types";
import { cn } from "../lib/utils";
import { Badge } from "./ui/badge";

export function FindingCard({
  finding,
  onOpenProcess,
}: {
  finding: Finding;
  onOpenProcess?: (processId: string) => void;
}) {
  const severity = findingSeverity(finding);
  const title = findingTitle(finding);
  const processId = finding.process_id;
  return (
    <article
      className={cn(
        "finding-card rounded-md border border-border bg-surface px-3 py-2.5 text-left",
        findingSeverityClass(severity),
      )}
    >
      <div className="mb-1.5 flex flex-wrap items-center gap-2">
        <Badge className={findingSeverityClass(severity)}>{severity}</Badge>
        <h3 className="text-sm font-semibold leading-snug">{title}</h3>
        {finding.pid != null ? (
          processId && onOpenProcess ? (
            <button
              type="button"
              className="font-mono text-accent hover:underline"
              onClick={() => onOpenProcess(processId)}
            >
              PID {finding.pid}
            </button>
          ) : (
            <span className="font-mono text-muted">PID {finding.pid}</span>
          )
        ) : null}
      </div>
      <p className="select-text text-sm leading-snug">{finding.explanation}</p>
      {finding.field_value ? (
        <pre className="finding-evidence mt-2 max-h-28 overflow-auto whitespace-pre-wrap break-all rounded-md px-2 py-1.5 font-mono text-[11px]">
          {finding.field_name ? `${finding.field_name}: ` : ""}
          {finding.field_value}
        </pre>
      ) : null}
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-muted">
        {finding.plugin ? <span>{finding.plugin}</span> : null}
        {finding.confidence ? <span>{finding.confidence}</span> : null}
      </div>
    </article>
  );
}
