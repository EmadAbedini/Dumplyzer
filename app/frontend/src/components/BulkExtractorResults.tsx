import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { engineCall, EngineClientError } from "../lib/api";
import { matchesFieldQuery } from "../lib/resultFilter";
import { useTableSort } from "../lib/tableSort";
import type { SortState } from "../lib/tableSort";
import type {
  BulkExtractorCategory,
  BulkExtractorFeature,
  BulkExtractorFeaturePage,
  BulkExtractorScanBundle,
} from "../lib/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { CenteredLoading } from "./CoverageStatus";
import { ResultFilterBar } from "./ResultFilterBar";
import { SortableTh } from "./SortableTh";
import { StatusToast, useStatusToast } from "./StatusToast";
import { cn } from "../lib/utils";

function extraText(extra: Record<string, unknown> | undefined, key: string): string {
  const value = extra?.[key];
  if (value == null || value === "") return "";
  return String(value);
}

function extraNumber(extra: Record<string, unknown> | undefined, key: string): number | null {
  const value = extra?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function formatSize(bytes: number | null): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function featureFields(item: BulkExtractorFeature, category: string): Record<string, unknown> {
  const extra = item.extra || {};
  return {
    value: item.value,
    offset: item.offset,
    context: item.context,
    count: item.count,
    scanner: item.scanner,
    algorithm: extraText(extra, "algorithm"),
    note: extraText(extra, "note"),
    path: extraText(extra, "path") || item.value,
    network: extraText(extra, "net_name"),
    opened: extraText(extra, "atime"),
    created: extraText(extra, "ctime"),
    filename: extraText(extra, "filename") || item.value,
    size: extraNumber(extra, "size_bytes"),
    sha1: extraText(extra, "sha1"),
    machine: extraText(extra, "machine"),
    compiled: extraText(extra, "compiled"),
    kind: extraText(extra, "kind"),
    category,
  };
}

export function BulkExtractorResults({
  bundle,
  onError,
}: {
  bundle: BulkExtractorScanBundle | null;
  onError: (message: string) => void;
}) {
  const scan = bundle?.scan ?? null;
  const [category, setCategory] = useState<string>("");
  const [page, setPage] = useState<BulkExtractorFeaturePage | null>(null);
  const [filter, setFilter] = useState("");
  const [filterField, setFilterField] = useState("all");
  const [hideWeak, setHideWeak] = useState(true);
  const [loading, setLoading] = useState(false);
  const loadGen = useRef(0);
  const { toast, showToast } = useStatusToast();

  const categories = page?.categories?.length
    ? page.categories
    : (scan?.categories as BulkExtractorCategory[] | undefined) ?? [];
  const selectedCategory =
    (category && categories.some((c) => c.id === category) ? category : categories[0]?.id) ??
    "";
  const pageMatches =
    page != null &&
    page.scan_id === scan?.id &&
    (page.category || "") === selectedCategory &&
    (selectedCategory !== "aes_keys" || Boolean(page.hide_weak) === hideWeak);

  const load = useCallback(async () => {
    if (!scan?.id) {
      setPage(null);
      return;
    }
    if (!selectedCategory && categories.length) return;
    const gen = ++loadGen.current;
    setLoading(true);
    try {
      const res = await engineCall<BulkExtractorFeaturePage>("bulk_extractor.features", {
        scan_id: scan.id,
        category: selectedCategory || undefined,
        hide_weak: selectedCategory === "aes_keys" ? hideWeak : false,
        limit: 800,
        offset: 0,
      });
      if (gen !== loadGen.current) return;
      setPage(res);
    } catch (e) {
      if (gen !== loadGen.current) return;
      setPage(null);
      onError(e instanceof EngineClientError ? e.message : String(e));
    } finally {
      if (gen === loadGen.current) setLoading(false);
    }
  }, [scan?.id, selectedCategory, categories.length, hideWeak, onError]);

  useEffect(() => {
    void load();
  }, [load]);

  const items = pageMatches && page ? page.items : [];
  const filtered = useMemo(
    () =>
      items.filter((item) =>
        matchesFieldQuery(filter, filterField, featureFields(item, selectedCategory), [
          item.scanner,
          JSON.stringify(item.extra || {}),
        ]),
      ),
    [items, filter, filterField, selectedCategory],
  );

  const sortValue = useCallback(
    (item: BulkExtractorFeature, key: string) => {
      const fields = featureFields(item, selectedCategory);
      if (key === "count") return item.count;
      if (key === "size") return extraNumber(item.extra, "size_bytes") ?? 0;
      return String(fields[key] ?? "");
    },
    [selectedCategory],
  );
  const { sorted, sort, toggle } = useTableSort(filtered, sortValue);

  const copyValue = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      showToast("Copied");
    } catch {
      onError("Could not copy to the clipboard.");
    }
  };

  if (!scan) {
    return (
      <div className="flex min-h-[16rem] flex-1 flex-col items-center justify-center px-6 py-16 text-center">
        <div className="text-sm font-semibold">No carved artifacts yet.</div>
        <p className="mt-2 max-w-sm text-sm leading-5 text-muted">
          Carve artifacts from this memory image.
        </p>
      </div>
    );
  }

  if (scan.status === "running" || scan.status === "queued") {
    return <CenteredLoading label="Carving artifacts…" />;
  }

  if (scan.status !== "completed") {
    return (
      <div className="flex min-h-[16rem] flex-1 flex-col items-center justify-center px-6 py-16 text-center">
        <div className="text-sm font-semibold">No carved artifacts yet.</div>
        <p className="mt-2 max-w-sm text-sm leading-5 text-muted">
          Carve artifacts from this memory image.
        </p>
      </div>
    );
  }

  const active = categories.find((c) => c.id === selectedCategory);
  const uniqueTotal = pageMatches && page ? page.total : (active?.unique_count ?? 0);
  const totalLabel = active
    ? `${uniqueTotal.toLocaleString()} unique ${active.label.toLowerCase()}`
    : "";

  return (
    <div className="flex h-full min-h-0 flex-col text-xs">
      <div className="shrink-0 space-y-2 border-b border-border px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <div className="text-sm font-semibold">Extracted strings &amp; IOCs</div>
          <div className="text-muted">{totalLabel}</div>
          {active?.row_count ? (
            <div className="text-muted">
              {active.row_count.toLocaleString()} raw hits
            </div>
          ) : null}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {categories.map((c) => (
            <button
              key={c.id}
              type="button"
              title={c.description}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-medium",
                c.id === selectedCategory
                  ? "border-accent bg-accent text-accent-fg"
                  : "border-border bg-surface-2 text-muted hover:text-foreground",
              )}
              onClick={() => setCategory(c.id)}
            >
              <span>{c.label}</span>
              <span className={c.id === selectedCategory ? "opacity-90" : "text-muted"}>
                {c.unique_count.toLocaleString()}
              </span>
            </button>
          ))}
          {categories.length === 0 && (
            <span className="text-muted">No carved values were stored for this scan.</span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ResultFilterBar
            query={filter}
            onQueryChange={setFilter}
            field={filterField}
            onFieldChange={setFilterField}
            placeholder="Filter this category…"
            fields={[
              { id: "value", label: "Value" },
              { id: "offset", label: "Offset" },
              { id: "context", label: "Context" },
              { id: "path", label: "Path" },
              { id: "network", label: "Network" },
            ]}
          />
          {selectedCategory === "aes_keys" ? (
            <Button
              size="sm"
              variant={hideWeak ? "default" : "outline"}
              onClick={() => setHideWeak((v) => !v)}
            >
              {hideWeak ? "Test keys hidden" : "Showing test keys"}
            </Button>
          ) : null}
        </div>
        {active?.description ? (
          <div className="text-[11px] text-muted">{active.description}</div>
        ) : (
          <div className="text-[11px] text-muted">
            Candidates carved from the memory image — not confirmed indicators.
          </div>
        )}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {loading && items.length === 0 ? (
          <div className="p-6 text-sm text-muted">Loading extracted values…</div>
        ) : sorted.length === 0 ? (
          <div className="p-6 text-sm text-muted">
            {filter.trim()
              ? "No values match the current filter."
              : "Nothing stored in this category."}
          </div>
        ) : (
          <FeatureTable
            category={selectedCategory}
            items={sorted}
            sort={sort}
            onToggle={toggle}
            onCopy={(value) => void copyValue(value)}
          />
        )}
      </div>
      <StatusToast message={toast} />
    </div>
  );
}

function FeatureTable({
  category,
  items,
  sort,
  onToggle,
  onCopy,
}: {
  category: string;
  items: BulkExtractorFeature[];
  sort: SortState | null;
  onToggle: (key: string) => void;
  onCopy: (value: string) => void;
}) {
  if (category === "aes_keys") {
    return (
      <table className="app-result-table w-full text-center">
        <thead className="sticky top-0 bg-surface-2 text-muted">
          <tr>
            <SortableTh label="Algorithm" column="algorithm" sort={sort} onToggle={onToggle} />
            <SortableTh label="Key" column="value" sort={sort} onToggle={onToggle} />
            <SortableTh label="Count" column="count" sort={sort} onToggle={onToggle} />
            <SortableTh label="Offset" column="offset" sort={sort} onToggle={onToggle} />
            <SortableTh label="Note" column="note" sort={sort} onToggle={onToggle} />
            <th className="px-2 py-1 font-medium">Copy</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const extra = item.extra || {};
            const weak = Boolean(extra.weak);
            return (
              <tr key={item.id} className="border-t border-border/40">
                <td className="whitespace-nowrap px-2 py-1">
                  <Badge>{extraText(extra, "algorithm") || "AES"}</Badge>
                </td>
                <td className="px-2 py-1 font-mono whitespace-pre-wrap break-all [overflow-wrap:anywhere]">
                  {item.value}
                </td>
                <td className="px-2 py-1 font-mono">{item.count.toLocaleString()}</td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">{item.offset ?? "—"}</td>
                <td className="px-2 py-1 text-muted">
                  {weak ? "Test / repeating pattern" : "—"}
                </td>
                <td className="px-2 py-1">
                  <Button size="sm" variant="outline" className="h-6 px-2 text-[0.7rem]" onClick={() => onCopy(item.value)}>
                    Copy
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  }

  if (category === "winlnk") {
    return (
      <table className="app-result-table w-full text-center">
        <thead className="sticky top-0 bg-surface-2 text-muted">
          <tr>
            <SortableTh label="Path" column="path" sort={sort} onToggle={onToggle} />
            <SortableTh label="Network" column="network" sort={sort} onToggle={onToggle} />
            <SortableTh label="Opened" column="opened" sort={sort} onToggle={onToggle} />
            <SortableTh label="Created" column="created" sort={sort} onToggle={onToggle} />
            <SortableTh label="Count" column="count" sort={sort} onToggle={onToggle} />
            <th className="px-2 py-1 font-medium">Copy</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const extra = item.extra || {};
            const path = extraText(extra, "path") || item.value;
            return (
              <tr key={item.id} className="border-t border-border/40">
                <td className="px-2 py-1 font-mono whitespace-pre-wrap break-all [overflow-wrap:anywhere] text-left">
                  {path || "—"}
                </td>
                <td className="px-2 py-1 font-mono whitespace-pre-wrap break-all [overflow-wrap:anywhere]">
                  {extraText(extra, "net_name") || "—"}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  {extraText(extra, "atime") || "—"}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  {extraText(extra, "ctime") || "—"}
                </td>
                <td className="px-2 py-1 font-mono">{item.count.toLocaleString()}</td>
                <td className="px-2 py-1">
                  <Button size="sm" variant="outline" className="h-6 px-2 text-[0.7rem]" onClick={() => onCopy(path)}>
                    Copy
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  }

  if (category === "sqlite" || category === "evtx" || category === "zip" || category === "jpeg") {
    return (
      <table className="app-result-table w-full text-center">
        <thead className="sticky top-0 bg-surface-2 text-muted">
          <tr>
            <SortableTh label="File" column="filename" sort={sort} onToggle={onToggle} />
            <SortableTh label="Size" column="size" sort={sort} onToggle={onToggle} />
            <SortableTh label="SHA-1" column="sha1" sort={sort} onToggle={onToggle} />
            <SortableTh label="Offset" column="offset" sort={sort} onToggle={onToggle} />
            <th className="px-2 py-1 font-medium">Copy</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const extra = item.extra || {};
            const name = extraText(extra, "filename") || item.value;
            return (
              <tr key={item.id} className="border-t border-border/40">
                <td className="px-2 py-1 font-mono whitespace-pre-wrap break-all [overflow-wrap:anywhere] text-left">
                  {name}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  {formatSize(extraNumber(extra, "size_bytes"))}
                </td>
                <td className="max-w-[14rem] truncate px-2 py-1 font-mono">
                  {extraText(extra, "sha1") || "—"}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">{item.offset ?? "—"}</td>
                <td className="px-2 py-1">
                  <Button size="sm" variant="outline" className="h-6 px-2 text-[0.7rem]" onClick={() => onCopy(name)}>
                    Copy
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  }

  if (category === "winpe") {
    return (
      <table className="app-result-table w-full text-center">
        <thead className="sticky top-0 bg-surface-2 text-muted">
          <tr>
            <SortableTh label="SHA-1" column="value" sort={sort} onToggle={onToggle} />
            <SortableTh label="Machine" column="machine" sort={sort} onToggle={onToggle} />
            <SortableTh label="Compiled" column="compiled" sort={sort} onToggle={onToggle} />
            <SortableTh label="Kind" column="kind" sort={sort} onToggle={onToggle} />
            <SortableTh label="Count" column="count" sort={sort} onToggle={onToggle} />
            <th className="px-2 py-1 font-medium">Copy</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const extra = item.extra || {};
            return (
              <tr key={item.id} className="border-t border-border/40">
                <td className="max-w-[16rem] truncate px-2 py-1 font-mono">{item.value}</td>
                <td className="whitespace-nowrap px-2 py-1">{extraText(extra, "machine") || "—"}</td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  {extraText(extra, "compiled") || "—"}
                </td>
                <td className="whitespace-nowrap px-2 py-1">{extraText(extra, "kind") || "PE"}</td>
                <td className="px-2 py-1 font-mono">{item.count.toLocaleString()}</td>
                <td className="px-2 py-1">
                  <Button size="sm" variant="outline" className="h-6 px-2 text-[0.7rem]" onClick={() => onCopy(item.value)}>
                    Copy
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  }

  if (category === "windirs") {
    return (
      <table className="app-result-table w-full text-center">
        <thead className="sticky top-0 bg-surface-2 text-muted">
          <tr>
            <SortableTh label="Filename" column="filename" sort={sort} onToggle={onToggle} />
            <SortableTh label="Size" column="size" sort={sort} onToggle={onToggle} />
            <SortableTh label="Modified" column="created" sort={sort} onToggle={onToggle} />
            <SortableTh label="Count" column="count" sort={sort} onToggle={onToggle} />
            <th className="px-2 py-1 font-medium">Copy</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const extra = item.extra || {};
            return (
              <tr key={item.id} className="border-t border-border/40">
                <td className="px-2 py-1 font-mono whitespace-pre-wrap break-all [overflow-wrap:anywhere] text-left">
                  {item.value}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  {formatSize(extraNumber(extra, "size_bytes"))}
                </td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  {extraText(extra, "mtime") || "—"}
                </td>
                <td className="px-2 py-1 font-mono">{item.count.toLocaleString()}</td>
                <td className="px-2 py-1">
                  <Button size="sm" variant="outline" className="h-6 px-2 text-[0.7rem]" onClick={() => onCopy(item.value)}>
                    Copy
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  }

  return (
    <table className="app-result-table w-full text-center">
      <thead className="sticky top-0 bg-surface-2 text-muted">
        <tr>
          <SortableTh label="Value" column="value" sort={sort} onToggle={onToggle} />
          <SortableTh label="Count" column="count" sort={sort} onToggle={onToggle} />
          <SortableTh label="Offset" column="offset" sort={sort} onToggle={onToggle} />
          <SortableTh label="Context" column="context" sort={sort} onToggle={onToggle} />
          <th className="px-2 py-1 font-medium">Copy</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item) => (
          <tr key={item.id} className="border-t border-border/40">
            <td className="px-2 py-1 font-mono whitespace-pre-wrap break-all [overflow-wrap:anywhere] text-left">
              {item.value}
            </td>
            <td className="px-2 py-1 font-mono">{item.count.toLocaleString()}</td>
            <td className="whitespace-nowrap px-2 py-1 font-mono">{item.offset ?? "—"}</td>
            <td className="max-w-sm truncate px-2 py-1 text-muted" title={item.context ?? ""}>
              {item.context || "—"}
            </td>
            <td className="px-2 py-1">
              <Button size="sm" variant="outline" className="h-6 px-2 text-[0.7rem]" onClick={() => onCopy(item.value)}>
                Copy
              </Button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
