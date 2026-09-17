import { useEffect, useMemo, useRef, useState } from "react";
import { listIanaTimeZones, systemTimeZone } from "../lib/timeZone";
import { cn } from "../lib/utils";
import { ClearableInput } from "./ui/input";

type Props = {
  value: string;
  onChange: (timeZone: string) => void;
  id?: string;
};

export function TimeZoneSelect({ value, onChange, id }: Props) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const rootRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const localZone = systemTimeZone();
  const zones = useMemo(() => {
    const listed = new Set(listIanaTimeZones());
    listed.add("UTC");
    listed.add(localZone);
    listed.add(value);
    return [...listed];
  }, [value, localZone]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matches = q
      ? zones.filter((z) => z.toLowerCase().includes(q) || labelFor(z, localZone).toLowerCase().includes(q))
      : zones;
    const pinned = ["UTC"];
    if (localZone !== "UTC") pinned.push(localZone);
    const rest = matches.filter((z) => !pinned.includes(z));
    const head = pinned.filter((z) => matches.includes(z) || !q);
    return [...head, ...rest];
  }, [query, zones, localZone]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const menu = menuRef.current;
    if (!menu) return;
    let cancelled = false;
    const frameId = window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        if (cancelled) return;
        scrollOverflowParentToReveal(menu);
      });
    });
    return () => {
      cancelled = true;
      window.cancelAnimationFrame(frameId);
    };
  }, [open]);

  return (
    <div ref={rootRef} className={cn("relative", open && "pb-60")}>
      <button
        id={id}
        type="button"
        className="flex h-8 w-full cursor-pointer items-center justify-between rounded-md border border-border bg-surface px-2.5 text-left text-sm shadow-sm outline-none transition-colors hover:bg-surface-2 focus:border-accent"
        onClick={() => {
          setQuery("");
          setOpen((v) => !v);
        }}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span className="min-w-0 truncate">{labelFor(value, localZone)}</span>
        <span className="ml-2 text-muted">▾</span>
      </button>
      {open ? (
        <div
          ref={menuRef}
          className="absolute z-20 mt-1 w-full overflow-hidden rounded-md border border-border bg-surface shadow-lg"
        >
          <div className="border-b border-border p-1.5">
            <ClearableInput
              autoFocus
              placeholder="Search time zones…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onClear={() => setQuery("")}
              onKeyDown={(e) => {
                if (e.key === "Escape") setOpen(false);
              }}
            />
          </div>
          <ul className="max-h-48 overflow-auto py-1" role="listbox">
            {filtered.length === 0 ? (
              <li className="px-2.5 py-2 text-sm text-muted">No matching time zones.</li>
            ) : (
              filtered.map((zone) => {
                const active = zone === value;
                return (
                  <li key={zone} role="option" aria-selected={active}>
                    <button
                      type="button"
                      className={cn(
                        "flex w-full cursor-pointer px-2.5 py-1.5 text-left text-sm hover:bg-surface-2",
                        active ? "bg-surface-2 font-medium" : "",
                      )}
                      onClick={() => {
                        onChange(zone);
                        setOpen(false);
                      }}
                    >
                      {labelFor(zone, localZone)}
                    </button>
                  </li>
                );
              })
            )}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function scrollOverflowParentToReveal(el: HTMLElement) {
  let parent: HTMLElement | null = el.parentElement;
  while (parent) {
    const overflowY = getComputedStyle(parent).overflowY;
    if (overflowY === "auto" || overflowY === "scroll") {
      const extra = el.getBoundingClientRect().bottom - parent.getBoundingClientRect().bottom + 8;
      if (extra > 0) parent.scrollBy({ top: extra, behavior: "smooth" });
      return;
    }
    parent = parent.parentElement;
  }
}

function labelFor(zone: string, localZone: string): string {
  if (zone === "UTC") return "UTC";
  if (zone === localZone) return `Local Time (${zone})`;
  return zone;
}
