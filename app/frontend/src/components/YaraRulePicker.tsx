import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { YaraRuleInfo } from "../lib/types";

type Props = {
  rules: YaraRuleInfo[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  disabled?: boolean;
};

type Group = {
  id: string;
  label: string;
  rules: YaraRuleInfo[];
};

function groupRules(rules: YaraRuleInfo[]): Group[] {
  const map = new Map<string, Group>();
  for (const rule of rules) {
    const id = rule.category || "other";
    const existing = map.get(id);
    if (existing) {
      existing.rules.push(rule);
    } else {
      map.set(id, {
        id,
        label: rule.category_label || id,
        rules: [rule],
      });
    }
  }
  const groups = [...map.values()];
  if (!groups.some((group) => group.id === "custom")) {
    groups.push({ id: "custom", label: "Custom rules", rules: [] });
  }
  return groups;
}

export function YaraRulePicker({ rules, selected, onChange, disabled }: Props) {
  const available = useMemo(
    () => rules.filter((rule) => rule.available !== false),
    [rules],
  );
  const groups = useMemo(() => groupRules(available), [available]);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const allRef = useRef<HTMLInputElement>(null);
  const groupRefs = useRef<Record<string, HTMLInputElement | null>>({});

  useEffect(() => {
    if (groups.some((group) => group.id === "custom")) {
      setOpen((prev) => ("custom" in prev ? prev : { ...prev, custom: true }));
    }
  }, [groups]);

  const selectedCount = available.filter((rule) => selected.has(rule.name)).length;
  const allSelected = available.length > 0 && selectedCount === available.length;
  const noneSelected = selectedCount === 0;

  useEffect(() => {
    if (allRef.current) {
      allRef.current.indeterminate = !allSelected && !noneSelected;
    }
    for (const group of groups) {
      const el = groupRefs.current[group.id];
      if (!el) continue;
      const n = group.rules.filter((rule) => selected.has(rule.name)).length;
      el.indeterminate = n > 0 && n < group.rules.length;
    }
  }, [allSelected, noneSelected, groups, selected]);

  const setNames = (names: string[], on: boolean) => {
    const next = new Set(selected);
    for (const name of names) {
      if (on) next.add(name);
      else next.delete(name);
    }
    onChange(next);
  };

  if (available.length === 0) {
    return (
      <p className="mt-3 text-xs text-muted">
        No compiled YARA rules are available for this scan type.
      </p>
    );
  }

  return (
    <div className="mt-3 rounded-md border border-border bg-surface">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <label className="flex items-center gap-2 text-sm font-medium">
          <input
            ref={allRef}
            type="checkbox"
            className="accent-accent"
            disabled={disabled}
            checked={allSelected}
            onChange={() =>
              setNames(
                available.map((rule) => rule.name),
                !allSelected,
              )
            }
          />
          All rules
        </label>
        <span className="ml-auto text-xs text-muted">
          {selectedCount.toLocaleString()} of {available.length.toLocaleString()} selected
        </span>
      </div>
      <div>
        {groups.map((group) => {
          const groupNames = group.rules.map((rule) => rule.name);
          const groupSelected = group.rules.filter((rule) => selected.has(rule.name)).length;
          const expanded = Boolean(open[group.id]);
          const emptyCustom = group.id === "custom" && group.rules.length === 0;
          return (
            <div key={group.id} className="border-t border-border/50">
              <div className="flex items-center gap-1 px-2 py-1.5">
                <button
                  type="button"
                  className="inline-flex h-6 w-6 items-center justify-center text-muted"
                  aria-expanded={expanded}
                  aria-label={`${expanded ? "Collapse" : "Expand"} ${group.label}`}
                  onClick={() =>
                    setOpen((prev) => ({ ...prev, [group.id]: !prev[group.id] }))
                  }
                >
                  {expanded ? (
                    <ChevronDown className="h-4 w-4" strokeWidth={2} />
                  ) : (
                    <ChevronRight className="h-4 w-4" strokeWidth={2} />
                  )}
                </button>
                <label className="flex min-w-0 flex-1 items-center gap-2 text-sm">
                  <input
                    ref={(el) => {
                      groupRefs.current[group.id] = el;
                    }}
                    type="checkbox"
                    className="accent-accent"
                    disabled={disabled || emptyCustom}
                    checked={!emptyCustom && groupSelected === group.rules.length}
                    onChange={() =>
                      setNames(groupNames, groupSelected !== group.rules.length)
                    }
                  />
                  <span className="truncate font-medium">{group.label}</span>
                  <span className="text-xs text-muted">
                    {groupSelected.toLocaleString()}/{group.rules.length.toLocaleString()}
                  </span>
                </label>
              </div>
              {expanded && emptyCustom ? (
                <p className="px-10 pb-3 text-xs text-muted">
                  Files you add in Settings → Signature Detection appear here after Reload
                  Rules. Use this group to scan only your rules.
                </p>
              ) : null}
              {expanded
                ? group.rules.map((rule) => (
                    <label
                      key={rule.name}
                      className="flex items-start gap-2 py-1 pr-3 pb-1.5 pl-10 text-sm last:pb-2"
                      title={rule.description || rule.name}
                    >
                      <input
                        type="checkbox"
                        className="mt-0.5 accent-accent"
                        disabled={disabled}
                        checked={selected.has(rule.name)}
                        onChange={() => setNames([rule.name], !selected.has(rule.name))}
                      />
                      <span className="min-w-0">
                        <span className="block truncate">{rule.display_name}</span>
                        <span className="block truncate font-mono text-[11px] text-muted">
                          {rule.name}
                        </span>
                      </span>
                    </label>
                  ))
                : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}
