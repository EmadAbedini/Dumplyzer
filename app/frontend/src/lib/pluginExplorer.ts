export type CatalogFilterInput = {
  query: string;
  category: string;
  runnableOnly: boolean;
};

export function filterPluginItems<
  T extends {
    id: string;
    name: string;
    module_path: string;
    description: string;
    category: string;
    class_name: string;
    runnable: boolean;
    available: boolean;
  },
>(items: T[], filter: CatalogFilterInput): T[] {
  const q = filter.query.trim().toLowerCase();
  return items.filter((item) => {
    if (filter.category && filter.category !== "all" && item.category !== filter.category) {
      return false;
    }
    if (filter.runnableOnly && !item.runnable) {
      return false;
    }
    if (!q) return true;
    return (
      item.id.toLowerCase().includes(q) ||
      item.name.toLowerCase().includes(q) ||
      item.module_path.toLowerCase().includes(q) ||
      item.class_name.toLowerCase().includes(q) ||
      (item.description || "").toLowerCase().includes(q)
    );
  });
}
