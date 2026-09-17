type Props = {
  importing: boolean;
};

export function DropOverlay({ importing }: Props) {
  return (
    <div
      className="pointer-events-none absolute inset-0 z-50 flex items-center justify-center bg-background/75 p-6"
      aria-hidden
    >
      <div className="absolute inset-3 rounded-lg border-2 border-dashed border-accent" />
      <div className="card relative max-w-sm px-6 py-5 text-center">
        <div className="text-base font-semibold">
          {importing ? "Import already in progress" : "Drop memory dump"}
        </div>
        <p className="mt-1 text-sm text-muted">
          {importing
            ? "Wait for the current import to finish, or cancel it from the banner."
            : "Release to import. The same validation as Import Memory Dump is used."}
        </p>
      </div>
    </div>
  );
}
