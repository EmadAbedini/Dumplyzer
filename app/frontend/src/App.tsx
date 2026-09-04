import { useCallback, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type SmokeResult = {
  ok: boolean;
  engine?: {
    ok: boolean;
    health?: Record<string, unknown>;
    volatility?: {
      ok: boolean;
      engine_version?: string;
      python_version?: string;
      volatility3_version?: string;
      volatility3_path?: string;
      framework_package_version?: string;
    };
  };
  error?: string;
};

export default function App() {
  const [result, setResult] = useState<SmokeResult | null>(null);
  const [busy, setBusy] = useState(false);

  const runSmoke = useCallback(async () => {
    setBusy(true);
    setResult(null);
    try {
      const data = await invoke<SmokeResult>("smoke_e2e");
      setResult(data);
    } catch (err) {
      setResult({ ok: false, error: String(err) });
    } finally {
      setBusy(false);
    }
  }, []);

  return (
    <main className="app">
      <header>
        <h1>MemScope</h1>
        <p className="tagline">Environment smoke test</p>
      </header>
      <section>
        <button type="button" onClick={runSmoke} disabled={busy}>
          {busy ? "Running…" : "Run Tauri → Engine → Volatility smoke"}
        </button>
      </section>
      {result && (
        <pre className={result.ok ? "ok" : "fail"}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </main>
  );
}
