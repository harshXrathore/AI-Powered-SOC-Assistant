import { useQuery } from "@tanstack/react-query";
import { apiClient } from "./services/apiClient";

interface HealthResponse {
  status: string;
  environment: string;
}

function App() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["health"],
    queryFn: async () => {
      const res = await apiClient.get<HealthResponse>("/health");
      return res.data;
    },
  });

  return (
    <div className="min-h-screen bg-soc-bg flex flex-col items-center justify-center gap-4">
      <h1 className="text-2xl font-semibold text-soc-accent">AI SOC Assistant</h1>
      <p className="text-slate-400">Phase 1 — architecture scaffold</p>

      <div className="mt-4 rounded-lg border border-soc-border bg-soc-panel px-6 py-4 text-sm">
        {isLoading && <span className="text-slate-400">Checking backend connection…</span>}
        {isError && <span className="text-soc-critical">Backend unreachable</span>}
        {data && (
          <span className="text-emerald-400">
            Backend status: {data.status} ({data.environment})
          </span>
        )}
      </div>
    </div>
  );
}

export default App;
