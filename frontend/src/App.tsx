import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { Route, Routes } from "react-router-dom";
import { api, onUnauthorized } from "./api/client";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { pages } from "./pages/registry";
import { Login } from "./pages/Login";

export function App() {
  const qc = useQueryClient();
  const session = useQuery({
    queryKey: ["session"],
    queryFn: () => api<{ authenticated: boolean }>("/auth/session"),
    retry: false,
    staleTime: 60_000,
  });
  useEffect(() => onUnauthorized(() => qc.setQueryData(["session"], null)), [qc]);
  if (session.isLoading) return <Loading what="Connecting" />;
  const authed = !!session.data?.authenticated;
  if (!authed) return <Login onLogin={() => qc.invalidateQueries()} />;
  return (
    <Layout onLogout={() => { qc.clear(); qc.setQueryData(["session"], null); }}>
      <Routes>
        {pages.map((p) => <Route key={p.path} path={p.path} element={<p.Component />} />)}
      </Routes>
    </Layout>
  );
}
