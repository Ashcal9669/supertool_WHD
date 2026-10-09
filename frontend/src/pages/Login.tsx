import { useState, type FormEvent } from "react";
import { post } from "../api/client";

export function Login({ onLogin }: { onLogin: () => void }) {
  const [token, setToken] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await post("/auth/login", { token });
      onLogin();
    } catch (x) {
      setErr(x instanceof Error ? x.message : String(x));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex min-h-full items-center justify-center">
      <form onSubmit={submit} className="panel w-[440px] p-6">
        <h1 className="mb-1 text-xl font-semibold text-accent">WHD</h1>
        <p className="mb-4 text-dim">
          Enter the access token. Find it on the WHD host with <code className="mono text-text">whd token --show</code>{" "}
          (file <code className="mono">~/.config/whd/token</code>).
        </p>
        <input
          autoFocus
          type="password"
          aria-label="Access token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="mono mb-3 w-full rounded border border-line bg-bg px-2 py-1.5 outline-none focus:border-accent"
          placeholder="access token"
        />
        {err && <p className="mb-3 text-err">{err}</p>}
        <button disabled={busy || !token} className="w-full rounded border border-accent/60 bg-accent/10 py-1.5 text-accent disabled:opacity-40">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
