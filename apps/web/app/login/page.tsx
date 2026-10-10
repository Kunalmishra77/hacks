"use client";

import { Suspense, useState, type FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ApiError, login, register } from "@/lib/api";

function AuthForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [mode, setMode] = useState<"login" | "register">(params.get("mode") === "register" ? "register" : "login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "login") await login(email, password);
      else await register(email, password, orgName);
      router.push("/dashboard");
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) setError("Too many attempts. Wait a minute and try again.");
        else if (err.status === 409) setError("An account with this email already exists. Sign in instead.");
        else if (err.status === 400) setError("Check the fields: passwords need at least 12 characters.");
        else setError("Email or password is wrong.");
      } else setError("Can't reach the Aegis API. Is it running?");
    } finally {
      setBusy(false);
    }
  }

  const field = "rounded-md border border-line bg-sheet px-3 py-2 text-base outline-none focus:border-ink";

  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center px-6 py-16">
      <h1 className="text-3xl font-semibold tracking-tight">{mode === "login" ? "Sign in" : "Create your account"}</h1>
      <form onSubmit={onSubmit} className="mt-8 flex flex-col gap-4">
        <label className="flex flex-col gap-1.5 text-sm font-medium">
          Email
          <input type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} className={field} />
        </label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">
          Password
          <input
            type="password"
            required
            minLength={mode === "register" ? 12 : 1}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={field}
          />
          {mode === "register" && <span className="text-xs font-normal text-muted">At least 12 characters. A short sentence works well.</span>}
        </label>
        {mode === "register" && (
          <label className="flex flex-col gap-1.5 text-sm font-medium">
            Organization name
            <input required minLength={2} value={orgName} onChange={(e) => setOrgName(e.target.value)} className={field} />
          </label>
        )}
        {error && (
          <p role="alert" className="text-sm text-stop">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy} className="mt-2 rounded-md bg-ink px-4 py-2.5 text-sm font-semibold text-sheet hover:bg-ink/85 disabled:opacity-50">
          {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
        </button>
      </form>
      <button
        type="button"
        onClick={() => {
          setMode(mode === "login" ? "register" : "login");
          setError(null);
        }}
        className="mt-6 self-start text-sm text-muted underline underline-offset-4 hover:text-ink"
      >
        {mode === "login" ? "New here? Create an account" : "Have an account? Sign in"}
      </button>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <AuthForm />
    </Suspense>
  );
}
