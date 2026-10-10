"use client";

import { useState, type FormEvent } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

interface Me {
  user: { id: string; email: string; name: string | null };
  memberships: { orgId: string; role: string; org: { name: string; slug: string } }[];
}

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      // The refresh token comes back as an httpOnly cookie; the access token
      // is kept in memory only (never localStorage).
      const res = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        setError(res.status === 429 ? "Too many attempts. Try again in a minute." : "Invalid email or password.");
        return;
      }
      const { accessToken } = (await res.json()) as { accessToken: string };
      const meRes = await fetch(`${API_URL}/auth/me`, { headers: { authorization: `Bearer ${accessToken}` } });
      setMe((await meRes.json()) as Me);
    } catch {
      setError("Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  if (me) {
    return (
      <main className="mx-auto max-w-md px-4 py-20">
        <h1 className="text-2xl font-semibold">Signed in as {me.user.email}</h1>
        <ul className="mt-6 divide-y divide-slate-200 rounded-md border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
          {me.memberships.length === 0 && <li className="p-3 text-sm text-slate-500">No organizations yet.</li>}
          {me.memberships.map((m) => (
            <li key={m.orgId} className="flex justify-between p-3 text-sm">
              <span>{m.org.name}</span>
              <span className="text-slate-500">{m.role}</span>
            </li>
          ))}
        </ul>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-sm px-4 py-20">
      <h1 className="text-2xl font-semibold">Sign in</h1>
      <form onSubmit={onSubmit} className="mt-6 flex flex-col gap-4">
        <label className="flex flex-col gap-1 text-sm">
          Email
          <input
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="rounded-md border border-slate-300 bg-white px-3 py-2 dark:border-slate-700 dark:bg-slate-900"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Password
          <input
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded-md border border-slate-300 bg-white px-3 py-2 dark:border-slate-700 dark:bg-slate-900"
          />
        </label>
        {error && <p className="text-sm text-red-600" role="alert">{error}</p>}
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50 dark:bg-slate-100 dark:text-slate-900"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
