import Link from "next/link";

export default function Home() {
  return (
    <main className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-20">
      <h1 className="text-3xl font-semibold tracking-tight">Aegis ASM</h1>
      <p className="text-slate-600 dark:text-slate-400">
        Find what&apos;s exposed, misconfigured, or affected by known CVEs, only in assets you own or are
        explicitly authorized to assess.
      </p>
      <p className="text-sm text-slate-500">
        Phase 0 foundation: accounts, organizations, roles and audit log. Scanning is not enabled yet.
      </p>
      <div>
        <Link
          href="/login"
          className="inline-block rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
        >
          Sign in
        </Link>
      </div>
    </main>
  );
}
