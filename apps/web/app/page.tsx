import Link from "next/link";

export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col justify-center px-6 py-20">
      <h1 className="text-5xl font-semibold leading-[1.05] tracking-tight sm:text-6xl">
        Know your edge
        <span className="block border-l-4 border-boundary pl-4 text-muted">before someone else maps it.</span>
      </h1>
      <p className="mt-8 max-w-xl text-lg leading-relaxed text-muted">
        Aegis finds the domains, hosts and web services you own, and shows what&apos;s exposed. It only looks inside
        boundaries you&apos;ve proven are yours, and it never attacks anything.
      </p>
      <div className="mt-10 flex gap-3">
        <Link href="/login" className="rounded-md bg-ink px-5 py-2.5 text-sm font-semibold text-sheet hover:bg-ink/85">
          Sign in
        </Link>
        <Link
          href="/login?mode=register"
          className="rounded-md border border-ink/25 px-5 py-2.5 text-sm font-semibold hover:border-ink/60"
        >
          Create an account
        </Link>
      </div>
    </main>
  );
}
