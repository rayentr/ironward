import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Ironward Dashboard",
  description: "Local security scan history for Ironward.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <div className="max-w-6xl mx-auto px-6 py-6">
          <nav className="flex items-center justify-between mb-10">
            <Link href="/" className="flex items-center gap-3">
              <span className="block w-3 h-3 rounded-sm bg-[var(--color-accent)]" />
              <span className="font-semibold">Ironward</span>
              <span className="text-[var(--color-muted)] text-sm">dashboard</span>
            </Link>
            <div className="flex gap-5 text-sm text-[var(--color-muted)]">
              <Link href="/" className="hover:text-white">Overview</Link>
              <Link href="/findings" className="hover:text-white">Findings</Link>
              <Link href="/repos" className="hover:text-white">Repos</Link>
            </div>
          </nav>
          {children}
        </div>
      </body>
    </html>
  );
}
