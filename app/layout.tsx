import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SubScope – Subdomain finder",
  description:
    "Find every subdomain of a domain from certificate logs and public DNS, check which ones respond, and export the list.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen font-sans">{children}</body>
    </html>
  );
}
