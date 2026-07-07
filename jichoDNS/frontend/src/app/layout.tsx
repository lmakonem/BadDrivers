import type { Metadata } from "next";
import localFont from "next/font/local";
import { Sora, Inter } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";

const sora = Sora({
  subsets: ["latin"],
  variable: "--font-sora",
  weight: ["400", "500", "600", "700", "800"],
  display: "swap",
});
const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});
const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-geist-mono",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "JichoSec — Africa's Premier Cyber Threat Intelligence Platform",
  description: "Africa's premier cyber threat intelligence platform. Protecting organizations with real-time threat visibility and actionable security intelligence — threat feeds, dark web monitoring, brand protection, ASM, AI reports, and API access.",
  keywords: ["cyber threat intelligence", "CTI", "Africa", "cybersecurity", "SOC", "SIEM", "threat detection", "dark web monitoring", "brand protection", "attack surface management"],
  authors: [{ name: "JichoSec Team" }],
  openGraph: {
    title: "JichoSec — Africa's Premier Cyber Threat Intelligence Platform",
    description: "Africa's premier cyber threat intelligence platform. Protecting organizations with real-time threat visibility and actionable security intelligence.",
    images: ["/jichosec.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${sora.variable} ${inter.variable} ${geistMono.variable} antialiased bg-body-dark text-slate-100`}
      >
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
