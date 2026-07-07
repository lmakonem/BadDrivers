import type { Metadata } from "next";
import localFont from "next/font/local";
import { Space_Grotesk, Inter } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-display",
  weight: ["500", "700"],
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
        className={`${spaceGrotesk.variable} ${inter.variable} ${geistMono.variable} antialiased bg-body-dark text-slate-100 overflow-x-hidden`}
      >
        {/* Site-wide fixed datacenter-photo background (opsecfusion parity) */}
        <div aria-hidden="true" className="site-bg" />
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
