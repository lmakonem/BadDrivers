import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { Providers } from "./providers";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist-sans",
  weight: "100 900",
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
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-gray-950 text-gray-100`}
      >
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
