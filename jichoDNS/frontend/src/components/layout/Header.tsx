"use client";

import Link from "next/link";
import { Search, Bell, User, Menu } from "lucide-react";
import { useState } from "react";
import { JichoLogo } from "@/components/brand/JichoMark";

export function Header() {
  const [searchQuery, setSearchQuery] = useState("");

  return (
    <header className="bg-body-dark border-b border-white/10 px-4 py-3">
      <div className="flex items-center justify-between">
        {/* Logo and Nav */}
        <div className="flex items-center gap-8">
          <Link href="/" className="flex items-center" aria-label="JichoSec home">
            <JichoLogo size={32} wordClassName="text-white" />
          </Link>

          <nav className="hidden md:flex items-center gap-6">
            <Link
              href="/"
              className="text-white/70 hover:text-secondary transition-colors"
            >
              Map
            </Link>
            <Link
              href="/indicators"
              className="text-white/70 hover:text-secondary transition-colors"
            >
              Indicators
            </Link>
            <Link
              href="/analysis"
              className="text-white/70 hover:text-secondary transition-colors"
            >
              Analysis
            </Link>
            <Link
              href="/api-docs"
              className="text-white/70 hover:text-secondary transition-colors"
            >
              API
            </Link>
          </nav>
        </div>

        {/* Search and Actions */}
        <div className="flex items-center gap-4">
          {/* Search */}
          <div className="hidden sm:flex items-center bg-white/5 rounded-lg px-3 py-2 border border-white/10 focus-within:border-secondary/60 transition-colors">
            <Search className="w-4 h-4 text-white/40" />
            <input
              type="text"
              placeholder="Search indicators..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent border-none outline-none text-sm text-white/90 placeholder-white/40 ml-2 w-48"
            />
          </div>

          {/* Actions */}
          <button className="p-2 text-white/50 hover:text-primary transition-colors">
            <Bell className="w-5 h-5" />
          </button>

          <button className="p-2 text-white/50 hover:text-primary transition-colors">
            <User className="w-5 h-5" />
          </button>

          <button className="md:hidden p-2 text-white/50 hover:text-white transition-colors">
            <Menu className="w-5 h-5" />
          </button>
        </div>
      </div>
    </header>
  );
}
