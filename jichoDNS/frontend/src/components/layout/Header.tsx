"use client";

import Image from "next/image";
import Link from "next/link";
import { Search, Bell, User, Menu } from "lucide-react";
import { useState } from "react";

export function Header() {
  const [searchQuery, setSearchQuery] = useState("");

  return (
    <header className="bg-gray-900 border-b border-gray-800 px-4 py-3">
      <div className="flex items-center justify-between">
        {/* Logo and Nav */}
        <div className="flex items-center gap-8">
          <Link href="/" className="flex items-center gap-2">
            <Image
              src="/jichodns.png"
              alt="JichoDNS"
              width={32}
              height={32}
              className="rounded"
            />
            <span className="text-xl font-bold text-white">JichoDNS</span>
          </Link>

          <nav className="hidden md:flex items-center gap-6">
            <Link
              href="/"
              className="text-gray-300 hover:text-white transition-colors"
            >
              Map
            </Link>
            <Link
              href="/indicators"
              className="text-gray-300 hover:text-white transition-colors"
            >
              Indicators
            </Link>
            <Link
              href="/analysis"
              className="text-gray-300 hover:text-white transition-colors"
            >
              Analysis
            </Link>
            <Link
              href="/api-docs"
              className="text-gray-300 hover:text-white transition-colors"
            >
              API
            </Link>
          </nav>
        </div>

        {/* Search and Actions */}
        <div className="flex items-center gap-4">
          {/* Search */}
          <div className="hidden sm:flex items-center bg-gray-800 rounded-lg px-3 py-2">
            <Search className="w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search indicators..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent border-none outline-none text-sm text-gray-200 placeholder-gray-500 ml-2 w-48"
            />
          </div>

          {/* Actions */}
          <button className="p-2 text-gray-400 hover:text-white transition-colors">
            <Bell className="w-5 h-5" />
          </button>

          <button className="p-2 text-gray-400 hover:text-white transition-colors">
            <User className="w-5 h-5" />
          </button>

          <button className="md:hidden p-2 text-gray-400 hover:text-white transition-colors">
            <Menu className="w-5 h-5" />
          </button>
        </div>
      </div>
    </header>
  );
}
