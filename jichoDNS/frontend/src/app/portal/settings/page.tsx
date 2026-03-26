"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import Link from "next/link";

export default function SettingsPage() {
  const { user, logout } = useAuth();
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="max-w-3xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-400 mt-1">Manage your account and preferences</p>
      </div>

      {/* Profile */}
      <div className="bg-card-dark border border-white/10 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Profile</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Email</label>
            <input
              type="email"
              value={user?.email || ""}
              disabled
              className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-gray-400 cursor-not-allowed"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Name</label>
            <input
              type="text"
              defaultValue={user?.name || ""}
              className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white focus:outline-none focus:border-primary/50"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Organization</label>
            <input
              type="text"
              defaultValue={user?.organization || ""}
              className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white focus:outline-none focus:border-primary/50"
            />
          </div>
        </div>
      </div>

      {/* Subscription */}
      <div className="bg-card-dark border border-white/10 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Subscription</h2>
        <div className="flex items-center justify-between p-4 bg-white/5 rounded-xl">
          <div>
            <p className="text-white font-medium capitalize">{user?.tier || "free"} Plan</p>
            <p className="text-sm text-gray-400">
              {user?.is_admin ? "Full admin access" : user?.tier === "free" ? "Upgrade for premium features" : "All premium features included"}
            </p>
          </div>
          {!user?.is_admin && user?.tier === "free" && (
            <Link
              href="/pricing"
              className="px-4 py-2 bg-primary hover:bg-primary-hover text-white text-sm font-medium rounded-lg transition-colors"
            >
              Upgrade
            </Link>
          )}
        </div>
      </div>

      {/* Notifications */}
      <div className="bg-card-dark border border-white/10 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Notifications</h2>
        <div className="space-y-3">
          {[
            { label: "Email alerts for critical threats", defaultOn: true },
            { label: "Weekly threat summary digest", defaultOn: true },
            { label: "New data breach notifications", defaultOn: true },
            { label: "Brand monitoring alerts", defaultOn: false },
            { label: "API usage warnings", defaultOn: false },
          ].map((item) => (
            <label
              key={item.label}
              className="flex items-center justify-between p-3 bg-white/5 rounded-xl cursor-pointer hover:bg-white/10 transition-colors"
            >
              <span className="text-sm text-white">{item.label}</span>
              <input
                type="checkbox"
                defaultChecked={item.defaultOn}
                className="w-5 h-5 rounded border-white/20 bg-white/10 text-primary focus:ring-primary/50"
              />
            </label>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between">
        <button
          onClick={handleSave}
          className="px-6 py-2.5 bg-primary hover:bg-primary-hover text-white font-medium rounded-xl transition-colors"
        >
          {saved ? "Saved!" : "Save Changes"}
        </button>
        <button
          onClick={logout}
          className="px-6 py-2.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 font-medium rounded-xl border border-red-500/20 transition-colors"
        >
          Sign Out
        </button>
      </div>
    </div>
  );
}
