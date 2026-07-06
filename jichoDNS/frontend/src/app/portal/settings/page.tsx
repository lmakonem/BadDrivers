"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import Link from "next/link";
import { apiFetchJSON } from "@/lib/fetch";

interface PlatformUser {
  id: number;
  email: string;
  name: string | null;
  is_admin: boolean;
  tier: string;
}

interface ClientAccess {
  user_id: number;
  email: string;
  name: string | null;
  access_level: string;
  granted_at: string | null;
  granted_by_email: string | null;
}

interface ASMClient {
  id: number;
  name: string;
  country_code: string | null;
  industry: string | null;
  risk_grade: string | null;
}

export default function SettingsPage() {
  const { user, logout } = useAuth();

  // Admin access management state
  const [adminTab, setAdminTab] = useState<"by_user" | "by_client">("by_user");
  const [users, setUsers] = useState<PlatformUser[]>([]);
  const [clients, setClients] = useState<ASMClient[]>([]);
  const [selectedUser, setSelectedUser] = useState<PlatformUser | null>(null);
  const [selectedClient, setSelectedClient] = useState<ASMClient | null>(null);
  const [clientAccess, setClientAccess] = useState<ClientAccess[]>([]);
  const [loadingAccess, setLoadingAccess] = useState(false);
  const [accessMsg, setAccessMsg] = useState<string | null>(null);
  const [grantLevel, setGrantLevel] = useState("read");

  const fetchUsers = useCallback(async () => {
    try {
      const d = await apiFetchJSON("/api/v1/asm/access/users") as { users: PlatformUser[] } | null;
      setUsers(d?.users ?? []);
    } catch { /* non-admin: silently ignore */ }
  }, []);

  const fetchClients = useCallback(async () => {
    try {
      const d = await apiFetchJSON("/api/v1/asm/clients") as { clients: ASMClient[] } | null;
      setClients(d?.clients ?? []);
    } catch {}
  }, []);

  const fetchClientAccess = useCallback(async (clientId: number) => {
    setLoadingAccess(true);
    try {
      const d = await apiFetchJSON(`/api/v1/asm/clients/${clientId}/access`) as { access: ClientAccess[] } | null;
      setClientAccess(d?.access ?? []);
    } finally {
      setLoadingAccess(false);
    }
  }, []);

  useEffect(() => {
    if (user?.is_admin) {
      fetchUsers();
      fetchClients();
    }
  }, [user, fetchUsers, fetchClients]);

  useEffect(() => {
    if (selectedClient) fetchClientAccess(selectedClient.id);
  }, [selectedClient, fetchClientAccess]);

  const grantAccess = async (clientId: number, userId: number, level: string) => {
    try {
      await apiFetchJSON(`/api/v1/asm/clients/${clientId}/access`, {
        method: "POST",
        body: JSON.stringify({ user_id: userId, access_level: level }),
      });
      setAccessMsg(`Access granted`);
      fetchClientAccess(clientId);
    } catch { setAccessMsg("Failed to grant access"); }
    setTimeout(() => setAccessMsg(null), 3000);
  };

  const revokeAccess = async (clientId: number, userId: number) => {
    try {
      await apiFetchJSON(`/api/v1/asm/clients/${clientId}/access/${userId}`, { method: "DELETE" });
      setAccessMsg("Access revoked");
      fetchClientAccess(clientId);
    } catch { setAccessMsg("Failed to revoke access"); }
    setTimeout(() => setAccessMsg(null), 3000);
  };

  const bulkGrant = async (userId: number, level: string) => {
    try {
      await apiFetchJSON(`/api/v1/asm/access/bulk-grant?user_id=${userId}&access_level=${level}`, { method: "POST" });
      setAccessMsg(`All clients granted to user`);
    } catch { setAccessMsg("Failed"); }
    setTimeout(() => setAccessMsg(null), 3000);
  };

  const bulkRevoke = async (userId: number) => {
    if (!confirm("Revoke this user's access to all clients?")) return;
    try {
      await apiFetchJSON(`/api/v1/asm/access/bulk-revoke?user_id=${userId}`, { method: "POST" });
      setAccessMsg("Access revoked from all clients");
    } catch { setAccessMsg("Failed"); }
    setTimeout(() => setAccessMsg(null), 3000);
  };

  const levelColor = (lvl: string) =>
    lvl === "owner" ? "text-blue-300 bg-blue-900/30 border-blue-700/40" :
    lvl === "admin" ? "text-purple-300 bg-purple-900/30 border-purple-700/40" :
    "text-gray-300 bg-gray-700/40 border-gray-600";

  return (
    <div className="max-w-4xl space-y-8 pb-12">
      <div className="sticky top-0 z-20 bg-ebony-950/95 backdrop-blur-sm pt-4 pb-2 -mx-4 px-4 lg:-mx-8 lg:px-8">
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-400 mt-1">Manage your account, preferences, and access control</p>
      </div>

      {/* Profile */}
      <div className="bg-card-dark border border-white/10 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Profile</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Email</label>
            <input type="email" value={user?.email || ""} disabled
              className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-gray-400 cursor-not-allowed" />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Name</label>
            <input type="text" value={user?.name || ""} disabled
              className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-gray-400 cursor-not-allowed" />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Organization</label>
            <input type="text" value={user?.organization || ""} disabled
              className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-gray-400 cursor-not-allowed" />
          </div>
          <p className="text-xs text-gray-500">Profile editing is not available in this release.</p>
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
            <Link href="/pricing"
              className="px-4 py-2 bg-primary hover:bg-primary-hover text-white text-sm font-medium rounded-lg transition-colors">
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
            <label key={item.label}
              className="flex items-center justify-between p-3 bg-white/5 rounded-xl cursor-not-allowed opacity-70">
              <span className="text-sm text-white">{item.label}</span>
              <input type="checkbox" defaultChecked={item.defaultOn} disabled
                className="w-5 h-5 rounded border-white/20 bg-white/10 text-primary focus:ring-primary/50" />
            </label>
          ))}
        </div>
      </div>

      {/* ── Admin: Access Control ── */}
      {user?.is_admin && (
        <div className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden">
          {/* Header */}
          <div className="p-5 border-b border-white/10">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">Access Control</h2>
                <p className="text-sm text-gray-400 mt-0.5">
                  Control which users can see Attack Surface, Brand Protection, and Alerts data per client.
                </p>
              </div>
              {accessMsg && (
                <span className="text-xs text-green-400 bg-green-900/20 border border-green-700/30 px-3 py-1.5 rounded-lg">
                  {accessMsg}
                </span>
              )}
            </div>
            {/* View toggle */}
            <div className="flex gap-2 mt-4">
              {([["by_client", "Manage by Client"], ["by_user", "Manage by User"]] as const).map(([v, l]) => (
                <button key={v} onClick={() => { setAdminTab(v); setSelectedClient(null); setSelectedUser(null); setClientAccess([]); }}
                  className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${adminTab === v ? "bg-primary text-white" : "bg-white/5 text-gray-400 hover:text-white"}`}>
                  {l}
                </button>
              ))}
            </div>
          </div>

          <div className="flex" style={{ minHeight: 420 }}>
            {/* ── By Client view ── */}
            {adminTab === "by_client" && (
              <>
                {/* Client list */}
                <div className="w-64 flex-shrink-0 border-r border-white/10 overflow-y-auto" style={{ maxHeight: 520 }}>
                  {clients.map((c) => (
                    <button key={c.id} onClick={() => setSelectedClient(c)}
                      className={`w-full text-left px-4 py-3 border-b border-white/5 hover:bg-white/5 transition-colors ${selectedClient?.id === c.id ? "bg-primary/10 border-l-2 border-l-primary" : ""}`}>
                      <div className="text-sm font-medium text-white truncate">{c.name}</div>
                      <div className="text-xs text-gray-500">{c.country_code} · Grade {c.risk_grade || "?"}</div>
                    </button>
                  ))}
                </div>

                {/* Access panel */}
                <div className="flex-1 p-5 space-y-4">
                  {!selectedClient ? (
                    <div className="text-gray-500 text-sm flex items-center justify-center h-full">
                      Select a client to manage access
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-semibold text-white">{selectedClient.name} — User Access</h3>
                        <span className="text-xs text-gray-500">{clientAccess.length} user(s)</span>
                      </div>

                      {/* Current access list */}
                      <div className="space-y-2">
                        {loadingAccess ? (
                          <div className="text-xs text-gray-500">Loading...</div>
                        ) : clientAccess.length === 0 ? (
                          <div className="text-xs text-gray-500">No users have access to this client.</div>
                        ) : clientAccess.map((a) => (
                          <div key={a.user_id} className="flex items-center justify-between bg-white/5 rounded-lg px-3 py-2">
                            <div>
                              <div className="text-sm text-white">{a.email}</div>
                              <div className="text-xs text-gray-500">{a.name || ""}</div>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={`text-xs px-2 py-0.5 rounded border ${levelColor(a.access_level)}`}>{a.access_level}</span>
                              {a.access_level !== "owner" && (
                                <button onClick={() => revokeAccess(selectedClient.id, a.user_id)}
                                  className="text-xs text-red-400 hover:text-red-300 px-2 py-0.5 border border-red-700/40 rounded hover:bg-red-900/20 transition-colors">
                                  Revoke
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>

                      {/* Grant access to a new user */}
                      <div className="border-t border-white/10 pt-4">
                        <div className="text-xs text-gray-400 mb-2 font-semibold uppercase tracking-wider">Grant Access</div>
                        <div className="flex gap-2 flex-wrap">
                          <select defaultValue="" onChange={(e) => {
                            const uid = parseInt(e.target.value);
                            if (uid) grantAccess(selectedClient.id, uid, grantLevel);
                            e.target.value = "";
                          }}
                            className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-primary/50">
                            <option value="" disabled>Select user to grant...</option>
                            {users
                              .filter((u) => !clientAccess.find((a) => a.user_id === u.id))
                              .map((u) => (
                                <option key={u.id} value={u.id}>{u.email} ({u.tier})</option>
                              ))}
                          </select>
                          <select value={grantLevel} onChange={(e) => setGrantLevel(e.target.value)}
                            className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-primary/50">
                            <option value="read">Read</option>
                            <option value="admin">Admin</option>
                          </select>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </>
            )}

            {/* ── By User view ── */}
            {adminTab === "by_user" && (
              <>
                {/* User list */}
                <div className="w-64 flex-shrink-0 border-r border-white/10 overflow-y-auto" style={{ maxHeight: 520 }}>
                  {users.map((u) => (
                    <button key={u.id} onClick={() => setSelectedUser(u)}
                      className={`w-full text-left px-4 py-3 border-b border-white/5 hover:bg-white/5 transition-colors ${selectedUser?.id === u.id ? "bg-primary/10 border-l-2 border-l-primary" : ""}`}>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-white truncate">{u.email}</span>
                        {u.is_admin && <span className="text-xs bg-purple-900/40 text-purple-300 border border-purple-700/40 px-1.5 py-0 rounded flex-shrink-0">admin</span>}
                      </div>
                      <div className="text-xs text-gray-500 capitalize">{u.tier}</div>
                    </button>
                  ))}
                </div>

                {/* User access panel */}
                <div className="flex-1 p-5 space-y-4">
                  {!selectedUser ? (
                    <div className="text-gray-500 text-sm flex items-center justify-center h-full">
                      Select a user to manage their access
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <div>
                          <h3 className="text-sm font-semibold text-white">{selectedUser.email}</h3>
                          <div className="text-xs text-gray-400 mt-0.5 capitalize">{selectedUser.tier} · {selectedUser.is_admin ? "Admin" : "User"}</div>
                        </div>
                        <div className="flex gap-2">
                          <select value={grantLevel} onChange={(e) => setGrantLevel(e.target.value)}
                            className="bg-white/5 border border-white/10 rounded-lg px-2 py-1 text-xs text-white focus:outline-none">
                            <option value="read">Read</option>
                            <option value="admin">Admin</option>
                          </select>
                          <button onClick={() => bulkGrant(selectedUser.id, grantLevel)}
                            className="text-xs px-3 py-1.5 bg-primary/20 text-primary hover:bg-primary/30 border border-primary/30 rounded-lg transition-colors">
                            Grant All Clients
                          </button>
                          <button onClick={() => bulkRevoke(selectedUser.id)}
                            className="text-xs px-3 py-1.5 bg-red-900/20 text-red-400 hover:bg-red-900/30 border border-red-700/30 rounded-lg transition-colors">
                            Revoke All
                          </button>
                        </div>
                      </div>

                      {/* Per-client access grid */}
                      <div className="text-xs text-gray-400 uppercase tracking-wider">Client Access</div>
                      <div className="space-y-1.5 overflow-y-auto" style={{ maxHeight: 320 }}>
                        {clients.map((c) => {
                          // Find if this user has access to this client
                          // We'll check by fetching per-client or estimate from clientAccess
                          return (
                            <div key={c.id} className="flex items-center justify-between bg-white/5 rounded-lg px-3 py-2">
                              <div>
                                <div className="text-sm text-white">{c.name}</div>
                                <div className="text-xs text-gray-500">{c.country_code}</div>
                              </div>
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => grantAccess(c.id, selectedUser.id, grantLevel)}
                                  className="text-xs px-2 py-0.5 bg-primary/10 text-primary hover:bg-primary/20 border border-primary/20 rounded transition-colors">
                                  Grant
                                </button>
                                <button
                                  onClick={() => revokeAccess(c.id, selectedUser.id)}
                                  className="text-xs px-2 py-0.5 bg-red-900/10 text-red-400 hover:bg-red-900/20 border border-red-700/20 rounded transition-colors">
                                  Revoke
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between">
        <button
          type="button"
          disabled
          title="Profile & notification settings are not editable in this release"
          className="px-6 py-2.5 bg-white/5 text-gray-500 font-medium rounded-xl cursor-not-allowed">
          Save Changes (coming soon)
        </button>
        <button onClick={logout}
          className="px-6 py-2.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 font-medium rounded-xl border border-red-500/20 transition-colors">
          Sign Out
        </button>
      </div>
    </div>
  );
}
