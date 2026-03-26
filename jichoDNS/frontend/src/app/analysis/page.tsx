"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Header } from "@/components/layout/Header";
import { api, DomainAnalysis } from "@/lib/api";
import { getThreatColor, getThreatLabel } from "@/lib/utils";
import { Search, AlertTriangle, CheckCircle, XCircle, Loader2 } from "lucide-react";

export default function AnalysisPage() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState<DomainAnalysis | null>(null);

  const mutation = useMutation({
    mutationFn: (domain: string) => api.analyzeDomain(domain),
    onSuccess: (data) => {
      setResult(data);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (domain.trim()) {
      mutation.mutate(domain.trim());
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1 p-6">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-2xl font-bold text-white mb-2">Domain Analysis</h1>
          <p className="text-gray-400 mb-6">
            Analyze a domain for potential threats using entropy analysis, DGA detection,
            and pattern matching.
          </p>

          {/* Search Form */}
          <form onSubmit={handleSubmit} className="mb-8">
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="Enter domain (e.g., suspicious-domain.com)"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <button
                type="submit"
                disabled={mutation.isPending || !domain.trim()}
                className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors flex items-center gap-2"
              >
                {mutation.isPending ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  "Analyze"
                )}
              </button>
            </div>
          </form>

          {/* Error State */}
          {mutation.isError && (
            <div className="bg-red-900/20 border border-red-800 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-2 text-red-400">
                <XCircle className="w-5 h-5" />
                <span>Error analyzing domain. Please try again.</span>
              </div>
            </div>
          )}

          {/* Results */}
          {result && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
              {/* Header */}
              <div className="p-4 border-b border-gray-800 flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-mono text-white">{result.domain}</h2>
                  <p className="text-sm text-gray-400">Analysis completed</p>
                </div>
                <div className="text-right">
                  <div
                    className="text-2xl font-bold"
                    style={{ color: getThreatColor(result.confidence) }}
                  >
                    {getThreatLabel(result.confidence)}
                  </div>
                  <div className="text-sm text-gray-400">
                    {(result.confidence * 100).toFixed(0)}% confidence
                  </div>
                </div>
              </div>

              {/* Classification */}
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Classification</h3>
                <div className="flex items-center gap-3">
                  {result.classification === "benign" ? (
                    <CheckCircle className="w-6 h-6 text-green-500" />
                  ) : (
                    <AlertTriangle className="w-6 h-6 text-red-500" />
                  )}
                  <span className="text-lg text-white capitalize">{result.classification}</span>
                  {result.is_dga_like && (
                    <span className="px-2 py-1 bg-red-900/30 text-red-400 text-xs rounded">
                      DGA-like
                    </span>
                  )}
                </div>
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 border-b border-gray-800">
                <div>
                  <div className="text-sm text-gray-400">Entropy</div>
                  <div className="text-xl font-semibold text-white">
                    {result.entropy.toFixed(2)}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-400">Length</div>
                  <div className="text-xl font-semibold text-white">{result.length}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-400">DGA Score</div>
                  <div
                    className="text-xl font-semibold"
                    style={{ color: getThreatColor(result.dga_score) }}
                  >
                    {(result.dga_score * 100).toFixed(0)}%
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-400">TLD</div>
                  <div className="text-xl font-semibold text-white">.{result.tld}</div>
                </div>
              </div>

              {/* Character Analysis */}
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-sm font-semibold text-gray-400 mb-3">Character Analysis</h3>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <div className="text-xs text-gray-500">Vowel Ratio</div>
                    <div className="text-lg text-white">
                      {(result.vowel_ratio * 100).toFixed(0)}%
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-500">Consonant Ratio</div>
                    <div className="text-lg text-white">
                      {(result.consonant_ratio * 100).toFixed(0)}%
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-500">Digit Ratio</div>
                    <div className="text-lg text-white">
                      {(result.digit_ratio * 100).toFixed(0)}%
                    </div>
                  </div>
                </div>
              </div>

              {/* Impossible N-grams */}
              {result.impossible_ngrams.length > 0 && (
                <div className="p-4">
                  <h3 className="text-sm font-semibold text-gray-400 mb-2">
                    Suspicious Patterns Detected
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {result.impossible_ngrams.map((ngram, i) => (
                      <span
                        key={i}
                        className="px-2 py-1 bg-red-900/30 text-red-400 text-sm font-mono rounded"
                      >
                        {ngram}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Example Domains */}
          {!result && !mutation.isPending && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Try these examples:</h3>
              <div className="flex flex-wrap gap-2">
                {[
                  "google.com",
                  "xyzqhkjwmvb.net",
                  "login-secure-bank.com",
                  "safaricom-mpesa-verify.xyz",
                  "djsklfjweiojf.ru",
                ].map((example) => (
                  <button
                    key={example}
                    onClick={() => {
                      setDomain(example);
                      mutation.mutate(example);
                    }}
                    className="px-3 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-mono rounded transition-colors"
                  >
                    {example}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
