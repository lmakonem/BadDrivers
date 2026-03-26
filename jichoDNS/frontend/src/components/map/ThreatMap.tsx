"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import dynamic from "next/dynamic";

// Dynamically import the map component to avoid SSR issues with Leaflet
const MapComponent = dynamic(() => import("./LeafletMap"), {
  ssr: false,
  loading: () => (
    <div className="absolute inset-0 bg-gray-900 flex items-center justify-center">
      <div className="text-gray-400">Loading map...</div>
    </div>
  ),
});

export function ThreatMap() {
  const { data: mapData, error } = useQuery({
    queryKey: ["mapData"],
    queryFn: api.getMapData,
    refetchInterval: 60000,
  });

  return (
    <div className="relative w-full h-full min-h-[500px]">
      <MapComponent mapData={mapData} />
      
      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-gray-900/90 backdrop-blur-sm rounded-lg p-3 border border-gray-700 z-[1000]">
        <h4 className="text-xs font-semibold text-gray-300 mb-2">Threat Level</h4>
        <div className="flex items-center gap-2">
          <div className="w-24 h-2 rounded" style={{
            background: "linear-gradient(to right, #1f2937, #22c55e, #eab308, #f97316, #ef4444)"
          }} />
        </div>
        <div className="flex justify-between text-xs text-gray-400 mt-1">
          <span>None</span>
          <span>Critical</span>
        </div>
      </div>

      {error && (
        <div className="absolute top-4 right-4 bg-red-900/90 text-red-300 px-3 py-2 rounded-lg text-sm z-[1000]">
          Failed to load threat data
        </div>
      )}
    </div>
  );
}
