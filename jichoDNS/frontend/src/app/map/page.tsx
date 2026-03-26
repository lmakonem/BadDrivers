import { ThreatMapLive } from "@/components/map/ThreatMapLive";

export const metadata = {
  title: "Live Threat Map | JichoSec",
  description: "Real-time visualization of cyber threats across Africa and globally",
};

export default function MapPage() {
  return (
    <div className="h-screen w-screen overflow-hidden bg-gray-950">
      <ThreatMapLive />
    </div>
  );
}
