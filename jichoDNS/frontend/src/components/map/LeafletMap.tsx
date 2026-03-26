"use client";

import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { getThreatColor, getThreatLabel } from "@/lib/utils";

interface MapProps {
  mapData?: GeoJSON.FeatureCollection;
}

export default function LeafletMap({ mapData }: MapProps) {
  const mapRef = useRef<L.Map | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const geoJsonLayerRef = useRef<L.GeoJSON | null>(null);

  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    // Initialize map centered on Africa
    mapRef.current = L.map(containerRef.current, {
      center: [0, 20],
      zoom: 3,
      minZoom: 2,
      maxZoom: 10,
      zoomControl: true,
    });

    // Add dark tile layer (CartoDB Dark Matter - free, no token needed)
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: "abcd",
      maxZoom: 19,
    }).addTo(mapRef.current);

    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, []);

  // Update GeoJSON layer when data changes
  useEffect(() => {
    if (!mapRef.current || !mapData) return;

    // Remove existing layer
    if (geoJsonLayerRef.current) {
      mapRef.current.removeLayer(geoJsonLayerRef.current);
    }

    // Add new GeoJSON layer with circle markers for points
    geoJsonLayerRef.current = L.geoJSON(mapData, {
      pointToLayer: (feature, latlng) => {
        const props = feature.properties;
        const totalThreats = props?.total_threats || 0;
        const riskScore = (props?.risk_score || 0) / 100; // Convert 0-100 to 0-1
        
        // Calculate radius based on threat count (min 8, max 40)
        let radius = 8;
        if (totalThreats > 0) {
          radius = Math.min(40, Math.max(8, Math.log10(totalThreats + 1) * 15));
        }
        
        return L.circleMarker(latlng, {
          radius: radius,
          fillColor: getThreatColor(riskScore),
          color: props?.has_data ? "#fff" : "#374151",
          weight: props?.has_data ? 2 : 1,
          opacity: 1,
          fillOpacity: props?.has_data ? 0.8 : 0.3,
        });
      },
      onEachFeature: (feature, layer) => {
        const props = feature.properties;
        if (props) {
          const popupContent = `
            <div style="color: #fff; background: #1f2937; padding: 12px; border-radius: 8px; min-width: 220px;">
              <h3 style="font-weight: bold; font-size: 16px; margin-bottom: 8px;">${props.country_name || "Unknown"}</h3>
              <p style="color: #9ca3af; margin-bottom: 8px;">Code: ${props.country_code || "N/A"}</p>
              <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                <span>Total Threats:</span>
                <span style="font-weight: bold; color: ${getThreatColor((props.risk_score || 0) / 100)}">${(props.total_threats || 0).toLocaleString()}</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                <span>C2:</span>
                <span style="color: #f97316">${(props.c2_count || 0).toLocaleString()}</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                <span>Malware:</span>
                <span style="color: #ef4444">${(props.malware_count || 0).toLocaleString()}</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                <span>Phishing:</span>
                <span style="color: #a855f7">${(props.phishing_count || 0).toLocaleString()}</span>
              </div>
              <div style="border-top: 1px solid #374151; margin-top: 8px; padding-top: 8px; display: flex; justify-content: space-between; font-weight: bold;">
                <span>Risk Score:</span>
                <span style="color: ${getThreatColor((props.risk_score || 0) / 100)}">${getThreatLabel((props.risk_score || 0) / 100)}</span>
              </div>
            </div>
          `;
          layer.bindPopup(popupContent, {
            className: "dark-popup",
          });
        }
      },
    }).addTo(mapRef.current);
  }, [mapData]);

  return (
    <>
      <style jsx global>{`
        .dark-popup .leaflet-popup-content-wrapper {
          background: transparent;
          box-shadow: none;
          padding: 0;
        }
        .dark-popup .leaflet-popup-content {
          margin: 0;
        }
        .dark-popup .leaflet-popup-tip {
          background: #1f2937;
        }
        .leaflet-container {
          background: #111827;
        }
      `}</style>
      <div ref={containerRef} className="absolute inset-0" />
    </>
  );
}
