// All African countries with coordinates
export const AFRICAN_COUNTRIES: Record<string, { lat: number; lon: number; name: string }> = {
  // North Africa
  DZ: { lat: 28.03, lon: 1.66, name: "Algeria" },
  EG: { lat: 26.82, lon: 30.80, name: "Egypt" },
  LY: { lat: 26.34, lon: 17.23, name: "Libya" },
  MA: { lat: 31.79, lon: -7.09, name: "Morocco" },
  SD: { lat: 12.86, lon: 30.22, name: "Sudan" },
  TN: { lat: 33.89, lon: 9.54, name: "Tunisia" },
  EH: { lat: 24.22, lon: -12.89, name: "Western Sahara" },
  // West Africa
  BJ: { lat: 9.31, lon: 2.32, name: "Benin" },
  BF: { lat: 12.24, lon: -1.56, name: "Burkina Faso" },
  CV: { lat: 16.00, lon: -24.01, name: "Cape Verde" },
  CI: { lat: 7.54, lon: -5.55, name: "Ivory Coast" },
  GM: { lat: 13.44, lon: -15.31, name: "Gambia" },
  GH: { lat: 7.95, lon: -1.02, name: "Ghana" },
  GN: { lat: 9.95, lon: -9.70, name: "Guinea" },
  GW: { lat: 11.80, lon: -15.18, name: "Guinea-Bissau" },
  LR: { lat: 6.43, lon: -9.43, name: "Liberia" },
  ML: { lat: 17.57, lon: -4.00, name: "Mali" },
  MR: { lat: 21.01, lon: -10.94, name: "Mauritania" },
  NE: { lat: 17.61, lon: 8.08, name: "Niger" },
  NG: { lat: 9.08, lon: 8.68, name: "Nigeria" },
  SN: { lat: 14.50, lon: -14.45, name: "Senegal" },
  SL: { lat: 8.46, lon: -11.78, name: "Sierra Leone" },
  TG: { lat: 8.62, lon: 0.82, name: "Togo" },
  // Central Africa
  AO: { lat: -11.20, lon: 17.87, name: "Angola" },
  CM: { lat: 7.37, lon: 12.35, name: "Cameroon" },
  CF: { lat: 6.61, lon: 20.94, name: "Central African Republic" },
  TD: { lat: 15.45, lon: 18.73, name: "Chad" },
  CG: { lat: -0.23, lon: 15.83, name: "Congo" },
  CD: { lat: -4.04, lon: 21.76, name: "DR Congo" },
  GQ: { lat: 1.65, lon: 10.27, name: "Equatorial Guinea" },
  GA: { lat: -0.80, lon: 11.61, name: "Gabon" },
  ST: { lat: 0.19, lon: 6.61, name: "Sao Tome and Principe" },
  // East Africa
  BI: { lat: -3.37, lon: 29.92, name: "Burundi" },
  KM: { lat: -11.88, lon: 43.87, name: "Comoros" },
  DJ: { lat: 11.83, lon: 42.59, name: "Djibouti" },
  ER: { lat: 15.18, lon: 39.78, name: "Eritrea" },
  ET: { lat: 9.15, lon: 40.49, name: "Ethiopia" },
  KE: { lat: -0.02, lon: 37.91, name: "Kenya" },
  MG: { lat: -18.77, lon: 46.87, name: "Madagascar" },
  MW: { lat: -13.25, lon: 34.30, name: "Malawi" },
  MU: { lat: -20.35, lon: 57.55, name: "Mauritius" },
  MZ: { lat: -18.67, lon: 35.53, name: "Mozambique" },
  RW: { lat: -1.94, lon: 29.87, name: "Rwanda" },
  SC: { lat: -4.68, lon: 55.49, name: "Seychelles" },
  SO: { lat: 5.15, lon: 46.20, name: "Somalia" },
  SS: { lat: 6.88, lon: 31.31, name: "South Sudan" },
  TZ: { lat: -6.37, lon: 34.89, name: "Tanzania" },
  UG: { lat: 1.37, lon: 32.29, name: "Uganda" },
  ZM: { lat: -13.13, lon: 27.85, name: "Zambia" },
  ZW: { lat: -19.02, lon: 29.15, name: "Zimbabwe" },
  // Southern Africa
  BW: { lat: -22.33, lon: 24.68, name: "Botswana" },
  LS: { lat: -29.61, lon: 28.23, name: "Lesotho" },
  NA: { lat: -22.96, lon: 18.49, name: "Namibia" },
  ZA: { lat: -30.56, lon: 22.94, name: "South Africa" },
  SZ: { lat: -26.52, lon: 31.47, name: "Eswatini" },
};

// Global countries (potential attack sources from anywhere in the world)
export const GLOBAL_COUNTRIES: Record<string, { lat: number; lon: number; name: string }> = {
  // North America
  US: { lat: 37.09, lon: -95.71, name: "United States" },
  CA: { lat: 56.13, lon: -106.35, name: "Canada" },
  MX: { lat: 23.63, lon: -102.55, name: "Mexico" },
  // Central America & Caribbean
  PA: { lat: 8.54, lon: -80.78, name: "Panama" },
  CR: { lat: 9.75, lon: -83.75, name: "Costa Rica" },
  CU: { lat: 21.52, lon: -77.78, name: "Cuba" },
  JM: { lat: 18.11, lon: -77.30, name: "Jamaica" },
  // South America
  BR: { lat: -14.24, lon: -51.93, name: "Brazil" },
  AR: { lat: -38.42, lon: -63.62, name: "Argentina" },
  CL: { lat: -35.68, lon: -71.54, name: "Chile" },
  CO: { lat: 4.57, lon: -74.30, name: "Colombia" },
  VE: { lat: 6.42, lon: -66.59, name: "Venezuela" },
  PE: { lat: -9.19, lon: -75.02, name: "Peru" },
  EC: { lat: -1.83, lon: -78.18, name: "Ecuador" },
  UY: { lat: -32.52, lon: -55.77, name: "Uruguay" },
  PY: { lat: -23.44, lon: -58.44, name: "Paraguay" },
  BO: { lat: -16.29, lon: -63.59, name: "Bolivia" },
  // Western Europe
  GB: { lat: 55.38, lon: -3.44, name: "United Kingdom" },
  DE: { lat: 51.17, lon: 10.45, name: "Germany" },
  FR: { lat: 46.23, lon: 2.21, name: "France" },
  NL: { lat: 52.13, lon: 5.29, name: "Netherlands" },
  BE: { lat: 50.50, lon: 4.47, name: "Belgium" },
  ES: { lat: 40.46, lon: -3.75, name: "Spain" },
  PT: { lat: 39.40, lon: -8.22, name: "Portugal" },
  IT: { lat: 41.87, lon: 12.57, name: "Italy" },
  CH: { lat: 46.82, lon: 8.23, name: "Switzerland" },
  AT: { lat: 47.52, lon: 14.55, name: "Austria" },
  IE: { lat: 53.14, lon: -7.69, name: "Ireland" },
  SE: { lat: 60.13, lon: 18.64, name: "Sweden" },
  NO: { lat: 60.47, lon: 8.47, name: "Norway" },
  DK: { lat: 56.26, lon: 9.50, name: "Denmark" },
  FI: { lat: 61.92, lon: 25.75, name: "Finland" },
  GR: { lat: 39.07, lon: 21.82, name: "Greece" },
  // Eastern Europe
  RU: { lat: 61.52, lon: 105.32, name: "Russia" },
  UA: { lat: 48.38, lon: 31.17, name: "Ukraine" },
  PL: { lat: 51.92, lon: 19.15, name: "Poland" },
  RO: { lat: 45.94, lon: 24.97, name: "Romania" },
  CZ: { lat: 49.82, lon: 15.47, name: "Czech Republic" },
  HU: { lat: 47.16, lon: 19.50, name: "Hungary" },
  BG: { lat: 42.73, lon: 25.49, name: "Bulgaria" },
  BY: { lat: 53.71, lon: 27.95, name: "Belarus" },
  SK: { lat: 48.67, lon: 19.70, name: "Slovakia" },
  RS: { lat: 44.02, lon: 21.01, name: "Serbia" },
  HR: { lat: 45.10, lon: 15.20, name: "Croatia" },
  LT: { lat: 55.17, lon: 23.88, name: "Lithuania" },
  LV: { lat: 56.88, lon: 24.60, name: "Latvia" },
  EE: { lat: 58.60, lon: 25.01, name: "Estonia" },
  MD: { lat: 47.41, lon: 28.37, name: "Moldova" },
  // Middle East
  IR: { lat: 32.43, lon: 53.69, name: "Iran" },
  TR: { lat: 38.96, lon: 35.24, name: "Turkey" },
  SA: { lat: 23.89, lon: 45.08, name: "Saudi Arabia" },
  AE: { lat: 23.42, lon: 53.85, name: "UAE" },
  IL: { lat: 31.05, lon: 34.85, name: "Israel" },
  IQ: { lat: 33.22, lon: 43.68, name: "Iraq" },
  SY: { lat: 34.80, lon: 39.00, name: "Syria" },
  JO: { lat: 30.59, lon: 36.24, name: "Jordan" },
  LB: { lat: 33.85, lon: 35.86, name: "Lebanon" },
  KW: { lat: 29.31, lon: 47.48, name: "Kuwait" },
  QA: { lat: 25.35, lon: 51.18, name: "Qatar" },
  BH: { lat: 26.07, lon: 50.56, name: "Bahrain" },
  OM: { lat: 21.47, lon: 55.98, name: "Oman" },
  YE: { lat: 15.55, lon: 48.52, name: "Yemen" },
  // Central Asia
  KZ: { lat: 48.02, lon: 66.92, name: "Kazakhstan" },
  UZ: { lat: 41.38, lon: 64.59, name: "Uzbekistan" },
  TM: { lat: 38.97, lon: 59.56, name: "Turkmenistan" },
  KG: { lat: 41.20, lon: 74.77, name: "Kyrgyzstan" },
  TJ: { lat: 38.86, lon: 71.28, name: "Tajikistan" },
  AF: { lat: 33.94, lon: 67.71, name: "Afghanistan" },
  // South Asia
  IN: { lat: 20.59, lon: 78.96, name: "India" },
  PK: { lat: 30.38, lon: 69.35, name: "Pakistan" },
  BD: { lat: 23.68, lon: 90.36, name: "Bangladesh" },
  LK: { lat: 7.87, lon: 80.77, name: "Sri Lanka" },
  NP: { lat: 28.39, lon: 84.12, name: "Nepal" },
  // East Asia
  CN: { lat: 35.86, lon: 104.19, name: "China" },
  JP: { lat: 36.20, lon: 138.25, name: "Japan" },
  KR: { lat: 35.91, lon: 127.77, name: "South Korea" },
  KP: { lat: 40.34, lon: 127.51, name: "North Korea" },
  TW: { lat: 23.70, lon: 121.00, name: "Taiwan" },
  MN: { lat: 46.86, lon: 103.85, name: "Mongolia" },
  HK: { lat: 22.40, lon: 114.11, name: "Hong Kong" },
  // Southeast Asia
  VN: { lat: 14.06, lon: 108.28, name: "Vietnam" },
  TH: { lat: 15.87, lon: 100.99, name: "Thailand" },
  ID: { lat: -0.79, lon: 113.92, name: "Indonesia" },
  MY: { lat: 4.21, lon: 101.98, name: "Malaysia" },
  SG: { lat: 1.35, lon: 103.82, name: "Singapore" },
  PH: { lat: 12.88, lon: 121.77, name: "Philippines" },
  MM: { lat: 21.91, lon: 95.96, name: "Myanmar" },
  KH: { lat: 12.57, lon: 104.99, name: "Cambodia" },
  LA: { lat: 19.86, lon: 102.50, name: "Laos" },
  // Oceania
  AU: { lat: -25.27, lon: 133.78, name: "Australia" },
  NZ: { lat: -40.90, lon: 174.89, name: "New Zealand" },
  FJ: { lat: -17.71, lon: 178.07, name: "Fiji" },
  PG: { lat: -6.31, lon: 143.96, name: "Papua New Guinea" },
};

// Combined coords for lookups (African + Global)
export const COUNTRY_COORDS: Record<string, { lat: number; lon: number; name: string }> = {
  ...AFRICAN_COUNTRIES,
  ...GLOBAL_COUNTRIES,
};

// List of African country codes
export const AFRICAN_TARGETS = Object.keys(AFRICAN_COUNTRIES);

// Attackers can come from anywhere: global countries + African countries (for Africa-to-Africa attacks)
export const ATTACKER_CODES = [...Object.keys(GLOBAL_COUNTRIES), ...Object.keys(AFRICAN_COUNTRIES)];

// Sorted list for UI display
export const AFRICAN_COUNTRY_LIST = Object.entries(AFRICAN_COUNTRIES)
  .map(([code, data]) => ({
    code,
    name: data.name,
  }))
  .sort((a, b) => a.name.localeCompare(b.name));
