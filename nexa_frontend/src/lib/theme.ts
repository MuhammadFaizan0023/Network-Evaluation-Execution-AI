// NEXA brand palette — driven from CSS custom properties so themes stay in sync.
export const cyberPalette = {
  blue:   "var(--color-status-info)",
  teal:   "var(--color-status-low)",
  amber:  "var(--color-status-medium)",
  orange: "var(--color-status-high)",
  red:    "var(--color-status-critical)",
  purple: "var(--color-cyber-purple)",
};

// Categorical palette for charts where bars/slices need distinct hues
// (independent of semantic meaning). Cycles via getChartColor(index).
export const chartPalette: string[] = [
  "var(--chart-cat-1)", // blue
  "var(--chart-cat-2)", // teal
  "var(--chart-cat-3)", // amber
  "var(--chart-cat-4)", // red
  "var(--chart-cat-5)", // violet
  "var(--chart-cat-6)", // emerald
  "var(--chart-cat-7)", // pink
  "var(--chart-cat-8)", // sky
];

export const getChartColor = (index: number): string =>
  chartPalette[((index % chartPalette.length) + chartPalette.length) % chartPalette.length];

export const severityColors: Record<string, string> = {
  CRITICAL: cyberPalette.red,
  HIGH:     cyberPalette.orange,
  MEDIUM:   cyberPalette.amber,
  LOW:      cyberPalette.teal,
  NORMAL:   cyberPalette.blue,
  // Zero-day: low-confidence IoT predictions flagged as "Unknown" attacks.
  "ZERO-DAY": cyberPalette.purple,
};

export const getAttackColor = (attackType: string): string => {
  const type = attackType.toLowerCase();
  if (type.includes("unknown") || type.includes("zero-day")) return cyberPalette.purple;
  if (type.includes("benign") || type.includes("normal")) return cyberPalette.teal;
  if (type.includes("dos") || type.includes("ddos"))      return cyberPalette.red;
  if (type.includes("bruteforce"))                        return cyberPalette.orange;
  if (type.includes("portscan") || type.includes("scan")) return cyberPalette.amber;
  if (type.includes("sqli") || type.includes("injection")) return cyberPalette.orange;
  if (type.includes("xss"))                                return cyberPalette.amber;
  return cyberPalette.purple;
};
