import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Download } from "lucide-react";
import { useMemo } from "react";
import { getAttackColor } from "@/lib/theme";
import { API_BASE_URL } from "@/lib/api";
import { toast } from "sonner";
import { useSource } from "@/components/providers/SourceContext";

interface DetectionScoreCardProps {
  stats: {
    detection_rate?: number;
    total_flows?: number;
    total_alerts?: number;
    benign_flows?: number;
  } | null;
  attackTypes: {
    labels: string[];
    values: number[];
  } | null;
  loading: boolean;
}

interface AlertRow {
  id: number;
  timestamp: string;
  severity: string;
  prediction: string;
  src_ip: string;
  dst_ip: string;
  dst_port?: number;
  protocol?: string;
  confidence: number;
  source_type: string;
}

export default function DetectionScoreCard({ stats, attackTypes, loading }: DetectionScoreCardProps) {
  const { sourceType, activeSite } = useSource();
  const total = stats?.total_flows || 0;
  const detectionRate = total > 0 ? (stats?.detection_rate || 0) : 0;

  const breakdown = useMemo(() => {
    if (!attackTypes) return [];
    return attackTypes.labels.slice(0, 3).map((label, i) => ({
      label,
      pct: total > 0 ? Math.round((attackTypes.values[i] / total) * 100) : 0,
      color: getAttackColor(label),
    }));
  }, [attackTypes, total]);

  if (loading && !stats) {
    return <Skeleton className="h-[280px] w-full rounded-[var(--radius)]" />;
  }

  const handleDownload = async () => {
    const toastId = toast.loading("Preparing report…");
    const scopeLabel = sourceType === "website" ? "website" : "home network";
    try {
      const siteParam = sourceType === "website" && activeSite ? `&registered_id=${activeSite.id}` : "";
      // The API caps page size at 50, so walk the pages to export every alert for this tab
      const MAX_ROWS = 5000;
      const results: AlertRow[] = [];
      let res: Response | null = null;
      for (let page = 1; results.length < MAX_ROWS; page++) {
        res = await fetch(`${API_BASE_URL}/alerts/?source_type=${sourceType}&limit=50&page=${page}${siteParam}`);
        if (!res.ok) break;
        const data = await res.json();
        results.push(...(data.results || []));
        if (!data.next) break;
      }
      if (res?.ok) {
        if (results.length === 0) {
          toast.warning(`No ${scopeLabel} alert data available to download.`, { id: toastId });
          return;
        }
        const headers = [
          "id",
          "timestamp",
          "severity",
          "prediction",
          "src_ip",
          "dst_ip",
          "dst_port",
          "protocol",
          "confidence",
          "source_type",
        ];
        const rows = results.map((a) =>
          [
            a.id,
            a.timestamp,
            a.severity,
            a.prediction,
            a.src_ip,
            a.dst_ip,
            a.dst_port,
            a.protocol,
            a.confidence,
            a.source_type,
          ]
            .map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`)
            .join(","),
        );
        const csv = [headers.join(","), ...rows].join("\n");
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `nexa-${scopeLabel.replace(" ", "-")}-alerts-report-${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        toast.success(`Report downloaded — ${results.length} alerts exported.`, { id: toastId });
      } else {
        toast.error("Failed to fetch alert report data. Check if the backend is running.", { id: toastId });
      }
    } catch (err) {
      console.error(err);
      toast.error("Error downloading report. Please try again.", { id: toastId });
    }
  };

  return (
    <Card className="p-6 shadow-none border-border bg-card flex flex-col">
      <header className="flex items-center justify-between mb-3">
        <h3 className="text-base font-semibold text-foreground">Detection rate</h3>
      </header>

      <p className="text-xs text-muted-foreground mb-4">
        <span className="text-foreground font-semibold tabular-nums">{detectionRate.toFixed(1)}%</span>{" "}
        of flows flagged as threats (alerts ÷ total flows)
      </p>

      <div className="flex items-center gap-5 flex-1">
        <div className="flex-1 space-y-2.5">
          {breakdown.map((b, i) => (
            <div key={`${b.label}-${i}`} className="flex items-center gap-2 text-xs">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: b.color }}
              />
              <span className="text-muted-foreground flex-1 truncate">{b.label}</span>
              <span className="text-foreground font-medium tabular-nums">{b.pct}%</span>
            </div>
          ))}
        </div>

        <RingChart value={Math.min(100, detectionRate)} colors={breakdown.map((b) => b.color)} />
      </div>

      <Button onClick={handleDownload} className="mt-5 h-10 rounded-full bg-foreground text-background hover:bg-foreground/90 gap-2 w-full cursor-pointer">
        <Download className="h-4 w-4" />
        Download report
      </Button>
    </Card>
  );
}

function RingChart({ value, colors = [] }: { value: number; colors?: string[] }) {
  const r1 = 38, r2 = 30, r3 = 22;
  const c = (r: number) => 2 * Math.PI * r;
  const dash = (r: number, pct: number) => `${(c(r) * pct) / 100} ${c(r)}`;

  const [c1, c2, c3] = [
    colors[0] ?? "var(--color-status-info)",
    colors[1] ?? "var(--color-status-medium)",
    colors[2] ?? "var(--color-status-high)",
  ];

  return (
    <svg width="110" height="110" viewBox="0 0 110 110" className="shrink-0">
      <g transform="rotate(-90 55 55)">
        <circle cx="55" cy="55" r={r1} fill="none" stroke="var(--muted)" strokeWidth="6" />
        <circle
          cx="55"
          cy="55"
          r={r1}
          fill="none"
          stroke={c1}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={dash(r1, value)}
        />
        <circle cx="55" cy="55" r={r2} fill="none" stroke="var(--muted)" strokeWidth="6" />
        <circle
          cx="55"
          cy="55"
          r={r2}
          fill="none"
          stroke={c2}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={dash(r2, Math.max(8, value * 0.6))}
        />
        <circle cx="55" cy="55" r={r3} fill="none" stroke="var(--muted)" strokeWidth="6" />
        <circle
          cx="55"
          cy="55"
          r={r3}
          fill="none"
          stroke={c3}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={dash(r3, Math.max(5, value * 0.3))}
        />
      </g>
      <text
        x="55"
        y="58"
        textAnchor="middle"
        className="fill-foreground text-[15px] font-semibold tabular-nums"
      >
        {value.toFixed(0)}%
      </text>
    </svg>
  );
}
