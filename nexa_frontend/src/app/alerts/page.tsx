"use client";

import { Suspense, useState, useMemo, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { format, formatDistanceToNow } from "date-fns";
import {
  ShieldAlert,
  Search,
  X,
  Clock,
  ArrowRight,
  Network,
  Target,
  Cpu,
  Ban,
  Check,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";
import { toast } from "sonner";

import { useDashboardData } from "@/hooks/useDashboardData";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { severityColors, getAttackColor, cyberPalette } from "@/lib/theme";
import { API_BASE_URL } from "@/lib/api";
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from "@/components/ui/tooltip";

interface AlertResult {
  id: number | string;
  timestamp: string;
  prediction: string;
  severity: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  confidence: number;
  source_type: string;
  recommended_action?: string;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NORMAL"] as const;

const protocolName = (p: number) => {
  const map: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP", 51: "AH" };
  return map[p] || `Proto ${p}`;
};

export default function AlertsPage() {
  return (
    <Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <AlertsPageInner />
    </Suspense>
  );
}

function AlertsPageInner() {
  // "all" shows every classified flow (benign + threats); "threats" keeps the
  // original alerts-only feed. Default to all so benign traffic is visible.
  const [trafficView, setTrafficView] = useState<"all" | "threats">("all");
  const { alerts, loading, page, setPage, pageSize, setPageSize } = useDashboardData({
    includeBenign: trafficView === "all",
  });
  const searchParams = useSearchParams();

  // Seed filters from URL once on mount (deep links from other pages).
  // We don't re-sync if the user changes filters interactively — URL stays out of date,
  // but state is the source of truth.
  const initialSearch =
    searchParams.get("search") ||
    searchParams.get("src_ip") ||
    searchParams.get("dst_ip") ||
    "";
  const initialSeverity = searchParams.get("severity")?.toUpperCase() || "ALL";
  const initialAttack = searchParams.get("prediction") || "ALL";

  const [search, setSearch] = useState(initialSearch);
  const [severityFilter, setSeverityFilter] = useState<string>(initialSeverity);
  const [attackFilter, setAttackFilter] = useState<string>(initialAttack);
  const [selected, setSelected] = useState<AlertResult | null>(null);

  const [blockedIps, setBlockedIps] = useState<string[]>([]);
  const [whitelistedIps, setWhitelistedIps] = useState<string[]>([]);

  // Confirmation dialog state
  const [confirmAction, setConfirmAction] = useState<{
    type: "block" | "whitelist" | "unblock" | "removeWhitelist";
    ip: string;
  } | null>(null);

  // Seed blocked and whitelisted IPs from API response on load
  useEffect(() => {
    if (alerts) {
      const rawAlerts = alerts as unknown as { blocked_ips?: string[]; whitelisted_ips?: string[] };
      setBlockedIps(rawAlerts.blocked_ips || []);
      setWhitelistedIps(rawAlerts.whitelisted_ips || []);
    }
  }, [alerts]);

  const handleBlock = async (ip: string) => {
    setBlockedIps((prev) => [...prev, ip]);
    setWhitelistedIps((prev) => prev.filter((x) => x !== ip));
    const toastId = toast.loading("Applying block rule…", {
      description: `Targeting IP address ${ip}`
    });
    try {
      const res = await fetch(`${API_BASE_URL}/block/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      if (!res.ok) throw new Error();
      toast.success("IP Address Blocked", {
        id: toastId,
        description: `${ip} has been blocked and traffic dropped.`
      });
    } catch {
      setBlockedIps((prev) => prev.filter((x) => x !== ip));
      toast.error("Action Failed", {
        id: toastId,
        description: `Failed to block ${ip}. Check the backend connection.`
      });
    }
  };

  const handleUnblock = async (ip: string) => {
    setBlockedIps((prev) => prev.filter((x) => x !== ip));
    const toastId = toast.loading("Removing block rule…", {
      description: `Targeting IP address ${ip}`
    });
    try {
      const res = await fetch(`${API_BASE_URL}/unblock/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      if (!res.ok) throw new Error();
      toast.success("IP Address Unblocked", {
        id: toastId,
        description: `Traffic restored successfully for ${ip}.`
      });
    } catch {
      setBlockedIps((prev) => [...prev, ip]);
      toast.error("Action Failed", {
        id: toastId,
        description: `Failed to unblock ${ip}. Check the backend connection.`
      });
    }
  };

  const handleWhitelist = async (ip: string) => {
    setWhitelistedIps((prev) => [...prev, ip]);
    setBlockedIps((prev) => prev.filter((x) => x !== ip));
    const toastId = toast.loading("Adding to whitelist…", {
      description: `Targeting IP address ${ip}`
    });
    try {
      const res = await fetch(`${API_BASE_URL}/whitelist/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      if (!res.ok) throw new Error();
      toast.success("IP Whitelisted", {
        id: toastId,
        description: `Future alerts from ${ip} will be suppressed.`
      });
    } catch {
      setWhitelistedIps((prev) => prev.filter((x) => x !== ip));
      toast.error("Action Failed", {
        id: toastId,
        description: `Failed to whitelist ${ip}. Check the backend connection.`
      });
    }
  };

  const handleRemoveWhitelist = async (ip: string) => {
    setWhitelistedIps((prev) => prev.filter((x) => x !== ip));
    const toastId = toast.loading("Removing from whitelist…", {
      description: `Targeting IP address ${ip}`
    });
    try {
      const res = await fetch(`${API_BASE_URL}/whitelist/?ip=${encodeURIComponent(ip)}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error();
      toast.success("Whitelist Removed", {
        id: toastId,
        description: `${ip} removed. Alerts will resume.`
      });
    } catch {
      setWhitelistedIps((prev) => [...prev, ip]);
      toast.error("Action Failed", {
        id: toastId,
        description: `Failed to remove whitelist for ${ip}.`
      });
    }
  };

  // Dispatch confirmed action
  const executeConfirmedAction = () => {
    if (!confirmAction) return;
    const { type, ip } = confirmAction;
    setConfirmAction(null);
    if (type === "block") handleBlock(ip);
    else if (type === "unblock") handleUnblock(ip);
    else if (type === "whitelist") handleWhitelist(ip);
    else if (type === "removeWhitelist") handleRemoveWhitelist(ip);
  };

  // Unique attack types in current page (for filter dropdown) — trim to collapse
  // whitespace variants the ML pipeline may produce.
  const attackTypes = useMemo(() => {
    if (!alerts) return [];
    const set = new Set(alerts.results.map((a) => a.prediction.trim()).filter(Boolean));
    return Array.from(set).sort();
  }, [alerts]);

  // Apply client-side filters to current page
  const filtered = useMemo(() => {
    if (!alerts) return [];
    return alerts.results.filter((a) => {
      if (severityFilter !== "ALL" && a.severity.toUpperCase() !== severityFilter) return false;
      if (attackFilter !== "ALL" && a.prediction !== attackFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        if (
          !a.src_ip.toLowerCase().includes(q) &&
          !a.dst_ip.toLowerCase().includes(q) &&
          !a.prediction.toLowerCase().includes(q)
        )
          return false;
      }
      return true;
    });
  }, [alerts, severityFilter, attackFilter, search]);

  const clearFilters = () => {
    setSearch("");
    setSeverityFilter("ALL");
    setAttackFilter("ALL");
  };
  const hasFilters = search !== "" || severityFilter !== "ALL" || attackFilter !== "ALL";

  return (
    <div className="flex flex-col gap-6">
      {/* Page header */}
      <header className="flex items-baseline justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Alerts</h1>
          <p className="text-sm text-muted-foreground mt-1">
            {alerts ? (
              <>
                <span className="text-foreground font-medium tabular-nums">
                  {alerts.count.toLocaleString()}
                </span>{" "}
                total {trafficView === "all" ? "flows" : "alerts"} ingested · showing page {page} ({filtered.length} after filters)
              </>
            ) : (
              "Loading alerts feed…"
            )}
          </p>
        </div>
        {hasFilters && (
          <Button variant="outline" size="sm" onClick={clearFilters} className="h-8 gap-1.5">
            <X className="h-3.5 w-3.5" /> Clear filters
          </Button>
        )}
      </header>

      {/* Active Rules Status Bar */}
      {(blockedIps.length > 0 || whitelistedIps.length > 0) && (
        <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 rounded-xl border border-border/80 bg-muted/20 text-xs">
          {blockedIps.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="font-semibold text-muted-foreground">Blocked IPs:</span>
              {blockedIps.map((ip) => (
                <span
                  key={ip}
                  className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-red-500/10 text-red-500 border border-red-500/20 font-mono text-[11px]"
                >
                  {ip}
                  <button
                    onClick={() => setConfirmAction({ type: "unblock", ip })}
                    className="hover:bg-red-500/20 rounded-full p-0.5 transition-colors"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
          {blockedIps.length > 0 && whitelistedIps.length > 0 && (
            <div className="h-4 w-[1px] bg-border/80 hidden sm:block" />
          )}
          {whitelistedIps.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="font-semibold text-muted-foreground">Whitelisted IPs:</span>
              {whitelistedIps.map((ip) => (
                <span
                  key={ip}
                  className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 font-mono text-[11px]"
                >
                  {ip}
                  <button
                    onClick={() => setConfirmAction({ type: "removeWhitelist", ip })}
                    className="hover:bg-emerald-500/20 rounded-full p-0.5 transition-colors"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Filter bar */}
      <Card className="p-3 shadow-none border-border bg-card rounded-2xl">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 w-full">
          <div className="relative w-full sm:w-[420px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search source IP, destination IP, or attack type…"
              className="pl-9 h-9 rounded-full border-border bg-background"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto sm:justify-end">
            <div className="w-[150px] shrink-0">
              <Select
                value={trafficView}
                onValueChange={(v) => {
                  setTrafficView(v as "all" | "threats");
                  setPage(1);
                }}
              >
                <SelectTrigger className="h-9 rounded-full border-border bg-background text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All traffic</SelectItem>
                  <SelectItem value="threats">Threats only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="w-[140px] shrink-0">
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="h-9 rounded-full border-border bg-background text-xs">
                  <SelectValue placeholder="All severities" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">All severities</SelectItem>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      <span className="inline-flex items-center gap-2">
                        <span
                          className="h-2 w-2 rounded-full"
                          style={{ backgroundColor: severityColors[s] }}
                        />
                        {s}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="w-[150px] shrink-0">
              <Select value={attackFilter} onValueChange={setAttackFilter}>
                <SelectTrigger className="h-9 rounded-full border-border bg-background text-xs">
                  <SelectValue placeholder="All attack types" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">All attack types</SelectItem>
                  {attackTypes.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="w-[80px] shrink-0">
              <Select
                value={String(pageSize)}
                onValueChange={(v) => {
                  setPageSize(Number(v));
                  setPage(1);
                }}
              >
                <SelectTrigger className="h-9 rounded-full border-border bg-background text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="10">10</SelectItem>
                  <SelectItem value="25">25</SelectItem>
                  <SelectItem value="50">50</SelectItem>
                  <SelectItem value="100">100</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>
      </Card>

      {/* Alerts table */}
      <Card className="shadow-none border-border bg-card overflow-hidden">
        {loading && !alerts ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-border">
                <TableHead className="h-10 text-xs font-medium text-muted-foreground bg-muted/40">
                  When
                </TableHead>
                <TableHead className="h-10 text-xs font-medium text-muted-foreground bg-muted/40">
                  Severity
                </TableHead>
                <TableHead className="h-10 text-xs font-medium text-muted-foreground bg-muted/40">
                  Attack
                </TableHead>
                <TableHead className="h-10 text-xs font-medium text-muted-foreground bg-muted/40">
                  Source → Destination
                </TableHead>
                <TableHead className="h-10 text-xs font-medium text-muted-foreground bg-muted/40">
                  Confidence
                </TableHead>
                <TableHead className="h-10 text-xs font-medium text-muted-foreground bg-muted/40">
                  Recommended Actions
                </TableHead>
                <TableHead className="h-10 text-xs font-medium text-muted-foreground bg-muted/40" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-24 text-center text-sm text-muted-foreground">
                    No records match the current filters.
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((alert) => {
                  const severity = alert.severity.toUpperCase();
                  const sColor = severityColors[severity] || cyberPalette.red;
                  const aColor = getAttackColor(alert.prediction);
                  const isBlocked = blockedIps.includes(alert.src_ip);
                  const isWhitelisted = whitelistedIps.includes(alert.src_ip);
                  return (
                    <TableRow
                      key={alert.id}
                      className="border-border hover:bg-accent/50 cursor-pointer"
                      onClick={() => setSelected(alert)}
                    >
                      <TableCell className="py-3">
                        <span className="text-xs text-muted-foreground">
                          {(() => {
                            try {
                              return formatDistanceToNow(new Date(alert.timestamp), {
                                addSuffix: true,
                              });
                            } catch {
                              return alert.timestamp;
                            }
                          })()}
                        </span>
                      </TableCell>
                      <TableCell className="py-3">
                        <span
                          className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-white"
                          style={{ backgroundColor: sColor }}
                        >
                          {severity}
                        </span>
                      </TableCell>
                      <TableCell className="py-3">
                        <div className="flex items-center gap-2">
                          <span
                            className="h-2 w-2 rounded-full shrink-0"
                            style={{ backgroundColor: aColor }}
                          />
                          <span className="text-sm font-medium text-foreground">
                            {alert.prediction}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="py-3">
                        <span className="font-mono text-xs text-foreground">
                          {alert.src_ip}
                          <ArrowRight className="inline h-3 w-3 mx-1.5 text-muted-foreground" />
                          {alert.dst_ip}:
                          <span className="text-muted-foreground">{alert.dst_port}</span>
                        </span>
                      </TableCell>
                      <TableCell className="py-3">
                        <span
                          className="text-sm font-semibold tabular-nums"
                          style={{ color: sColor }}
                        >
                          {((alert.confidence || 0) * 100).toFixed(1)}%
                        </span>
                      </TableCell>
                      <TableCell className="py-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1.5">
                          {isBlocked ? (
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button
                                    size="icon"
                                    variant="outline"
                                    onClick={() => setConfirmAction({ type: "unblock", ip: alert.src_ip })}
                                    className="h-7 w-7 rounded-full bg-emerald-500/10 text-emerald-500 border-emerald-500/20 hover:bg-emerald-500/20"
                                  >
                                    <Check className="h-3.5 w-3.5" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent className="text-xs">
                                  IP Blocked. Click to Unblock / Restore device.
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          ) : (
                            <>
                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button
                                      size="icon"
                                      variant="outline"
                                      onClick={() => setConfirmAction({ type: "block", ip: alert.src_ip })}
                                      className="h-7 w-7 rounded-full bg-red-500/10 text-red-500 border-red-500/20 hover:bg-red-500/20"
                                    >
                                      <Ban className="h-3.5 w-3.5" />
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent className="text-xs">
                                    Block this IP from the network instantly.
                                  </TooltipContent>
                                </Tooltip>
                              </TooltipProvider>

                              <TooltipProvider>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button
                                      size="icon"
                                      variant="outline"
                                      disabled={isWhitelisted}
                                      onClick={() => !isWhitelisted && setConfirmAction({ type: "whitelist", ip: alert.src_ip })}
                                      className={`h-7 w-7 rounded-full ${
                                        isWhitelisted 
                                          ? "bg-muted text-muted-foreground border-border" 
                                          : "bg-muted/40 text-foreground/70 border-border/80 hover:bg-muted"
                                      }`}
                                    >
                                      {isWhitelisted ? (
                                        <Check className="h-3.5 w-3.5 text-emerald-500" />
                                      ) : (
                                        <ShieldCheck className="h-3.5 w-3.5" />
                                      )}
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent className="text-xs">
                                    {isWhitelisted ? "This IP is whitelisted" : "Whitelist IP to suppress future alerts."}
                                  </TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                            </>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="py-3 text-right">
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 px-2.5 text-xs font-medium"
                        >
                          Details
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        )}
      </Card>

      {/* Pagination */}
      {alerts && alerts.count > pageSize && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground tabular-nums">
            Page {page} of {Math.ceil(alerts.count / pageSize)}
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page >= Math.ceil(alerts.count / pageSize)}
              onClick={() => setPage(page + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      )}

      {/* Alert detail dialog */}
      <AlertDetailDialog alert={selected} onClose={() => setSelected(null)} />

      {/* Confirmation dialog for destructive actions */}
      <Dialog open={!!confirmAction} onOpenChange={(open) => !open && setConfirmAction(null)}>
        <DialogContent className="max-w-sm border-border bg-card rounded-2xl p-6">
          <DialogHeader className="space-y-3">
            <div className="flex items-center gap-3">
              <div className={`h-10 w-10 rounded-full grid place-items-center ${
                confirmAction?.type === "block" ? "bg-red-500/10" :
                confirmAction?.type === "whitelist" ? "bg-emerald-500/10" :
                "bg-muted"
              }`}>
                <AlertTriangle className={`h-5 w-5 ${
                  confirmAction?.type === "block" ? "text-red-500" :
                  confirmAction?.type === "whitelist" ? "text-emerald-500" :
                  "text-muted-foreground"
                }`} />
              </div>
              <div>
                <DialogTitle className="text-base font-semibold text-foreground">
                  {confirmAction?.type === "block" && "Block IP Address"}
                  {confirmAction?.type === "unblock" && "Unblock IP Address"}
                  {confirmAction?.type === "whitelist" && "Whitelist IP Address"}
                  {confirmAction?.type === "removeWhitelist" && "Remove from Whitelist"}
                </DialogTitle>
              </div>
            </div>
          </DialogHeader>
          <p className="text-sm text-muted-foreground mt-1">
            {confirmAction?.type === "block" && (
              <>Drop all traffic from <span className="font-mono font-semibold text-foreground">{confirmAction.ip}</span>? A firewall rule will be applied immediately.</>)}
            {confirmAction?.type === "unblock" && (
              <>Restore traffic from <span className="font-mono font-semibold text-foreground">{confirmAction?.ip}</span>? The firewall block rule will be removed.</>)}
            {confirmAction?.type === "whitelist" && (
              <>Suppress all future alerts from <span className="font-mono font-semibold text-foreground">{confirmAction.ip}</span>? This IP will be treated as trusted.</>)}
            {confirmAction?.type === "removeWhitelist" && (
              <>Remove <span className="font-mono font-semibold text-foreground">{confirmAction?.ip}</span> from the whitelist? Alerts will resume.</>)}
          </p>
          <div className="flex justify-end gap-2 mt-4">
            <Button variant="ghost" onClick={() => setConfirmAction(null)} className="rounded-full h-8 px-4 text-xs">
              Cancel
            </Button>
            <Button
              onClick={executeConfirmedAction}
              className={`rounded-full h-8 px-4 text-xs text-white ${
                confirmAction?.type === "block" ? "bg-red-500 hover:bg-red-600" :
                confirmAction?.type === "whitelist" ? "bg-emerald-600 hover:bg-emerald-700" :
                "bg-foreground hover:bg-foreground/90 text-background"
              }`}
            >
              {confirmAction?.type === "block" && "Yes, Block IP"}
              {confirmAction?.type === "unblock" && "Yes, Unblock IP"}
              {confirmAction?.type === "whitelist" && "Yes, Whitelist IP"}
              {confirmAction?.type === "removeWhitelist" && "Yes, Remove"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function AlertDetailDialog({
  alert,
  onClose,
}: {
  alert: AlertResult | null;
  onClose: () => void;
}) {


  if (!alert) return null;
  const severity = alert.severity.toUpperCase();
  const sColor = severityColors[severity] || cyberPalette.red;
  const aColor = getAttackColor(alert.prediction);

  let timeAbsolute = alert.timestamp;
  let timeRelative = "";
  try {
    timeAbsolute = format(new Date(alert.timestamp), "PPpp");
    timeRelative = formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true });
  } catch {
    /* ignore */
  }



  return (
    <Dialog open={!!alert} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader className="space-y-3">
          <div className="flex items-center gap-3">
            <div
              className="h-12 w-12 rounded-full text-white grid place-items-center shadow-sm"
              style={{ backgroundColor: sColor }}
            >
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div className="flex-1 min-w-0">
              <DialogTitle className="text-lg font-semibold leading-tight">
                {alert.prediction}
              </DialogTitle>
              <div className="flex items-center gap-2 mt-1">
                <span
                  className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-white"
                  style={{ backgroundColor: sColor }}
                >
                  {severity}
                </span>
                <span className="text-xs text-muted-foreground">
                  Alert <span className="font-mono">#{alert.id}</span>
                </span>
              </div>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-5 pt-2">
          {/* Time */}
          <DetailRow icon={Clock} label="Detected">
            <div className="text-sm text-foreground">{timeAbsolute}</div>
            {timeRelative && (
              <div className="text-xs text-muted-foreground mt-0.5">{timeRelative}</div>
            )}
          </DetailRow>

          {/* Network */}
          <DetailRow icon={Network} label="Network">
            <div className="flex items-center gap-2 flex-wrap text-sm font-mono">
              <span className="text-foreground">{alert.src_ip}</span>
              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-foreground">
                {alert.dst_ip}
                <span className="text-muted-foreground">:{alert.dst_port}</span>
              </span>
              <span className="text-xs text-muted-foreground ml-2">
                ({protocolName(alert.protocol)})
              </span>
            </div>
          </DetailRow>

          {/* Attack classification */}
          <DetailRow icon={Target} label="Classification">
            <div className="flex items-center gap-2">
              <span
                className="h-2 w-2 rounded-full shrink-0"
                style={{ backgroundColor: aColor }}
              />
              <span className="text-sm font-medium text-foreground">{alert.prediction}</span>
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              Source channel: <span className="text-foreground">{alert.source_type}</span>
            </div>
          </DetailRow>

          {/* Confidence */}
          <DetailRow icon={Cpu} label="Model confidence">
            <div className="flex items-center gap-3">
              <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${(alert.confidence || 0) * 100}%`,
                    backgroundColor: sColor,
                  }}
                />
              </div>
              <span
                className="text-sm font-semibold tabular-nums"
                style={{ color: sColor }}
              >
                {((alert.confidence || 0) * 100).toFixed(2)}%
              </span>
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              Above the model&apos;s 80% threshold means high-confidence classification.
            </div>
          </DetailRow>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function DetailRow({
  icon: Icon,
  label,
  children,
}: {
  icon: React.ElementType;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="h-8 w-8 shrink-0 rounded-md bg-muted grid place-items-center text-muted-foreground">
        <Icon className="h-4 w-4" />
      </div>
      <div className="flex-1 min-w-0 pt-1">
        <div className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium mb-1.5">
          {label}
        </div>
        {children}
      </div>
    </div>
  );
}
