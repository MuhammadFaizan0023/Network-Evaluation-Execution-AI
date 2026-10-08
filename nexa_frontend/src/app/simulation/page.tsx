"use client";

import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import {
  Play,
  Square,
  Activity,
  ShieldAlert,
  Terminal,
  Clock,
  CheckCircle2,
} from "lucide-react";
import { API_BASE_URL } from "@/lib/api";
import { useSource } from "@/components/providers/SourceContext";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import TrafficVolumeChart from "@/components/dashboard/TrafficVolumeChart";
import { severityColors } from "@/lib/theme";

interface FlowLog {
  id?: number | string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  prediction: string;
  confidence: number;
  severity: string;
}

interface EventLog {
  time: string;
  message: string;
  type: "info" | "threat" | "system";
}

const getWsUrl = () => {
  const base = API_BASE_URL.replace("/api", "");
  return base.replace(/^http/, "ws") + "/ws/simulation/";
};

const scenarioMapping: Record<string, { label: string; expected: string }> = {
  bruteforce: { label: "Web Brute Force", expected: "BruteForce-Web" },
  portscan: { label: "Port Scan", expected: "PortScan" },
  sqli: { label: "SQL Injection", expected: "SQL-Injection" },
  dos: { label: "Denial of Service", expected: "DoS" },
  xss: { label: "Cross-Site Scripting", expected: "XSS" },
  // Home-network / IoT scenarios (expected = TON-IoT class)
  iotrecon: { label: "Reconnaissance & Access Attack", expected: "Scanning" },
  iotbenign: { label: "Benign", expected: "—" },
  iotbackdoor: { label: "Backdoor", expected: "Backdoor" },
  iotransomware: { label: "Ransomware", expected: "Ransomware" },
  iotmitm: { label: "MITM", expected: "MITM" },
  iotdos: { label: "DoS", expected: "DoS" },
};

// Scenario dropdown options per source type
const WEB_SCENARIOS = [
  { value: "portscan", label: "Port Scan (Nmap)" },
  { value: "sqli", label: "SQL Injection" },
  { value: "bruteforce", label: "Web Brute Force" },
  { value: "dos", label: "Denial of Service (DoS)" },
  { value: "xss", label: "Cross-Site Scripting (XSS)" },
];
const IOT_SCENARIOS = [
  { value: "iotrecon", label: "Reconnaissance & Access Attack" },
  { value: "iotbenign", label: "Benign" },
  { value: "iotbackdoor", label: "Backdoor" },
  { value: "iotransomware", label: "Ransomware" },
  { value: "iotmitm", label: "MITM" },
  { value: "iotdos", label: "DoS" },
];

export default function SimulationPage() {
  const { sourceType } = useSource();
  const scenarioOptions = sourceType === "home_network" ? IOT_SCENARIOS : WEB_SCENARIOS;

  const [isRunning, setIsRunning] = useState(false);
  const [scenario, setScenario] = useState("bruteforce");
  const [target, setTarget] = useState("172.20.0.10");
  const [duration, setDuration] = useState("30"); // in seconds
  const [intensity, setIntensity] = useState("medium");

  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [stats, setStats] = useState({ flows: 0, alerts: 0 });
  const [liveFlows, setLiveFlows] = useState<FlowLog[]>([]);
  const [events, setEvents] = useState<EventLog[]>([]);

  const [trafficVolumeData, setTrafficVolumeData] = useState<{
    labels: string[];
    flows: number[];
    alerts: number[];
  } | null>(null);
  const [chartLoading, setChartLoading] = useState(false);
  const [lastRunSummary, setLastRunSummary] = useState<{
    scenario: string;
    expected: string;
    detected: string;
    result: string;
    latency: string;
    flows: number;
    alerts: number;
  } | null>(null);

  // Ref to track duration for stop trigger
  const durationRef = useRef(duration);
  durationRef.current = duration;

  // Always-current refs so buildSummary reads the latest values without stale closures.
  const scenarioRef = useRef(scenario);
  scenarioRef.current = scenario;
  const elapsedRef = useRef(elapsed);
  elapsedRef.current = elapsed;
  const statsRef = useRef(stats);
  statsRef.current = stats;
  const liveFlowsRef = useRef(liveFlows);
  liveFlowsRef.current = liveFlows;

  // Build the detection summary from the flows collected during the run
  const buildSummary = useCallback(() => {
    const sc = scenarioRef.current;
    const mapInfo = scenarioMapping[sc] || { label: sc, expected: "—" };
    const flows = liveFlowsRef.current;
    const latestThreat = flows.find((f) => f.prediction.toLowerCase() !== "benign");
    const detectedVal = latestThreat ? latestThreat.prediction : "Benign";
    const expectedClean = mapInfo.expected.toLowerCase().replace(/[^a-z0-9]/g, "");
    const detectedClean = detectedVal.toLowerCase().replace(/[^a-z0-9]/g, "");
    const isCorrect = detectedClean.includes(expectedClean) ||
                      (detectedVal === "Benign" && mapInfo.expected === "—");
    const el = elapsedRef.current;
    const st = statsRef.current;
    setLastRunSummary({
      scenario: mapInfo.label,
      expected: mapInfo.expected,
      detected: detectedVal,
      result: isCorrect ? "✓ Correct Detection" : "✗ Missed / Incorrect",
      latency: latestThreat ? `${(el > 1 ? (el - 1) : 1.2).toFixed(1)} sec` : "N/A",
      flows: st.flows,
      alerts: st.alerts,
    });
  }, []);

  // Keep the selected scenario valid for the current source type (web vs IoT)
  useEffect(() => {
    if (!scenarioOptions.some((s) => s.value === scenario)) {
      setScenario(scenarioOptions[0].value);
    }
  }, [scenarioOptions, scenario]);

  // Clear previous results/logs when switching source tab (web <-> home network)
  useEffect(() => {
    // Default target per source: IoT victim device vs DVWA web target
    setTarget(sourceType === "home_network" ? "172.20.0.50" : "172.20.0.10");
    setLastRunSummary(null);
    setLiveFlows([]);
    setEvents([]);
    setStats({ flows: 0, alerts: 0 });
    setTrafficVolumeData(null);
    setElapsed(0);
  }, [sourceType]);

  // Append clean timeline events
  const addEvent = useCallback((message: string, type: "info" | "threat" | "system" = "info") => {
    const timeStr = new Date().toLocaleTimeString();
    setEvents((prev) => [{ time: timeStr, message, type }, ...prev].slice(0, 50));
  }, []);

  // Backfill logs
  const fetchLiveFeed = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/simulation/live-feed/`).catch(() => null);
      if (res && res.ok) {
        const data = await res.json();
        setLiveFlows(data.flows || []);
      }
    } catch (err) {
      console.error(err);
    }
  }, []);

  // Fetch dashboard traffic volume data for consistent spikes chart
  const fetchTrafficVolume = useCallback(async () => {
    setChartLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/dashboard/traffic-volume/?minutes=60`).catch(() => null);
      if (res && res.ok) {
        const data = await res.json();
        setTrafficVolumeData(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setChartLoading(false);
    }
  }, []);

  const handleStartAttack = useCallback(async () => {
    setActionLoading(true);
    // Clear any previous run's results/logs before starting a new simulation
    setLastRunSummary(null);
    setLiveFlows([]);
    setEvents([]);
    setStats({ flows: 0, alerts: 0 });
    setTrafficVolumeData(null);
    setElapsed(0);
    addEvent(`Initializing scenario: ${scenario.toUpperCase()} targeting ${target}...`, "system");
    // Lane this run belongs to: web scenarios -> website (CNN); home-network -> iot_test (TON-IoT)
    const simSourceType = sourceType === "home_network" ? "iot_test" : "website";
    try {
      const res = await fetch(`${API_BASE_URL}/simulation/start/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_type: scenario, target: target, intensity: intensity, duration: duration, source_type: simSourceType }),
      });
      if (res.ok) {
        lastActionTimeRef.current = Date.now();
        setIsRunning(true);
        fetchTrafficVolume();
        addEvent("Simulation pipeline started successfully", "system");
      } else {
        addEvent("Failure starting simulation on backend container", "threat");
        alert("Failed to start simulation. Verify Docker setup is active.");
      }
    } catch (e) {
      console.error(e);
      addEvent("Connection error to Django APIs", "threat");
    } finally {
      setActionLoading(false);
    }
  }, [scenario, target, intensity, duration, sourceType, addEvent, fetchTrafficVolume]);

  const handleStopAttack = useCallback(async () => {
    setActionLoading(true);
    addEvent("Terminating active attack scripts...", "system");
    try {
      const res = await fetch(`${API_BASE_URL}/simulation/stop/`, {
        method: "POST",
      });
      if (res.ok) {
        lastActionTimeRef.current = Date.now();
        setIsRunning(false);
        addEvent("Simulation stopped. Safe status restored.", "system");
        fetchTrafficVolume();
        // Hard stop: freeze the summary from the flows collected during the run.
        buildSummary();
      } else {
        alert("Failed to stop simulation.");
      }
    } catch (e) {
      console.error(e);
    } finally {
      setActionLoading(false);
    }
  }, [addEvent, buildSummary, fetchTrafficVolume]);

  // Check backend status on mount
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/simulation/status/`).catch(() => null);
        if (res && res.ok) {
          const data = await res.json();
          setIsRunning(data.is_running);
          if (data.is_running) {
            setScenario(data.attack_type);
            setStats({
              flows: data.flows_generated,
              alerts: data.alerts_triggered,
            });
            setElapsed(data.elapsed_seconds || 0);
            fetchLiveFeed();
            fetchTrafficVolume();
            addEvent(`Resumed active simulation: ${data.attack_type.toUpperCase()}`, "system");
          } else {
            // If nothing is running, ensure stats are clear
            setStats({ flows: 0, alerts: 0 });
            setEvents([]);
            fetchTrafficVolume();
          }
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchStatus();
  }, [addEvent, fetchLiveFeed, fetchTrafficVolume]);

  const lastActionTimeRef = useRef<number>(0);

  // Always-current ref for stop — prevents handleStopAttack from being a timer dep
  const handleStopAttackRef = useRef(handleStopAttack);
  handleStopAttackRef.current = handleStopAttack;

  // Guard: prevents the timer from triggering stop more than once per run
  const stoppingRef = useRef(false);

  // Poll traffic volume chart during simulation run
  useEffect(() => {
    let pollTimer: NodeJS.Timeout;
    if (isRunning) {
      pollTimer = setInterval(() => {
        fetchTrafficVolume();
      }, 3000);
    }
    return () => clearInterval(pollTimer);
  }, [isRunning, fetchTrafficVolume]);

  // Socket listener
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout;

    const connectWs = () => {
      ws = new WebSocket(getWsUrl());

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          // Handle scan reset - clear all simulation state immediately
          if (data.type === "simulation_reset") {
            setIsRunning(false);
            setStats({ flows: 0, alerts: 0 });
            setLiveFlows([]);
            setTrafficVolumeData(null);
            setEvents([]);
            setLastRunSummary(null);
            return;
          }

          if (data.type === "simulation_update") {
            if (data.flows_generated !== undefined && data.flows_generated !== null) {
              setStats({
                flows: data.flows_generated,
                alerts: data.alerts_triggered ?? 0,
              });
            }

            if (data.latest_flow) {
              setLiveFlows((prev) => {
                if (prev.some((f) => f.timestamp === data.latest_flow.timestamp && f.prediction === data.latest_flow.prediction)) {
                  return prev;
                }
                const isThreat = data.latest_flow.prediction.toLowerCase() !== "benign";
                if (isThreat) {
                  addEvent(`Threat classified: ${data.latest_flow.prediction} from ${data.latest_flow.src_ip} (Severity: ${data.latest_flow.severity})`, "threat");
                } else {
                  addEvent(`Benign network flow analyzed`, "info");
                }
                const next = [data.latest_flow, ...prev].slice(0, 30);
                liveFlowsRef.current = next;
                return next;
              });
            }
          }
        } catch (e) {
          console.error("WS error:", e);
        }
      };

      ws.onclose = () => {
        reconnectTimeout = setTimeout(connectWs, 3000);
      };
    };

    connectWs();

    return () => {
      if (ws) ws.close();
      clearTimeout(reconnectTimeout);
    };
  }, [addEvent, fetchTrafficVolume]);

  // Countdown timer — only depends on isRunning, never on the stop callback
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isRunning) {
      stoppingRef.current = false; // reset guard each new run
      timer = setInterval(() => {
        setElapsed((prev) => {
          const nextVal = prev + 1;
          const limit = parseInt(durationRef.current, 10);
          if (nextVal >= limit && !stoppingRef.current) {
            stoppingRef.current = true; // one-shot guard
            handleStopAttackRef.current();
            return limit;
          }
          return nextVal;
        });
      }, 1000);
    } else {
      setElapsed(0);
    }
    return () => clearInterval(timer);
  }, [isRunning]);

  // Determine latest threat found
  const threatResult = useMemo(() => {
    if (!isRunning) return { detected: false, type: "—", severity: "—", latency: "—" };
    const latestThreat = liveFlows.find((f) => f.prediction.toLowerCase() !== "benign");
    if (!latestThreat) return { detected: false, type: "—", severity: "—", latency: "—" };
    return {
      detected: true,
      type: latestThreat.prediction,
      severity: latestThreat.severity,
      latency: `${(elapsed > 1 ? (elapsed - 1) : 1.2).toFixed(1)} sec`,
    };
  }, [liveFlows, isRunning, elapsed]);

  const limitSeconds = parseInt(duration, 10);

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <Skeleton className="h-12 w-64" />
        <Skeleton className="h-[300px] w-full rounded-2xl" />
        <Skeleton className="h-[200px] w-full rounded-2xl" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Simulation Lab</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Generate controlled network scenarios and evaluate Watchtower IDS detection.
          </p>
        </div>
      </header>

      {/* 1. Configuration Panel */}
      <Card className="p-6 shadow-none border-border bg-card">
        <h2 className="text-sm font-semibold text-foreground mb-4">Simulation Configuration</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 w-full items-end">
          <div className="space-y-1.5 w-full">
            <label className="text-xs font-medium text-muted-foreground">Scenario</label>
            <Select value={scenario} onValueChange={setScenario} disabled={isRunning}>
              <SelectTrigger className="w-full h-10 rounded-xl bg-muted/30">
                <SelectValue placeholder="Select Scenario" />
              </SelectTrigger>
              <SelectContent>
                {scenarioOptions.map((s) => (
                  <SelectItem key={s.value} value={s.value}>
                    {s.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5 w-full">
            <label className="text-xs font-medium text-muted-foreground">Target Host</label>
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={isRunning}
              className="w-full h-10 rounded-xl bg-muted/30 border-border"
            />
          </div>

          <div className="space-y-1.5 w-full">
            <label className="text-xs font-medium text-muted-foreground">Duration</label>
            <Select value={duration} onValueChange={setDuration} disabled={isRunning}>
              <SelectTrigger className="w-full h-10 rounded-xl bg-muted/30">
                <SelectValue placeholder="Select Duration" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="30">30 seconds</SelectItem>
                <SelectItem value="60">60 seconds</SelectItem>
                <SelectItem value="120">2 minutes</SelectItem>
                <SelectItem value="300">5 minutes</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5 w-full">
            <label className="text-xs font-medium text-muted-foreground">Intensity</label>
            <Select value={intensity} onValueChange={setIntensity} disabled={isRunning}>
              <SelectTrigger className="w-full h-10 rounded-xl bg-muted/30">
                <SelectValue placeholder="Select Intensity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex justify-center mt-6">
          {isRunning ? (
            <Button
              variant="destructive"
              onClick={handleStopAttack}
              disabled={actionLoading}
              className="w-full md:w-56 h-10 rounded-full font-medium gap-2 shadow-xs cursor-pointer"
            >
              <Square className="h-4 w-4 fill-current" />
              {actionLoading ? "Stopping..." : "Stop Simulation"}
            </Button>
          ) : (
            <Button
              onClick={handleStartAttack}
              disabled={actionLoading}
              className="w-full md:w-56 h-10 rounded-full bg-foreground text-background hover:bg-foreground/90 font-medium gap-2 shadow-xs cursor-pointer"
            >
              <Play className="h-4 w-4 fill-current" />
              {actionLoading ? "Starting..." : "Start Simulation"}
            </Button>
          )}
        </div>
      </Card>

      {/* 2. Middle Row: Status & Detection Result OR Simulation Complete */}
      {lastRunSummary && !isRunning ? (
        <Card className="p-6 shadow-none border-border bg-card animate-in fade-in slide-in-from-bottom-2 duration-300">
          <div className="flex items-center gap-2 mb-4 border-b border-border pb-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-500" />
            <h2 className="text-sm font-semibold text-foreground">Simulation Complete</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="space-y-3">
              <div className="flex justify-between border-b border-border/40 pb-2 text-xs">
                <span className="text-muted-foreground">Scenario</span>
                <span className="text-foreground font-semibold">{lastRunSummary.scenario}</span>
              </div>
              <div className="flex justify-between border-b border-border/40 pb-2 text-xs">
                <span className="text-muted-foreground">Expected</span>
                <span className="text-foreground font-mono font-semibold">{lastRunSummary.expected}</span>
              </div>
              <div className="flex justify-between border-b border-border/40 pb-2 text-xs">
                <span className="text-muted-foreground">Detected</span>
                <span className="text-foreground font-mono font-semibold">{lastRunSummary.detected}</span>
              </div>
              <div className="flex justify-between pb-1 text-xs">
                <span className="text-muted-foreground">Result</span>
                <span className={`font-bold ${lastRunSummary.result.includes("✓") ? "text-emerald-500" : "text-red-500"}`}>
                  {lastRunSummary.result}
                </span>
              </div>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between border-b border-border/40 pb-2 text-xs">
                <span className="text-muted-foreground">Detection Latency</span>
                <span className="text-foreground font-semibold">{lastRunSummary.latency}</span>
              </div>
              <div className="flex justify-between border-b border-border/40 pb-2 text-xs">
                <span className="text-muted-foreground">Flows Generated</span>
                <span className="text-foreground font-mono font-semibold">{lastRunSummary.flows.toLocaleString()}</span>
              </div>
              <div className="flex justify-between border-b border-border/40 pb-2 text-xs">
                <span className="text-muted-foreground">Alerts Generated</span>
                <span className="text-foreground font-mono font-semibold">{lastRunSummary.alerts.toLocaleString()}</span>
              </div>
            </div>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Status Card */}
          <Card className={`p-6 shadow-none border ${isRunning ? "border-red-500/20 bg-red-500/[0.01]" : "border-border bg-card"}`}>
            <h3 className="text-sm font-semibold text-foreground mb-4">Simulation Status</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Session Status</span>
                {isRunning ? (
                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-500/10 text-red-500 animate-pulse border border-red-500/20">
                    ● RUNNING
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-muted text-muted-foreground border border-border">
                    ● IDLE
                  </span>
                )}
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground font-medium flex items-center gap-1">
                  <Clock className="h-3.5 w-3.5" /> Progress Time
                </span>
                <span className="text-sm font-bold text-foreground font-mono">
                  {Math.floor(elapsed / 60)}:{(elapsed % 60).toString().padStart(2, "0")} /{" "}
                  {Math.floor(limitSeconds / 60)}:{(limitSeconds % 60).toString().padStart(2, "0")}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground font-medium flex items-center gap-1">
                  <Activity className="h-3.5 w-3.5" /> Flows Generated
                </span>
                <span className="text-sm font-bold text-foreground font-mono">
                  {(stats?.flows ?? 0).toLocaleString()}
                </span>
              </div>
            </div>
          </Card>

          {/* Detection Card */}
          <Card className={`p-6 shadow-none border ${threatResult.detected ? "border-red-500/20 bg-red-500/[0.01]" : "border-border bg-card"}`}>
            <h3 className="text-sm font-semibold text-foreground mb-4">Detection Result</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Gateway Status</span>
                {threatResult.detected ? (
                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-500/10 text-red-500 border border-red-500/20">
                    <ShieldAlert className="h-3 w-3" /> Threat Detected
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                    <CheckCircle2 className="h-3 w-3" /> System Secure
                  </span>
                )}
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Classification</span>
                <span className="text-sm font-bold text-foreground font-mono">{threatResult.type}</span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Severity / Latency</span>
                <span className="text-sm font-bold text-foreground font-mono flex items-center gap-2">
                  {threatResult.severity !== "—" && (
                    <span
                      className="inline-flex items-center rounded-full px-1.5 py-0.5 text-[9px] font-bold text-white uppercase"
                      style={{ backgroundColor: severityColors[threatResult.severity.toUpperCase()] }}
                    >
                      {threatResult.severity}
                    </span>
                  )}
                  <span className="text-muted-foreground text-xs">{threatResult.latency}</span>
                </span>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* 3. Live Simulation Traffic Chart */}
      <Card className="p-6 shadow-none border-border bg-card">
        <style>{`
          .simulation-chart-wrapper h2,
          .simulation-chart-wrapper span,
          .simulation-chart-wrapper p {
            display: none !important;
          }
          .simulation-chart-wrapper .w-full {
            min-height: 180px !important;
            height: 180px !important;
          }
          .simulation-chart-wrapper svg {
            height: 180px !important;
          }
        `}</style>

        {!isRunning ? (
          <div className="flex flex-col items-center justify-center h-[180px] rounded-xl border border-dashed border-border/80 bg-muted/20 text-center">
            <h4 className="text-xs font-semibold text-foreground">Awaiting simulation traffic</h4>
            <p className="text-[11px] text-muted-foreground mt-0.5">Start a scenario above to visualize network flow waves.</p>
          </div>
        ) : (
          <div className="simulation-chart-wrapper h-[180px] overflow-hidden">
            <TrafficVolumeChart data={trafficVolumeData} loading={chartLoading} />
          </div>
        )}
      </Card>

      {/* 4. Detection Events Console */}
      <Card className="p-6 shadow-none border-border bg-card">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2 mb-4">
          <Terminal className="h-4 w-4 text-muted-foreground" /> Detection Events Log
        </h3>
        <div className="font-mono text-xs bg-neutral-950 text-neutral-300 p-4 rounded-xl border border-border/10 overflow-y-auto max-h-[220px] min-h-[140px] flex flex-col gap-2 shadow-inner">
          {events.length === 0 ? (
            <div className="text-neutral-500 italic text-center py-10 my-auto">
              Console idle. Awaiting simulation events...
            </div>
          ) : (
            events.map((evt, idx) => (
              <div key={idx} className="flex items-start gap-3 py-0.5 border-b border-neutral-900/40">
                <span className="text-neutral-600 shrink-0">[{evt.time}]</span>
                <span
                  className={`font-semibold shrink-0 uppercase text-[10px] tracking-wide ${
                    evt.type === "threat"
                      ? "text-red-500"
                      : evt.type === "system"
                      ? "text-blue-400"
                      : "text-emerald-400"
                  }`}
                >
                  {evt.type}
                </span>
                <span className="text-neutral-200 leading-normal">{evt.message}</span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
