import { useState, useEffect, useCallback } from "react";
import { useSource } from "@/components/providers/SourceContext";

const getApiBaseUrl = () => {
  if (process.env.NEXT_PUBLIC_API_BASE_URL) {
    return process.env.NEXT_PUBLIC_API_BASE_URL;
  }
  if (typeof window !== "undefined") {
    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
      return "http://localhost:8000/api";
    }
    return `${window.location.protocol}//${window.location.host}/api`;
  }
  return "http://localhost:8000/api";
};

const getWsBaseUrl = () => {
  if (process.env.NEXT_PUBLIC_WS_BASE_URL) {
    return process.env.NEXT_PUBLIC_WS_BASE_URL;
  }
  if (typeof window !== "undefined") {
    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
      return "ws://localhost:8000/ws/dashboard/";
    }
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${wsProtocol}//${window.location.host}/ws/dashboard/`;
  }
  return "ws://localhost:8000/ws/dashboard/";
};

const API_BASE_URL = getApiBaseUrl();
const WS_BASE_URL = getWsBaseUrl();

interface DashboardStats {
  total_flows: number;
  total_alerts: number;
  active_alerts: number;
  detection_rate: number;
  benign_flows: number;
  resolved_alerts?: number;
}

interface AttackTypesData {
  labels: string[];
  values: number[];
}

interface SeverityData {
  labels: string[];
  values: number[];
}

interface TrafficVolumeData {
  labels: string[];
  flows: number[];
  alerts: number[];
}

interface TopAttacker {
  src_ip: string;
  count: number;
  attack_types: string[];
  status?: string;
}

interface TopAttackersData {
  attackers: TopAttacker[];
}

interface TopTarget {
  dst_ip: string;
  count: number;
  ports: number[];
  attack_types: string[];
  last_seen: string | null;
}

interface TopTargetsData {
  targets: TopTarget[];
}

interface PipelineServiceStatus {
  status: boolean;
  label?: string;
  last_seen?: string;
}

interface PipelineStatusData {
  kafka: PipelineServiceStatus;
  ml_consumer: PipelineServiceStatus;
  cicflowmeter: PipelineServiceStatus;
  tcpdump: PipelineServiceStatus;
  flows_per_minute: number;
  alerts_per_minute: number;
}

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
  recommended_action: string;
}

interface AlertsData {
  count: number;
  next: string | null;
  previous: string | null;
  results: AlertResult[];
}

const MOCK_DATA = {
  stats: {
    total_flows: 1500,
    total_alerts: 320,
    active_alerts: 24,
    detection_rate: 21.33,
    benign_flows: 1180,
    resolved_alerts: 0,
  },
  attackTypes: {
    labels: ["Benign", "PortScan", "SQL-Injection", "BruteForce-Web", "DoS-Slowloris"],
    values: [1180, 150, 80, 60, 30],
  },
  severity: {
    labels: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NORMAL"],
    values: [45, 80, 120, 30, 1180],
  },
  trafficVolume: {
    labels: ["12:00", "12:05", "12:10", "12:15", "12:20", "12:25", "12:30"],
    flows: [45, 67, 120, 89, 210, 150, 180],
    alerts: [2, 5, 15, 8, 32, 10, 12],
  },
  topAttackers: {
    attackers: [
      { src_ip: "172.20.0.200", count: 450, attack_types: ["PortScan", "SQLi"] },
      { src_ip: "10.0.0.5", count: 120, attack_types: ["BruteForce-Web"] },
      { src_ip: "192.168.1.100", count: 85, attack_types: ["DoS"] },
      { src_ip: "10.10.10.10", count: 45, attack_types: ["SSH-Bruteforce"] },
      { src_ip: "172.16.0.50", count: 20, attack_types: ["XSS"] },
    ],
  },
  topTargets: {
    targets: [
      {
        dst_ip: "172.20.0.10",
        count: 380,
        ports: [80, 443, 22],
        attack_types: ["PortScan", "SQL-Injection"],
        last_seen: new Date().toISOString(),
      },
      {
        dst_ip: "10.0.0.5",
        count: 120,
        ports: [443, 8080],
        attack_types: ["BruteForce-Web"],
        last_seen: new Date(Date.now() - 60000).toISOString(),
      },
      {
        dst_ip: "192.168.1.50",
        count: 75,
        ports: [80, 23],
        attack_types: ["DoS"],
        last_seen: new Date(Date.now() - 300000).toISOString(),
      },
    ],
  },
  pipelineStatus: {
    kafka: { status: true, label: "Running" },
    ml_consumer: { status: true, label: "Running", last_seen: new Date().toISOString() },
    cicflowmeter: { status: true, label: "Running" },
    tcpdump: { status: true, label: "Running" },
    flows_per_minute: 45,
    alerts_per_minute: 3,
  },
  alerts: {
    count: 320,
    next: "/api/alerts/?page=2",
    previous: null,
    results: [
      {
        id: 1,
        timestamp: new Date().toISOString(),
        prediction: "PortScan",
        severity: "CRITICAL",
        src_ip: "172.20.0.200",
        dst_ip: "172.20.0.10",
        dst_port: 80,
        protocol: 6,
        confidence: 0.99,
        source_type: "website",
        recommended_action: "Block source IP in firewall.",
      },
      {
        id: 2,
        timestamp: new Date(Date.now() - 60000).toISOString(),
        prediction: "SQL-Injection",
        severity: "HIGH",
        src_ip: "172.20.0.200",
        dst_ip: "10.0.0.5",
        dst_port: 443,
        protocol: 6,
        confidence: 0.85,
        source_type: "website",
        recommended_action: "Inspect web server logs for SQLi attempts.",
      },
      {
        id: 3,
        timestamp: new Date(Date.now() - 120000).toISOString(),
        prediction: "BruteForce-Web",
        severity: "MEDIUM",
        src_ip: "10.0.0.5",
        dst_ip: "192.168.1.50",
        dst_port: 80,
        protocol: 6,
        confidence: 0.76,
        source_type: "home_network",
        recommended_action: "Implement rate limiting on login endpoint.",
      },
    ],
  },
};

export const useDashboardData = (options?: { includeBenign?: boolean }) => {
  const includeBenign = options?.includeBenign ?? false;
  const { sourceType, activeSite } = useSource();

  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [attackTypes, setAttackTypes] = useState<AttackTypesData | null>(null);
  const [severity, setSeverity] = useState<SeverityData | null>(null);
  const [trafficVolume, setTrafficVolume] = useState<TrafficVolumeData | null>(null);
  const [topAttackers, setTopAttackers] = useState<TopAttackersData | null>(null);
  const [topTargets, setTopTargets] = useState<TopTargetsData | null>(null);
  const [pipelineStatus, setPipelineStatus] = useState<PipelineStatusData | null>(null);
  const [alerts, setAlerts] = useState<AlertsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const applyMockData = useCallback(() => {
    setStats(MOCK_DATA.stats);
    setAttackTypes(MOCK_DATA.attackTypes);
    setSeverity(MOCK_DATA.severity);
    setTrafficVolume(MOCK_DATA.trafficVolume);
    setTopAttackers(MOCK_DATA.topAttackers);
    setTopTargets(MOCK_DATA.topTargets);
    setPipelineStatus(MOCK_DATA.pipelineStatus);
    setAlerts(MOCK_DATA.alerts);
  }, []);

  const fetchData = useCallback(async () => {
    setLoading(true);
    const siteParam = sourceType === "website" && activeSite ? `&registered_id=${activeSite.id}` : "";
    try {
      const [
        statsRes,
        attackTypesRes,
        severityRes,
        trafficVolumeRes,
        topAttackersRes,
        topTargetsRes,
        pipelineStatusRes,
        alertsRes,
      ] = await Promise.all([
        fetch(`${API_BASE_URL}/dashboard/stats/?source_type=${sourceType}${siteParam}`).catch(() => null),
        fetch(`${API_BASE_URL}/dashboard/attack-types/?source_type=${sourceType}${siteParam}`).catch(() => null),
        fetch(`${API_BASE_URL}/dashboard/severity/?source_type=${sourceType}${siteParam}`).catch(() => null),
        fetch(`${API_BASE_URL}/dashboard/traffic-volume/?source_type=${sourceType}&minutes=60${siteParam}`).catch(() => null),
        fetch(`${API_BASE_URL}/dashboard/top-attackers/?source_type=${sourceType}&limit=5${siteParam}`).catch(() => null),
        fetch(`${API_BASE_URL}/dashboard/top-targets/?source_type=${sourceType}&limit=5${siteParam}`).catch(() => null),
        fetch(`${API_BASE_URL}/dashboard/pipeline-status/?source_type=${sourceType}`).catch(() => null),
        fetch(`${API_BASE_URL}/alerts/?source_type=${sourceType}&page=${page}&limit=${pageSize}${siteParam}${includeBenign ? "&include_benign=true" : ""}`).catch(() => null),
      ]);

      const allFailed = ![statsRes, attackTypesRes, severityRes, trafficVolumeRes, topAttackersRes, topTargetsRes, pipelineStatusRes, alertsRes].some((res) => res && res.ok);

      if (allFailed) {
        applyMockData();
      } else {
        if (statsRes?.ok) setStats(await statsRes.json());
        if (attackTypesRes?.ok) setAttackTypes(await attackTypesRes.json());
        if (severityRes?.ok) setSeverity(await severityRes.json());
        if (trafficVolumeRes?.ok) setTrafficVolume(await trafficVolumeRes.json());
        if (topAttackersRes?.ok) setTopAttackers(await topAttackersRes.json());
        if (topTargetsRes?.ok) setTopTargets(await topTargetsRes.json());
        if (pipelineStatusRes?.ok) setPipelineStatus(await pipelineStatusRes.json());
        if (alertsRes?.ok) setAlerts(await alertsRes.json());
      }
    } catch (error) {
      console.error("Fetch error:", error);
      applyMockData();
    } finally {
      setLoading(false);
    }
  }, [sourceType, activeSite, page, pageSize, includeBenign, applyMockData]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  useEffect(() => {
    const ws = new WebSocket(WS_BASE_URL);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "dashboard_update") {
          fetchData();
        }
      } catch (err) {
        console.error(err);
      }
    };

    ws.onerror = () => {
    };

    return () => {
      ws.close();
    };
  }, [fetchData]);

  return {
    stats,
    attackTypes,
    severity,
    trafficVolume,
    topAttackers,
    topTargets,
    pipelineStatus,
    alerts,
    loading,
    page,
    setPage,
    pageSize,
    setPageSize,
  };
};
