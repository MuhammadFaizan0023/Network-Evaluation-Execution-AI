"use client";

import { useCallback, useEffect, useState } from "react";
import { API_BASE_URL, type AlertResultLite } from "@/lib/api";
import { useSource } from "@/components/providers/SourceContext";

const LIMIT = 5;
const POLL_MS = 15000;

async function fetchRecent(url: string): Promise<AlertResultLite[]> {
  try {
    const r = await fetch(url);
    if (!r.ok) return [];
    const data = await r.json();
    return Array.isArray(data.results) ? data.results.slice(0, LIMIT) : [];
  } catch {
    return [];
  }
}

/**
 * Fetches the most recent alerts for BOTH sources (website + home network)
 * independently, so the notification dropdown's two tabs can render regardless
 * of the globally selected source. Polls every 15s to keep the lists / badge
 * fresh. Failures resolve to empty arrays rather than throwing.
 */
export function useNotificationAlerts() {
  const { activeSite } = useSource();
  const [website, setWebsite] = useState<AlertResultLite[]>([]);
  const [home, setHome] = useState<AlertResultLite[]>([]);
  const [loading, setLoading] = useState(true);

  const siteId = activeSite?.id;

  const load = useCallback(async () => {
    const siteParam = siteId ? `&registered_id=${siteId}` : "";
    const [web, hn] = await Promise.all([
      fetchRecent(
        `${API_BASE_URL}/alerts/?source_type=website&page=1&limit=${LIMIT}${siteParam}`,
      ),
      fetchRecent(
        `${API_BASE_URL}/alerts/?source_type=home_network&page=1&limit=${LIMIT}`,
      ),
    ]);
    setWebsite(web);
    setHome(hn);
    setLoading(false);
  }, [siteId]);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  return { website, home, loading };
}
