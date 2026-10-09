"use client";

import { ArrowRight, Bell } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { Button } from "./ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "./ui/popover";
import { useSource } from "./providers/SourceContext";
import { useNotificationAlerts } from "@/hooks/useNotificationAlerts";
import { cyberPalette, getAttackColor, severityColors } from "@/lib/theme";
import type { AlertResultLite } from "@/lib/api";

type SourceType = "website" | "home_network";

const formatWhen = (timestamp: string): string => {
  try {
    return formatDistanceToNow(new Date(timestamp), { addSuffix: true });
  } catch {
    return timestamp;
  }
};

function AlertRow({
  alert,
  onClick,
}: {
  alert: AlertResultLite;
  onClick: () => void;
}) {
  const severity = alert.severity.toUpperCase();
  const sColor = severityColors[severity] || cyberPalette.red;
  const aColor = getAttackColor(alert.prediction);

  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full cursor-pointer rounded-md px-2 py-2 text-left transition-colors hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-muted-foreground">
          {formatWhen(alert.timestamp)}
        </span>
        <span
          className="inline-flex items-center rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-white"
          style={{ backgroundColor: sColor }}
        >
          {severity}
        </span>
      </div>
      <div className="mt-1 flex items-center gap-2">
        <span
          className="h-2 w-2 shrink-0 rounded-full"
          style={{ backgroundColor: aColor }}
        />
        <span className="text-sm font-medium text-foreground">
          {alert.prediction}
        </span>
      </div>
      <div className="mt-1 font-mono text-[11px] text-foreground">
        {alert.src_ip}
        <ArrowRight className="mx-1.5 inline h-3 w-3 text-muted-foreground" />
        {alert.dst_ip}:
        <span className="text-muted-foreground">{alert.dst_port}</span>
      </div>
    </button>
  );
}

const SOURCE_LABELS: Record<SourceType, string> = {
  website: "Website",
  home_network: "Home network",
};

const NotificationBell = () => {
  const router = useRouter();
  const { sourceType } = useSource();
  const { website, home } = useNotificationAlerts();
  const [open, setOpen] = useState(false);

  // The dropdown always reflects the module the user is currently in.
  const list = sourceType === "website" ? website : home;
  const hasAlerts = list.length > 0;

  const goToAlerts = () => {
    setOpen(false);
    router.push("/alerts");
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          className="relative h-10 w-10 rounded-full border-border bg-card hover:bg-accent"
        >
          <Bell className="h-4 w-4" />
          {hasAlerts && (
            <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-destructive" />
          )}
          <span className="sr-only">Notifications</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" sideOffset={8} className="w-80 p-0">
        <div className="flex items-baseline justify-between px-3 pt-3 pb-2">
          <span className="text-sm font-medium text-foreground">Recent alerts</span>
          <span className="text-[11px] font-medium text-muted-foreground">
            {SOURCE_LABELS[sourceType]}
          </span>
        </div>

        <div className="max-h-80 overflow-y-auto px-2">
          {list.length === 0 ? (
            <p className="px-2 py-6 text-center text-xs text-muted-foreground">
              No recent alerts.
            </p>
          ) : (
            list.map((alert) => (
              <AlertRow key={alert.id} alert={alert} onClick={goToAlerts} />
            ))
          )}
        </div>

        <div className="border-t border-border p-2">
          <button
            type="button"
            onClick={goToAlerts}
            className="flex w-full cursor-pointer items-center justify-center gap-1 rounded-md py-2 text-xs font-medium text-foreground transition-colors hover:bg-accent"
          >
            More
            <ArrowRight className="h-3 w-3" />
          </button>
        </div>
      </PopoverContent>
    </Popover>
  );
};

export default NotificationBell;
