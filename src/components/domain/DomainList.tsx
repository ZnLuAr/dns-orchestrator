import { useTranslation } from "react-i18next";
import type { Domain, DomainStatus } from "@/types";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { Globe } from "lucide-react";

interface DomainListProps {
  domains: Domain[];
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}

export function DomainList({
  domains,
  selectedId,
  onSelect,
}: DomainListProps) {
  const { t } = useTranslation();

  const statusConfig: Record<DomainStatus, { labelKey: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
    active: { labelKey: "domain.status.active", variant: "default" },
    paused: { labelKey: "domain.status.paused", variant: "secondary" },
    pending: { labelKey: "domain.status.pending", variant: "outline" },
    error: { labelKey: "domain.status.error", variant: "destructive" },
  };

  if (domains.length === 0) {
    return (
      <div className="text-sm text-muted-foreground py-2">{t("domain.noDomains")}</div>
    );
  }

  return (
    <div className="space-y-1">
      {domains.map((domain) => (
        <button
          key={domain.id}
          onClick={() => onSelect(selectedId === domain.id ? null : domain.id)}
          className={cn(
            "w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
            "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
            selectedId === domain.id &&
              "bg-sidebar-accent text-sidebar-accent-foreground"
          )}
        >
          <Globe className="h-4 w-4 shrink-0 text-muted-foreground" />
          <div className="flex-1 text-left truncate">
            <div className="font-medium truncate">{domain.name}</div>
            {domain.recordCount !== undefined && (
              <div className="text-xs text-muted-foreground">
                {t("domain.recordCount", { count: domain.recordCount })}
              </div>
            )}
          </div>
          <Badge
            variant={statusConfig[domain.status]?.variant ?? "secondary"}
            className="text-xs"
          >
            {t(statusConfig[domain.status]?.labelKey ?? "domain.status.active")}
          </Badge>
        </button>
      ))}
    </div>
  );
}
