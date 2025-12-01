import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { useAccountStore, useDomainStore } from "@/stores";
import { DnsRecordTable } from "@/components/dns/DnsRecordTable";
import { Globe } from "lucide-react";

export function MainContent() {
  const { t } = useTranslation();
  const { selectedAccountId, accounts, providers } = useAccountStore();
  const { selectedDomainId, domains } = useDomainStore();

  const selectedDomain = domains.find((d) => d.id === selectedDomainId);
  const selectedAccount = accounts.find((a) => a.id === selectedAccountId);

  // 获取当前账户对应的提供商功能
  const providerFeatures = useMemo(() => {
    if (!selectedAccount) return null;
    const provider = providers.find((p) => p.id === selectedAccount.provider);
    return provider?.features ?? null;
  }, [selectedAccount, providers]);

  if (!selectedDomainId || !selectedAccountId) {
    return (
      <main className="flex-1 flex items-center justify-center bg-muted/30">
        <div className="text-center text-muted-foreground">
          <Globe className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p className="text-lg">{t("main.selectDomain")}</p>
          <p className="text-sm mt-1">{t("main.selectDomainHint")}</p>
        </div>
      </main>
    );
  }

  return (
    <main className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b bg-background">
        <h2 className="text-xl font-semibold">{selectedDomain?.name}</h2>
        <p className="text-sm text-muted-foreground mt-1">
          {t("main.manageDns", { domain: selectedDomain?.name })}
        </p>
      </div>

      {/* Content */}
      <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
        <DnsRecordTable
          accountId={selectedAccountId}
          domainId={selectedDomainId}
          supportsProxy={providerFeatures?.proxy ?? false}
        />
      </div>
    </main>
  );
}
