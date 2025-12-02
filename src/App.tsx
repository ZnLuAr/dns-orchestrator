import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { AppLayout } from "@/components/layout/AppLayout";
import { SettingsPage } from "@/components/settings/SettingsPage";
import { StatusBar } from "@/components/ui/status-bar";
import { Toaster } from "@/components/ui/sonner";
import { initTheme } from "@/stores";
import { useUpdaterStore } from "@/stores/updaterStore";

type View = "main" | "settings";

function App() {
  const { t } = useTranslation();
  const { checkForUpdates } = useUpdaterStore();
  const [currentView, setCurrentView] = useState<View>("main");

  useEffect(() => {
    initTheme();

    // 启动后延迟 3 秒检查更新（静默检查，状态栏会自动显示）
    const timer = setTimeout(async () => {
      try {
        await checkForUpdates();
      } catch (error) {
        // 启动时的错误检查不打扰用户，仅记录日志
        console.error("Update check failed:", error);
      }
    }, 3000);

    return () => clearTimeout(timer);
  }, [checkForUpdates, t]);

  return (
    <>
      <AppLayout>
        {currentView === "settings" && (
          <SettingsPage onBack={() => setCurrentView("main")} />
        )}
      </AppLayout>
      <StatusBar onOpenSettings={() => setCurrentView("settings")} />
      <Toaster richColors position="top-right" />
    </>
  );
}

export default App;
