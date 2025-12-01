import { useTranslation } from "react-i18next";
import { useSettingsStore } from "@/stores/settingsStore";
import { supportedLanguages, type LanguageCode } from "@/i18n";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Moon, Sun, Monitor, Languages } from "lucide-react";
import { cn } from "@/lib/utils";

interface SettingsSheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SettingsSheet({ open, onOpenChange }: SettingsSheetProps) {
  const { t } = useTranslation();
  const { theme, language, setTheme, setLanguage } = useSettingsStore();

  const themes = [
    { id: "light" as const, label: t("settings.themeLight"), icon: Sun },
    { id: "dark" as const, label: t("settings.themeDark"), icon: Moon },
    { id: "system" as const, label: t("settings.themeSystem"), icon: Monitor },
  ];

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        <SheetHeader>
          <SheetTitle>{t("settings.title")}</SheetTitle>
        </SheetHeader>

        <div className="mt-6 space-y-6">
          {/* 主题设置 */}
          <div className="space-y-4">
            <Label className="text-base">{t("settings.appearance")}</Label>
            <div className="grid grid-cols-3 gap-2">
              {themes.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setTheme(id)}
                  className={cn(
                    "flex flex-col items-center gap-2 p-3 rounded-lg border-2 transition-colors",
                    theme === id
                      ? "border-primary bg-primary/5"
                      : "border-transparent bg-muted/50 hover:bg-muted"
                  )}
                >
                  <Icon className="h-5 w-5" />
                  <span className="text-xs">{label}</span>
                </button>
              ))}
            </div>
          </div>

          <Separator />

          {/* 语言设置 */}
          <div className="space-y-4">
            <Label className="text-base">{t("settings.language")}</Label>
            <div className="grid grid-cols-2 gap-2">
              {supportedLanguages.map((lang) => (
                <button
                  key={lang.code}
                  onClick={() => setLanguage(lang.code as LanguageCode)}
                  className={cn(
                    "flex items-center gap-2 p-3 rounded-lg border-2 transition-colors",
                    language === lang.code
                      ? "border-primary bg-primary/5"
                      : "border-transparent bg-muted/50 hover:bg-muted"
                  )}
                >
                  <Languages className="h-4 w-4" />
                  <span className="text-sm">{lang.name}</span>
                </button>
              ))}
            </div>
          </div>

          <Separator />

          {/* 通知设置 */}
          <div className="space-y-4">
            <Label className="text-base">{t("settings.notifications")}</Label>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="notifications" className="text-sm font-normal">
                  {t("settings.operationNotifications")}
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t("settings.operationNotificationsDesc")}
                </p>
              </div>
              <Switch id="notifications" defaultChecked />
            </div>
          </div>

          <Separator />

          {/* 关于 */}
          <div className="space-y-2">
            <Label className="text-base">{t("settings.about")}</Label>
            <div className="text-sm text-muted-foreground space-y-1">
              <p>{t("common.appName")}</p>
              <p>{t("settings.version")} 0.0.1-alpha</p>
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
