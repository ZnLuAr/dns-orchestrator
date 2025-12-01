import { create } from "zustand";
import { changeLanguage, type LanguageCode } from "@/i18n";

type Theme = "light" | "dark" | "system";

interface SettingsState {
  theme: Theme;
  language: LanguageCode;
  setTheme: (theme: Theme) => void;
  setLanguage: (lang: LanguageCode) => void;
}

export const useSettingsStore = create<SettingsState>((set) => ({
  theme: (localStorage.getItem("theme") as Theme) || "system",
  language: (localStorage.getItem("language") as LanguageCode) || "zh-CN",

  setTheme: (theme) => {
    set({ theme });
    localStorage.setItem("theme", theme);

    // 应用主题
    const root = document.documentElement;
    root.classList.remove("light", "dark");

    if (theme === "system") {
      const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.classList.add(systemDark ? "dark" : "light");
    } else {
      root.classList.add(theme);
    }
  },

  setLanguage: (lang) => {
    set({ language: lang });
    changeLanguage(lang);
  },
}));

// 初始化主题
export function initTheme() {
  const theme = (localStorage.getItem("theme") as Theme) || "system";
  const root = document.documentElement;

  if (theme === "system") {
    const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.classList.add(systemDark ? "dark" : "light");
  } else {
    root.classList.add(theme);
  }
}
