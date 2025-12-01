import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type { Domain, ApiResponse } from "@/types";

interface DomainState {
  domains: Domain[];
  selectedDomainId: string | null;
  isLoading: boolean;
  error: string | null;

  fetchDomains: (accountId: string) => Promise<void>;
  selectDomain: (id: string | null) => void;
  clearDomains: () => void;
}

export const useDomainStore = create<DomainState>((set) => ({
  domains: [],
  selectedDomainId: null,
  isLoading: false,
  error: null,

  fetchDomains: async (accountId) => {
    set({ isLoading: true, error: null, selectedDomainId: null });
    try {
      const response = await invoke<ApiResponse<Domain[]>>("list_domains", {
        accountId,
      });
      if (response.success && response.data) {
        set({ domains: response.data });
      } else {
        set({ error: response.error?.message || "获取域名列表失败" });
      }
    } catch (err) {
      set({ error: String(err) });
    } finally {
      set({ isLoading: false });
    }
  },

  selectDomain: (id) => set({ selectedDomainId: id }),

  clearDomains: () => set({ domains: [], selectedDomainId: null }),
}));
