import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";
import type {
  DnsRecord,
  CreateDnsRecordRequest,
  UpdateDnsRecordRequest,
  ApiResponse,
} from "@/types";

interface DnsState {
  records: DnsRecord[];
  currentDomainId: string | null;
  isLoading: boolean;
  isDeleting: boolean;
  error: string | null;

  fetchRecords: (accountId: string, domainId: string) => Promise<void>;
  createRecord: (
    accountId: string,
    request: CreateDnsRecordRequest
  ) => Promise<DnsRecord | null>;
  updateRecord: (
    accountId: string,
    recordId: string,
    request: UpdateDnsRecordRequest
  ) => Promise<boolean>;
  deleteRecord: (
    accountId: string,
    recordId: string,
    domainId: string
  ) => Promise<boolean>;
  clearRecords: () => void;
}

export const useDnsStore = create<DnsState>((set, get) => ({
  records: [],
  currentDomainId: null,
  isLoading: false,
  isDeleting: false,
  error: null,

  fetchRecords: async (accountId, domainId) => {
    set({ isLoading: true, error: null, records: [], currentDomainId: domainId });
    try {
      const response = await invoke<ApiResponse<DnsRecord[]>>(
        "list_dns_records",
        { accountId, domainId }
      );
      // 只有当 domainId 匹配当前选中的域名时才更新
      if (get().currentDomainId !== domainId) {
        return; // 请求已过期，忽略
      }
      if (response.success && response.data) {
        set({ records: response.data });
      } else {
        const msg = response.error?.message || "获取 DNS 记录失败";
        set({ error: msg });
        toast.error(msg);
      }
    } catch (err) {
      if (get().currentDomainId !== domainId) {
        return; // 请求已过期，忽略
      }
      const msg = String(err);
      set({ error: msg });
      toast.error(msg);
    } finally {
      if (get().currentDomainId === domainId) {
        set({ isLoading: false });
      }
    }
  },

  createRecord: async (accountId, request) => {
    set({ isLoading: true, error: null });
    try {
      const response = await invoke<ApiResponse<DnsRecord>>(
        "create_dns_record",
        { accountId, request }
      );
      if (response.success && response.data) {
        set((state) => ({ records: [...state.records, response.data!] }));
        toast.success(`记录 "${response.data.name}" 添加成功`);
        return response.data;
      }
      const msg = response.error?.message || "创建记录失败";
      set({ error: msg });
      toast.error(msg);
      return null;
    } catch (err) {
      const msg = String(err);
      set({ error: msg });
      toast.error(msg);
      return null;
    } finally {
      set({ isLoading: false });
    }
  },

  updateRecord: async (accountId, recordId, request) => {
    try {
      const response = await invoke<ApiResponse<DnsRecord>>(
        "update_dns_record",
        { accountId, recordId, request }
      );
      if (response.success && response.data) {
        set((state) => ({
          records: state.records.map((r) =>
            r.id === recordId ? response.data! : r
          ),
        }));
        toast.success("记录更新成功");
        return true;
      }
      toast.error("更新记录失败");
      return false;
    } catch (err) {
      toast.error(String(err));
      return false;
    }
  },

  deleteRecord: async (accountId, recordId, domainId) => {
    set({ isDeleting: true });
    try {
      const response = await invoke<ApiResponse<void>>("delete_dns_record", {
        accountId,
        recordId,
        domainId,
      });
      if (response.success) {
        set((state) => ({
          records: state.records.filter((r) => r.id !== recordId),
        }));
        toast.success("记录已删除");
        return true;
      }
      toast.error("删除记录失败");
      return false;
    } catch (err) {
      toast.error(String(err));
      return false;
    } finally {
      set({ isDeleting: false });
    }
  },

  clearRecords: () => set({ records: [], error: null }),
}));
