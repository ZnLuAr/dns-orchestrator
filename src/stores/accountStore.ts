import { toast } from "sonner"
import { create } from "zustand"
import { TIMING } from "@/constants"
import i18n from "@/i18n"
import { extractErrorMessage, getErrorMessage, getFieldErrorMessage } from "@/lib/error"
import { logger } from "@/lib/logger"
import { removeRecentDomainsByAccount } from "@/lib/recent-domains"
import { accountService } from "@/services"
import type { Account, CreateAccountRequest, CredentialValidationDetails } from "@/types"
import type { ProviderInfo } from "@/types/provider"
import { useDomainStore } from "./domainStore"

interface AccountState {
  accounts: Account[]
  providers: ProviderInfo[]
  selectedAccountId: string | null
  expandedAccountId: string | null
  isLoading: boolean
  isDeleting: boolean
  error: string | null
  fieldErrors: Record<string, string> // 字段级错误
  isExportDialogOpen: boolean
  isImportDialogOpen: boolean

  fetchAccounts: () => Promise<void>
  fetchProviders: () => Promise<void>
  createAccount: (request: CreateAccountRequest) => Promise<Account | null>
  deleteAccount: (id: string) => Promise<boolean>
  selectAccount: (id: string | null) => void
  setExpandedAccountId: (id: string | null) => void
  clearFieldErrors: () => void
  openExportDialog: () => void
  closeExportDialog: () => void
  openImportDialog: () => void
  closeImportDialog: () => void
}

export const useAccountStore = create<AccountState>((set) => ({
  accounts: [],
  providers: [],
  selectedAccountId: null,
  expandedAccountId: null,
  isLoading: false,
  isDeleting: false,
  error: null,
  fieldErrors: {},
  isExportDialogOpen: false,
  isImportDialogOpen: false,

  fetchAccounts: async () => {
    set({ isLoading: true, error: null })
    try {
      const response = await accountService.listAccounts()
      if (response.success && response.data) {
        set({ accounts: response.data })
        // 检查是否有加载失败的账户
        const failedAccounts = response.data.filter((a) => a.status === "error")
        if (failedAccounts.length > 0) {
          toast.error(i18n.t("account.loadFailedCount", { count: failedAccounts.length }), {
            duration: TIMING.TOAST_DURATION,
          })
        }
      } else {
        const msg = getErrorMessage(response.error)
        set({ error: msg })
        toast.error(msg)
      }
    } catch (err) {
      const msg = extractErrorMessage(err)
      set({ error: msg })
      toast.error(msg)
    } finally {
      set({ isLoading: false })
    }
  },

  fetchProviders: async () => {
    try {
      const response = await accountService.listProviders()
      if (response.success && response.data) {
        set({ providers: response.data })
      } else {
        logger.error("Failed to fetch providers:", getErrorMessage(response.error))
      }
    } catch (err) {
      logger.error("Failed to fetch providers:", err)
    }
  },

  createAccount: async (request) => {
    set({ isLoading: true, error: null, fieldErrors: {} })
    try {
      const response = await accountService.createAccount(request)
      if (response.success && response.data) {
        set((state) => ({ accounts: [...state.accounts, response.data!] }))
        toast.success(i18n.t("account.createSuccess", { name: response.data.name }))
        return response.data
      }
      // 处理凭证验证错误（字段级）
      if (response.error?.code === "CredentialValidation" && response.error.details) {
        const details = response.error.details as CredentialValidationDetails
        const fieldError = getFieldErrorMessage(details)
        set({ fieldErrors: { [details.field]: fieldError } })
        return null
      }
      // 其他错误
      const msg = getErrorMessage(response.error)
      set({ error: msg })
      toast.error(msg)
      return null
    } catch (err) {
      const msg = extractErrorMessage(err)
      set({ error: msg })
      toast.error(msg)
      return null
    } finally {
      set({ isLoading: false })
    }
  },

  deleteAccount: async (id) => {
    set({ isDeleting: true })
    try {
      const response = await accountService.deleteAccount(id)
      if (response.success) {
        set((state) => ({
          accounts: state.accounts.filter((a) => a.id !== id),
          selectedAccountId: state.selectedAccountId === id ? null : state.selectedAccountId,
        }))
        // 清理域名缓存
        useDomainStore.getState().clearAccountCache(id)
        // 清理最近域名记录
        removeRecentDomainsByAccount(id)
        toast.success(i18n.t("account.deleteSuccess"))
        return true
      }
      toast.error(i18n.t("account.deleteFailed"))
      return false
    } catch (err) {
      toast.error(extractErrorMessage(err))
      return false
    } finally {
      set({ isDeleting: false })
    }
  },

  selectAccount: (id) => set({ selectedAccountId: id }),
  setExpandedAccountId: (id) => set({ expandedAccountId: id }),
  clearFieldErrors: () => set({ fieldErrors: {} }),

  openExportDialog: () => set({ isExportDialogOpen: true }),
  closeExportDialog: () => set({ isExportDialogOpen: false }),
  openImportDialog: () => set({ isImportDialogOpen: true }),
  closeImportDialog: () => set({ isImportDialogOpen: false }),
}))
