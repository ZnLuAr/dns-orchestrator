import { useCallback, useEffect, useState } from "react"
import { AccountsPage } from "@/components/accounts/AccountsPage"
import { DnsRecordPage } from "@/components/domains/DnsRecordPage"
import { DomainSelectorPage } from "@/components/domains/DomainSelectorPage"
import { ErrorBoundary } from "@/components/error"
import { addRecentDomain, HomePage } from "@/components/home/HomePage"
import { AppLayout } from "@/components/layout/AppLayout"
import { SettingsPage } from "@/components/settings/SettingsPage"
import { ToolboxPage } from "@/components/toolbox/ToolboxPage"
import { Toaster } from "@/components/ui/sonner"
import { StatusBar } from "@/components/ui/status-bar"
import { UpdateDialog } from "@/components/ui/update-dialog"
import { TIMING } from "@/constants"
import { useIsMobile } from "@/hooks/useMediaQuery"
import { initDebugMode } from "@/lib/debug"
import { logger } from "@/lib/logger"
import { initTheme, useAccountStore, useDomainStore } from "@/stores"
import { useUpdaterStore } from "@/stores/updaterStore"

type View = "main" | "domains" | "domains-detail" | "settings" | "toolbox" | "accounts"

// 用于 Sidebar 高亮的映射（domains-detail 也应该高亮 domains）
function getNavView(view: View): "main" | "domains" | "settings" | "toolbox" | "accounts" {
  if (view === "domains-detail") return "domains"
  return view
}

function App() {
  const { checkForUpdates, showUpdateDialog, setShowUpdateDialog } = useUpdaterStore()
  const { accounts, selectAccount, fetchAccounts } = useAccountStore()
  const { selectDomain, loadFromStorage, refreshAllAccounts } = useDomainStore()
  const [currentView, setCurrentView] = useState<View>("main")
  const isMobile = useIsMobile()

  // 当前选中的域名信息（用于 domains-detail 视图）
  const [selectedDomainInfo, setSelectedDomainInfo] = useState<{
    accountId: string
    domainId: string
  } | null>(null)

  // 初始化
  useEffect(() => {
    initTheme()
    initDebugMode()
    // 加载账户列表
    fetchAccounts()
    // 从 localStorage 加载域名缓存
    loadFromStorage()
  }, [fetchAccounts, loadFromStorage])

  // 账户加载完成后，后台刷新域名
  useEffect(() => {
    if (accounts.length > 0) {
      // 过滤掉错误状态的账户
      const validAccounts = accounts.filter((a) => a.status !== "error")
      if (validAccounts.length > 0) {
        refreshAllAccounts(validAccounts)
      }
    }
  }, [accounts, refreshAllAccounts])

  // 检查更新（仅桌面端）
  useEffect(() => {
    if (isMobile) return

    const timer = setTimeout(async () => {
      try {
        await checkForUpdates()
      } catch (error) {
        logger.error("Update check failed:", error)
      }
    }, TIMING.UPDATE_CHECK_DELAY)

    return () => clearTimeout(timer)
  }, [checkForUpdates, isMobile])

  // 导航处理
  const handleNavigate = useCallback((view: View) => {
    // 如果从 domains-detail 切换到其他视图，清除选中状态
    if (view !== "domains" && view !== "domains-detail") {
      setSelectedDomainInfo(null)
    }
    setCurrentView(view)
  }, [])

  // 从域名列表选择域名 -> 进入 DNS 记录页
  const handleSelectDomain = useCallback(
    (accountId: string, domainId: string, domainName: string) => {
      const account = accounts.find((a) => a.id === accountId)
      if (account) {
        // 记录最近访问
        addRecentDomain({
          accountId,
          domainId,
          domainName,
          accountName: account.name,
          provider: account.provider,
        })
      }

      selectAccount(accountId)
      selectDomain(accountId, domainId)
      setSelectedDomainInfo({ accountId, domainId })
      setCurrentView("domains-detail")
    },
    [accounts, selectAccount, selectDomain]
  )

  // 从主页快捷访问 -> 直接进入 DNS 记录页
  const handleQuickAccess = useCallback(
    (accountId: string, domainId: string, domainName: string) => {
      handleSelectDomain(accountId, domainId, domainName)
    },
    [handleSelectDomain]
  )

  // 从 DNS 记录页返回域名列表
  const handleBackToList = useCallback(() => {
    setSelectedDomainInfo(null)
    setCurrentView("domains")
  }, [])

  // 移动端子页面时隐藏 AppLayout 的 header
  const shouldHideHeader = isMobile && currentView !== "main"

  const renderContent = () => {
    switch (currentView) {
      case "main":
        return <HomePage onNavigate={handleNavigate} onQuickAccess={handleQuickAccess} />
      case "domains":
        return <DomainSelectorPage onBack={() => setCurrentView("main")} onSelect={handleSelectDomain} />
      case "domains-detail":
        if (selectedDomainInfo) {
          return (
            <DnsRecordPage
              accountId={selectedDomainInfo.accountId}
              domainId={selectedDomainInfo.domainId}
              onBack={handleBackToList}
            />
          )
        }
        // 如果没有选中信息，回到列表
        return <DomainSelectorPage onBack={() => setCurrentView("main")} onSelect={handleSelectDomain} />
      case "settings":
        return <SettingsPage onBack={() => setCurrentView("main")} />
      case "toolbox":
        return <ToolboxPage onBack={() => setCurrentView("main")} />
      case "accounts":
        return <AccountsPage onBack={() => setCurrentView("main")} />
      default:
        return <HomePage onNavigate={handleNavigate} onQuickAccess={handleQuickAccess} />
    }
  }

  return (
    <ErrorBoundary level="global" name="App" showRetry={false}>
      <AppLayout
        currentView={getNavView(currentView)}
        onNavigate={handleNavigate}
        hideHeader={shouldHideHeader}
      >
        <ErrorBoundary level="page" name="ContentArea">
          {renderContent()}
        </ErrorBoundary>
      </AppLayout>
      {!isMobile && <StatusBar />}
      <UpdateDialog open={showUpdateDialog} onOpenChange={setShowUpdateDialog} />
      <Toaster richColors position={isMobile ? "bottom-center" : "top-right"} />
    </ErrorBoundary>
  )
}

export default App
