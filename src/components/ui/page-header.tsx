import type * as React from "react"
import { MobileMenuTrigger } from "@/components/layout/MobileMenuTrigger"
import { cn } from "@/lib/utils"

interface PageHeaderProps {
  /** 页面标题 */
  title: string
  /** 标题前的图标 */
  icon?: React.ReactNode
  /** 副标题/描述 */
  subtitle?: string
  /** 右侧操作区域 */
  actions?: React.ReactNode
  /** 是否显示移动端菜单触发器，默认 true */
  showMobileMenu?: boolean
  /** 返回按钮（如果提供则不显示 MobileMenu） */
  backButton?: React.ReactNode
  /** 额外的 className */
  className?: string
}

/**
 * 页面头部组件
 * 统一页面标题区域的布局和样式
 */
export function PageHeader({
  title,
  icon,
  subtitle,
  actions,
  showMobileMenu = true,
  backButton,
  className,
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        "flex items-center gap-2 border-b bg-background px-4 py-3 sm:gap-3 sm:px-6 sm:py-4",
        className
      )}
    >
      {/* 移动端菜单按钮 */}
      {showMobileMenu && !backButton && (
        <div className="md:hidden">
          <MobileMenuTrigger />
        </div>
      )}

      {/* 返回按钮 */}
      {backButton}

      {/* 图标 */}
      {icon && <span className="text-primary">{icon}</span>}

      {/* 标题区域 */}
      <div className="min-w-0 flex-1">
        <h2 className="truncate font-semibold text-xl">{title}</h2>
        {subtitle && <p className="truncate text-muted-foreground text-sm">{subtitle}</p>}
      </div>

      {/* 操作区域 */}
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}
