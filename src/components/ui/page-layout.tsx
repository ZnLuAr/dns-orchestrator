import type * as React from "react"
import { cn } from "@/lib/utils"

interface PageLayoutProps {
  children: React.ReactNode
  className?: string
}

/**
 * 页面布局容器
 * 统一页面的 flex 布局结构
 */
export function PageLayout({ children, className }: PageLayoutProps) {
  return (
    <div className={cn("flex min-h-0 flex-1 flex-col overflow-hidden", className)}>{children}</div>
  )
}
