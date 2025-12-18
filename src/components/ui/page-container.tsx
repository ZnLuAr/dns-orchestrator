import type * as React from "react"
import { cn } from "@/lib/utils"
import { ScrollArea } from "./scroll-area"

interface PageContainerProps {
  children: React.ReactNode
  /** 是否使用 ScrollArea 包裹，默认 true */
  scrollable?: boolean
  /** 最大宽度约束，如 'max-w-3xl' 或 'max-w-4xl' */
  maxWidth?: string
  /** 额外的 className */
  className?: string
}

/**
 * 页面内容容器组件
 * 统一页面 padding 和滚动行为
 */
export function PageContainer({
  children,
  scrollable = true,
  maxWidth,
  className,
}: PageContainerProps) {
  const content = (
    <div className={cn("scroll-pb-safe p-4 sm:p-6", maxWidth && `mx-auto ${maxWidth}`, className)}>
      {children}
    </div>
  )

  if (scrollable) {
    return <ScrollArea className="min-h-0 flex-1">{content}</ScrollArea>
  }

  return content
}
