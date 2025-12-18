import type * as React from "react"
import { cn } from "@/lib/utils"

type EmptyStateSize = "compact" | "default" | "large"

interface EmptyStateProps {
  /** 图标 */
  icon?: React.ReactNode
  /** 标题 */
  title: string
  /** 描述文字 */
  description?: string
  /** 操作按钮区域 */
  actions?: React.ReactNode
  /** 尺寸变体: compact=py-8, default=py-12, large=py-16 */
  size?: EmptyStateSize
  /** 额外的 className */
  className?: string
}

const sizeStyles: Record<EmptyStateSize, string> = {
  compact: "py-8",
  default: "py-12",
  large: "py-16",
}

/**
 * 空状态组件
 * 统一空数据/无结果场景的展示
 */
export function EmptyState({
  icon,
  title,
  description,
  actions,
  size = "default",
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center text-center",
        sizeStyles[size],
        className
      )}
    >
      {icon && <div className="mb-4 text-muted-foreground/30">{icon}</div>}
      <h3 className="mb-2 font-medium text-lg">{title}</h3>
      {description && <p className="mb-6 max-w-sm text-muted-foreground text-sm">{description}</p>}
      {actions && <div className="flex gap-3">{actions}</div>}
    </div>
  )
}
