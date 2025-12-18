import type * as React from "react"
import { cn } from "@/lib/utils"

interface SettingSectionProps {
  /** 标题 */
  title: string
  /** 描述 */
  description?: string
  /** 子内容 */
  children: React.ReactNode
  /** 额外的 className */
  className?: string
}

/**
 * 设置区块组件
 * 用于设置页面的分组布局
 */
export function SettingSection({ title, description, children, className }: SettingSectionProps) {
  return (
    <div className={cn("space-y-3 sm:space-y-5", className)}>
      <div>
        <h3 className="mb-1 font-semibold text-lg">{title}</h3>
        {description && <p className="text-muted-foreground text-sm">{description}</p>}
      </div>
      {children}
    </div>
  )
}

interface SettingItemProps {
  /** 子内容 */
  children: React.ReactNode
  /** 额外的 className */
  className?: string
}

/**
 * 设置项容器
 * 统一设置项的卡片样式
 */
export function SettingItem({ children, className }: SettingItemProps) {
  return <div className={cn("rounded-xl border bg-card p-4 sm:p-5", className)}>{children}</div>
}

interface SettingRowProps {
  /** 左侧标签 */
  label: React.ReactNode
  /** 标签下的描述 */
  description?: string
  /** 右侧控件 */
  control: React.ReactNode
  /** 额外的 className */
  className?: string
}

/**
 * 设置行组件
 * 左侧标签+描述，右侧控件的布局
 */
export function SettingRow({ label, description, control, className }: SettingRowProps) {
  return (
    <div className={cn("flex items-center justify-between", className)}>
      <div className="space-y-1.5">
        <div className="font-medium text-sm">{label}</div>
        {description && <p className="text-muted-foreground text-xs">{description}</p>}
      </div>
      {control}
    </div>
  )
}
