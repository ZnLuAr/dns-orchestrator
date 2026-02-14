/**
 * Android 更新相关类型定义
 * 仅在 Android 平台使用，独立于通用 Transport 类型
 */

import type { Channel } from "@tauri-apps/api/core"

/** Android 更新信息 */
export interface AndroidUpdate {
  version: string
  notes: string
  url: string
  signature: string
}

/** 下载进度事件 */
export interface DownloadProgress {
  event: "Started" | "Progress" | "Finished"
  data: {
    content_length?: number
    chunk_length?: number
  }
}

/** Android 更新相关命令类型映射 */
export interface AndroidUpdaterCommandMap {
  check_android_update: {
    args: { currentVersion: string }
    result: AndroidUpdate | null
  }
  download_apk: {
    args: { url: string; signature: string; onProgress: Channel<DownloadProgress> }
    result: string
  }
  install_apk: {
    args: { path: string }
    result: undefined
  }
}

// 重新导出 Channel 类型，方便 updaterStore 使用
export type { Channel }
