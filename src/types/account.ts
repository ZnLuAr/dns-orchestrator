/** 账号状态 */
export type AccountStatus = "active" | "error";

/** 账号基础信息 */
export interface Account {
  id: string;
  name: string;
  provider: string;
  createdAt: string;
  updatedAt: string;
  status?: AccountStatus;
  error?: string;
}

/** 创建账号请求 */
export interface CreateAccountRequest {
  name: string;
  provider: string;
  credentials: Record<string, string>;
}

/** 更新账号请求 */
export interface UpdateAccountRequest {
  id: string;
  name?: string;
  credentials?: Record<string, string>;
}
