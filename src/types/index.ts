export * from "./provider";
export * from "./account";
export * from "./domain";
export * from "./dns";

/** 通用 API 响应 */
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
}

/** API 错误 */
export interface ApiError {
  code: string;
  message: string;
}
