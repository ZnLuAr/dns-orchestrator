use tauri::State;

use crate::error::DnsError;
use crate::types::*;
use crate::AppState;

/// 列出域名下的所有 DNS 记录
#[tauri::command]
pub async fn list_dns_records(
    state: State<'_, AppState>,
    account_id: String,
    domain_id: String,
) -> Result<ApiResponse<Vec<DnsRecord>>, String> {
    // 获取 provider
    let provider = state
        .registry
        .get(&account_id)
        .await
        .ok_or_else(|| DnsError::AccountNotFound(account_id.clone()).to_string())?;

    // 调用 provider 获取 DNS 记录列表
    let records = provider
        .list_records(&domain_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(records))
}

/// 创建 DNS 记录
#[tauri::command]
pub async fn create_dns_record(
    state: State<'_, AppState>,
    account_id: String,
    request: CreateDnsRecordRequest,
) -> Result<ApiResponse<DnsRecord>, String> {
    // 获取 provider
    let provider = state
        .registry
        .get(&account_id)
        .await
        .ok_or_else(|| DnsError::AccountNotFound(account_id.clone()).to_string())?;

    // 调用 provider 创建记录
    let record = provider
        .create_record(&request)
        .await
        .map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(record))
}

/// 更新 DNS 记录
#[tauri::command]
pub async fn update_dns_record(
    state: State<'_, AppState>,
    account_id: String,
    record_id: String,
    request: UpdateDnsRecordRequest,
) -> Result<ApiResponse<DnsRecord>, String> {
    // 获取 provider
    let provider = state
        .registry
        .get(&account_id)
        .await
        .ok_or_else(|| DnsError::AccountNotFound(account_id.clone()).to_string())?;

    // 调用 provider 更新记录
    let record = provider
        .update_record(&record_id, &request)
        .await
        .map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(record))
}

/// 删除 DNS 记录
#[tauri::command]
pub async fn delete_dns_record(
    state: State<'_, AppState>,
    account_id: String,
    record_id: String,
    domain_id: String,
) -> Result<ApiResponse<()>, String> {
    // 获取 provider
    let provider = state
        .registry
        .get(&account_id)
        .await
        .ok_or_else(|| DnsError::AccountNotFound(account_id.clone()).to_string())?;

    // 调用 provider 删除记录
    provider
        .delete_record(&record_id, &domain_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(()))
}
