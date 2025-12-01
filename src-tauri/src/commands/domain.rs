use tauri::State;

use crate::error::DnsError;
use crate::types::*;
use crate::AppState;

/// 列出账号下的所有域名
#[tauri::command]
pub async fn list_domains(
    state: State<'_, AppState>,
    account_id: String,
) -> Result<ApiResponse<Vec<Domain>>, String> {
    // 获取 provider
    let provider = state
        .registry
        .get(&account_id)
        .await
        .ok_or_else(|| DnsError::AccountNotFound(account_id.clone()).to_string())?;

    // 调用 provider 获取域名列表
    let domains = provider.list_domains().await.map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(domains))
}

/// 获取域名详情
#[tauri::command]
pub async fn get_domain(
    state: State<'_, AppState>,
    account_id: String,
    domain_id: String,
) -> Result<ApiResponse<Domain>, String> {
    // 获取 provider
    let provider = state
        .registry
        .get(&account_id)
        .await
        .ok_or_else(|| DnsError::AccountNotFound(account_id.clone()).to_string())?;

    // 调用 provider 获取域名详情
    let domain = provider
        .get_domain(&domain_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(ApiResponse::success(domain))
}
