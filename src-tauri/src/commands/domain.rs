use tauri::State;

use crate::error::{DnsError, ProviderError};
use crate::types::{AccountStatus, ApiResponse, Domain, PaginatedResponse, PaginationParams};
use crate::AppState;

/// 更新账户状态（凭证失效时调用）
async fn mark_account_invalid(state: &AppState, account_id: &str, error_msg: &str) {
    let mut accounts = state.accounts.write().await;
    if let Some(account) = accounts.iter_mut().find(|a| a.id == account_id) {
        account.status = Some(AccountStatus::Error);
        account.error = Some(error_msg.to_string());
        log::warn!("Account {account_id} marked as invalid: {error_msg}");
    }
}

/// 列出账号下的所有域名（分页）
#[tauri::command]
pub async fn list_domains(
    state: State<'_, AppState>,
    account_id: String,
    page: Option<u32>,
    page_size: Option<u32>,
) -> Result<ApiResponse<PaginatedResponse<Domain>>, DnsError> {
    // 获取 provider
    let provider = state
        .registry
        .get(&account_id)
        .await
        .ok_or_else(|| DnsError::AccountNotFound(account_id.clone()))?;

    // 构造分页参数
    let params = PaginationParams {
        page: page.unwrap_or(1),
        page_size: page_size.unwrap_or(20),
    };

    // 调用 provider 获取域名列表
    match provider.list_domains(&params).await {
        Ok(lib_response) => {
            // 将库的 Domain 转换为应用层的 Domain（添加 account_id）
            let domains: Vec<Domain> = lib_response
                .items
                .into_iter()
                .map(|d| Domain::from_lib(d, account_id.clone()))
                .collect();

            let response = PaginatedResponse::new(
                domains,
                lib_response.page,
                lib_response.page_size,
                lib_response.total_count,
            );
            Ok(ApiResponse::success(response))
        }
        Err(ProviderError::InvalidCredentials { provider }) => {
            // 凭证失效，更新账户状态
            mark_account_invalid(&state, &account_id, "凭证已失效").await;
            Err(DnsError::Provider(ProviderError::InvalidCredentials {
                provider,
            }))
        }
        Err(e) => Err(DnsError::Provider(e)),
    }
}

/// 获取域名详情
#[tauri::command]
pub async fn get_domain(
    state: State<'_, AppState>,
    account_id: String,
    domain_id: String,
) -> Result<ApiResponse<Domain>, DnsError> {
    // 获取 provider
    let provider = state
        .registry
        .get(&account_id)
        .await
        .ok_or_else(|| DnsError::AccountNotFound(account_id.clone()))?;

    // 调用 provider 获取域名详情
    let lib_domain = provider.get_domain(&domain_id).await?;

    // 转换为应用层的 Domain（添加 account_id）
    let domain = Domain::from_lib(lib_domain, account_id);

    Ok(ApiResponse::success(domain))
}
