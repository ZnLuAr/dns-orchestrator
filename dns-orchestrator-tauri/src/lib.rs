mod adapters;
mod commands;
mod error;
mod types;

use std::sync::Arc;

#[cfg(target_os = "android")]
use commands::updater;
use commands::{account, dns, domain, domain_metadata, toolbox};
use tauri::Manager;
use tauri_plugin_log::{Target, TargetKind};

use adapters::{TauriAccountRepository, TauriCredentialStore, TauriDomainMetadataRepository};
use dns_orchestrator_app::{AppState, AppStateBuilder, StartupHooks};

/// Tauri-specific startup hooks for credential backup.
struct TauriStartupHooks {
    app_handle: tauri::AppHandle,
}

#[async_trait::async_trait]
impl StartupHooks for TauriStartupHooks {
    async fn backup_credentials(&self, raw_json: &str) -> Option<String> {
        let data_dir = match self.app_handle.path().app_data_dir() {
            Ok(dir) => dir,
            Err(e) => {
                log::warn!("Failed to get data dir for backup: {e}");
                return None;
            }
        };

        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            log::warn!("Failed to create data dir for backup: {e}");
            return None;
        }

        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = data_dir.join(format!("credentials.backup.{timestamp}.json"));

        if let Err(e) = std::fs::write(&backup_path, raw_json.as_bytes()) {
            log::warn!("Failed to write backup: {e}");
            return None;
        }

        let path_str = backup_path.display().to_string();
        log::info!("凭证已备份到: {path_str}");
        Some(path_str)
    }

    async fn cleanup_backup(&self, backup_info: &str) {
        if let Err(e) = std::fs::remove_file(backup_info) {
            log::warn!("删除备份文件失败: {e}");
        } else {
            log::info!("已删除备份文件");
        }
    }

    async fn preserve_backup(&self, backup_info: &str, error: &str) {
        log::error!("迁移失败，备份文件保留在: {backup_info}，请手动检查 (error: {error})");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init());

    #[cfg(debug_assertions)]
    {
        builder = builder.plugin(
            tauri_plugin_log::Builder::new()
                .targets([Target::new(TargetKind::Stdout)])
                .level(log::LevelFilter::Debug)
                .build(),
        );
    }

    #[cfg(not(debug_assertions))]
    {
        builder = builder.plugin(
            tauri_plugin_log::Builder::new()
                .targets([Target::new(TargetKind::Stdout)])
                .level(log::LevelFilter::Warn)
                .build(),
        );
    }

    // 仅桌面端启用 updater
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }

    // Android 启用 Stronghold 和 APK Installer
    // TODO: `stronghold_salt.txt` 使用相对路径，依赖 Stronghold plugin 内部基于 app data dir 解析。
    // 若后续发现 Android 上凭证存储异常，应排查此路径是否正确解析。
    // Plugin 注册发生在 builder 阶段（setup 之前），此时无法通过 app.path() 获取绝对路径。
    #[cfg(target_os = "android")]
    {
        builder = builder
            .plugin(
                tauri_plugin_stronghold::Builder::with_argon2(&std::path::PathBuf::from(
                    "stronghold_salt.txt",
                ))
                .build(),
            )
            .plugin(tauri_plugin_apk_installer::init());
    }

    let builder = builder.setup(|app| {
        let app_handle = app.handle().clone();

        // 创建平台适配器
        #[cfg(not(target_os = "android"))]
        let credential_store = Arc::new(TauriCredentialStore::new());

        #[cfg(target_os = "android")]
        let credential_store = Arc::new(TauriCredentialStore::new(app_handle.clone()));

        let account_repository = Arc::new(TauriAccountRepository::new(app_handle.clone()));
        let domain_metadata_repository =
            Arc::new(TauriDomainMetadataRepository::new(app_handle.clone()));

        // 通过 AppStateBuilder 构建 AppState
        let state = AppStateBuilder::new()
            .credential_store(credential_store)
            .account_repository(account_repository)
            .domain_metadata_repository(domain_metadata_repository)
            .build()
            .map_err(|e| e.to_string())?;

        app.manage(state);

        // 执行凭证迁移（v1.7.0 - 阻塞操作，确保迁移完成后再恢复账户）
        let hooks = TauriStartupHooks {
            app_handle: app_handle.clone(),
        };
        let app_handle_for_migration = app_handle.clone();
        tauri::async_runtime::block_on(async move {
            let state = app_handle_for_migration.state::<AppState>();
            state.run_migration(&hooks).await;
        });

        // 后台恢复账户，不阻塞启动
        tauri::async_runtime::spawn(async move {
            let state = app_handle.state::<AppState>();
            state.run_account_restore().await;
        });

        Ok(())
    });

    /// 生成包含公共命令和可选平台特定命令的 `invoke_handler`。
    /// 避免桌面端和 Android 端的命令注册重复。
    macro_rules! build_invoke_handler {
        ($($extra:path),* $(,)?) => {
            tauri::generate_handler![
                // Account commands
                account::list_accounts,
                account::create_account,
                account::update_account,
                account::delete_account,
                account::batch_delete_accounts,
                account::list_providers,
                account::export_accounts,
                account::preview_import,
                account::import_accounts,
                account::is_restore_completed,
                // Domain commands
                domain::list_domains,
                domain::get_domain,
                // Domain metadata commands
                domain_metadata::get_domain_metadata,
                domain_metadata::toggle_domain_favorite,
                domain_metadata::list_account_favorite_domain_keys,
                domain_metadata::add_domain_tag,
                domain_metadata::remove_domain_tag,
                domain_metadata::set_domain_tags,
                domain_metadata::find_domains_by_tag,
                domain_metadata::list_all_domain_tags,
                domain_metadata::batch_add_domain_tags,
                domain_metadata::batch_remove_domain_tags,
                domain_metadata::batch_set_domain_tags,
                domain_metadata::update_domain_metadata,
                // DNS commands
                dns::list_dns_records,
                dns::create_dns_record,
                dns::update_dns_record,
                dns::delete_dns_record,
                dns::batch_delete_dns_records,
                // Toolbox commands
                toolbox::whois_lookup,
                toolbox::dns_lookup,
                toolbox::ip_lookup,
                toolbox::ssl_check,
                toolbox::http_header_check,
                toolbox::dns_propagation_check,
                toolbox::dnssec_check,
                // Platform-specific commands
                $($extra,)*
            ]
        };
    }

    #[cfg(not(target_os = "android"))]
    let builder = builder.invoke_handler(build_invoke_handler![]);

    #[cfg(target_os = "android")]
    let builder = builder.invoke_handler(build_invoke_handler![
        updater::check_android_update,
        updater::download_apk,
        updater::install_apk,
    ]);

    #[allow(clippy::expect_used)]
    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
