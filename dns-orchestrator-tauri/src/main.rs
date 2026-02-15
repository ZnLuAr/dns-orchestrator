// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // 日志系统由 tauri-plugin-log 初始化
    dns_orchestrator_lib::run();
}
