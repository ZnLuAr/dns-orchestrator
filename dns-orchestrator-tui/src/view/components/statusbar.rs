//! 底部状态栏组件

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::model::{App, FocusPanel, Page};
use crate::view::theme::Styles;

/// 渲染状态栏
pub fn render(app: &App, frame: &mut Frame, area: Rect) {
    // 根据当前焦点和页面生成快捷键提示
    let hints = get_hints(app);

    // 构建状态栏内容
    let mut spans = Vec::new();

    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
        }
        spans.push(Span::styled(*key, Styles::hint_key()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(*desc, Styles::hint_desc()));
    }

    // 如果有状态消息，显示在右侧
    if let Some(ref msg) = app.status_message {
        // Add分隔符
        spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
        spans.push(Span::styled(msg.clone(), Style::default().fg(Color::Yellow)));
    }

    let content = Line::from(spans);
    let paragraph = Paragraph::new(content).style(Styles::statusbar());

    frame.render_widget(paragraph, area);
}

/// 根据当前状态生成快捷键提示
fn get_hints(app: &App) -> Vec<(&'static str, &'static str)> {
    let mut hints = Vec::new();

    // 全局快捷键
    hints.push(("←→", "Switch Panels"));

    // 根据焦点位置显示不同的快捷键
    match app.focus {
        FocusPanel::Navigation => {
            hints.push(("↑↓", "Navigation"));
            hints.push(("Enter", "Enter"));
        }
        FocusPanel::Content => {
            match &app.current_page {
                Page::Home => {
                    hints.push(("↑↓", "Navigation"));
                }
                Page::Accounts => {
                    hints.push(("↑↓", "Select"));
                    hints.push(("Alt+a", "Add"));
                    hints.push(("Alt+d", "Delete"));
                }
                Page::Domains => {
                    hints.push(("↑↓", "Select"));
                    hints.push(("Enter", "Enter"));
                }
                Page::DnsRecords { .. } => {
                    hints.push(("↑↓", "Select"));
                    hints.push(("Alt+a", "Add"));
                    hints.push(("Esc", "Back"));
                }
                Page::Toolbox => {
                    hints.push(("Tab", "Switch Tools"));
                    hints.push(("Enter", "Execute"));
                }
                Page::Settings => {
                    hints.push(("↑↓", "Select"));
                    hints.push(("Enter", "Modify"));
                }
            }
        }
    }

    // Quit
    hints.push(("Alt+q", "Quit"));

    hints
}