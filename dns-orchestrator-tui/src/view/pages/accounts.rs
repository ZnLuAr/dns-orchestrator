//! 账号管理页面视图

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState},
    Frame,
};

use crate::i18n::t;
use crate::model::domain::ProviderType;
use crate::model::App;
use crate::view::theme::colors;

/// 渲染账号管理页面
pub fn render(app: &App, frame: &mut Frame, area: Rect) {
    if app.accounts.accounts.is_empty() {
        render_empty(frame, area);
    } else {
        render_list(app, frame, area);
    }
}

/// 渲染空状态
fn render_empty(frame: &mut Frame, area: Rect) {
    let texts = t();
    let c = colors();
    let content = vec![
        Line::from(""),
        Line::styled(
            format!("  {}", texts.accounts.no_accounts),
            Style::default().fg(c.muted),
        ),
        Line::from(""),
        Line::styled(
            format!("  Alt+a: {}", texts.accounts.add_account),
            Style::default().fg(c.muted),
        ),
    ];

    let paragraph = ratatui::widgets::Paragraph::new(content);
    frame.render_widget(paragraph, area);
}

/// 渲染账号列表
fn render_list(app: &App, frame: &mut Frame, area: Rect) {
    let c = colors();
    let items: Vec<ListItem> = app
        .accounts
        .accounts
        .iter()
        .enumerate()
        .map(|(i, account)| {
            let is_selected = i == app.accounts.selected;
            // 将 core ProviderType 转换为 TUI 的包装类型以获取 short_name()
            let tui_provider = ProviderType::from_core(&account.provider);
            let provider_badge = format!("[{}]", tui_provider.short_name());

            let style = if is_selected {
                Style::default()
                    .fg(c.selected_fg)
                    .bg(c.selected_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(c.fg)
            };

            let provider_style = if is_selected {
                Style::default().fg(c.selected_fg).bg(c.selected_bg)
            } else {
                Style::default().fg(c.muted)
            };

            let line = Line::from(vec![
                Span::raw("  "),
                Span::styled(&account.name, style),
                Span::raw(" "),
                Span::styled(provider_badge, provider_style),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default())
        .highlight_style(Style::default());

    let mut state = ListState::default();
    state.select(Some(app.accounts.selected));

    frame.render_stateful_widget(list, area, &mut state);
}
