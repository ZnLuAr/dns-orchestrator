//! 左侧导航面板组件

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

use crate::model::App;
use crate::view::theme::Styles;

/// 渲染导航面板
pub fn render(app: &App, frame: &mut Frame, area: Rect) {
    let is_focused = app.focus.is_navigation();

    // 边框样式
    let border_style = if is_focused {
        Styles::border_focused()
    } else {
        Styles::border()
    };

    let block = Block::default()
        .title(" Navigation ")
        .title_style(Styles::title())
        .borders(Borders::ALL)
        .border_style(border_style);

    // 构建导航项列表
    let items: Vec<ListItem> = app
        .navigation
        .items
        .iter()
        .enumerate()
        .map(|(i, nav_item)| {
            let is_selected = i == app.navigation.selected;
            let prefix = if is_selected { "▶ " } else { "  " };

            let content = format!("{}{} {}", prefix, nav_item.icon, nav_item.label);

            let style = if is_selected {
                Styles::selected()
            } else {
                Style::default()
            };

            ListItem::new(Line::from(Span::styled(content, style)))
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(Styles::selected());

    // 使用 ListState 来跟踪选中状态
    let mut state = ListState::default();
    state.select(Some(app.navigation.selected));

    frame.render_stateful_widget(list, area, &mut state);
}