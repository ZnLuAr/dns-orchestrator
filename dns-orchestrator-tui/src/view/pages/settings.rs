//! 设置页面视图

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::model::App;

/// 渲染设置页面
pub fn render(_app: &App, frame: &mut Frame, area: Rect) {
    let settings = vec![
        ("Theme", "Dark"),
        ("Language", "English"),
        ("Pagination Mode", "Infinite Scroll"),
    ];

    let mut lines = vec![Line::from("")];

    for (i, (name, value)) in settings.iter().enumerate() {
        let prefix = if i == 0 { "▶ " } else { "  " };
        let style = if i == 0 {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        lines.push(Line::from(vec![
            Span::styled(format!("  {}{}", prefix, name), style),
            Span::styled(": ", Style::default().fg(Color::DarkGray)),
            Span::styled(*value, Style::default().fg(Color::Cyan)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "  Press Enter to change selected setting.",
        Style::default().fg(Color::DarkGray),
    ));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);
}