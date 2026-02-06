use egui::text::LayoutJob;
use egui::{Color32, FontFamily, FontId, TextFormat, TextStyle, Ui};
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};

pub fn layout_md(ui: &Ui, input: &str) -> LayoutJob {
    let mut job = LayoutJob::default();
    let base_format = default_format(ui);
    layout_md_raw(&mut job, base_format, input);
    job
}

pub fn layout_md_raw(job: &mut LayoutJob, base_format: TextFormat, input: &str) {
    let mut format_stack = vec![base_format.clone()];
    let mut pending_newlines: u8 = 0;
    let mut list_stack: Vec<ListState> = Vec::new();

    for event in Parser::new(input) {
        match event {
            Event::Text(text) => {
                if pending_newlines > 0 {
                    let fmt = format_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| base_format.clone());
                    for _ in 0..pending_newlines {
                        job.append("\n", 0.0, fmt.clone());
                    }
                    pending_newlines = 0;
                }
                let fmt = format_stack
                    .last()
                    .cloned()
                    .unwrap_or_else(|| base_format.clone());
                job.append(&text, 0.0, fmt);
            }
            Event::Code(text) => {
                if pending_newlines > 0 {
                    let fmt = format_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| base_format.clone());
                    for _ in 0..pending_newlines {
                        job.append("\n", 0.0, fmt.clone());
                    }
                    pending_newlines = 0;
                }
                let mut fmt = format_stack
                    .last()
                    .cloned()
                    .unwrap_or_else(|| base_format.clone());
                fmt.font_id = FontId::new(fmt.font_id.size, FontFamily::Monospace);
                job.append(&text, 0.0, fmt);
            }
            Event::SoftBreak | Event::HardBreak => {
                let fmt = format_stack
                    .last()
                    .cloned()
                    .unwrap_or_else(|| base_format.clone());
                job.append("\n", 0.0, fmt);
            }
            Event::Start(tag) => match tag {
                Tag::Paragraph => {}
                Tag::Heading { level, .. } => {
                    if pending_newlines > 0 {
                        let fmt = format_stack
                            .last()
                            .cloned()
                            .unwrap_or_else(|| base_format.clone());
                        for _ in 0..pending_newlines {
                            job.append("\n", 0.0, fmt.clone());
                        }
                        pending_newlines = 0;
                    }
                    let mut fmt = format_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| base_format.clone());
                    let scale = match level {
                        HeadingLevel::H1 => 1.6,
                        HeadingLevel::H2 => 1.4,
                        HeadingLevel::H3 => 1.2,
                        HeadingLevel::H4 => 1.1,
                        HeadingLevel::H5 => 1.05,
                        HeadingLevel::H6 => 1.0,
                    };
                    fmt.font_id = FontId::new(
                        fmt.font_id.size * scale,
                        FontFamily::Name("main_bold".into()),
                    );
                    format_stack.push(fmt);
                }
                Tag::Emphasis => {
                    let mut fmt = format_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| base_format.clone());
                    let family = match fmt.font_id.family {
                        FontFamily::Name(ref name) if name.as_ref() == "main_bold" => {
                            "main_bold_italic"
                        }
                        FontFamily::Name(ref name) if name.as_ref() == "main_bold_italic" => {
                            "main_bold_italic"
                        }
                        _ => "main_italic",
                    };
                    fmt.font_id = FontId::new(fmt.font_id.size, FontFamily::Name(family.into()));
                    format_stack.push(fmt);
                }
                Tag::Strong => {
                    let mut fmt = format_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| base_format.clone());
                    let family = match fmt.font_id.family {
                        FontFamily::Name(ref name) if name.as_ref() == "main_italic" => {
                            "main_bold_italic"
                        }
                        FontFamily::Name(ref name) if name.as_ref() == "main_bold_italic" => {
                            "main_bold_italic"
                        }
                        _ => "main_bold",
                    };
                    fmt.font_id = FontId::new(fmt.font_id.size, FontFamily::Name(family.into()));
                    format_stack.push(fmt);
                }
                Tag::CodeBlock(_) => {
                    let mut fmt = format_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| base_format.clone());
                    fmt.font_id = FontId::new(fmt.font_id.size, FontFamily::Monospace);
                    format_stack.push(fmt);
                }
                Tag::Item => {
                    if pending_newlines > 0 {
                        let fmt = format_stack
                            .last()
                            .cloned()
                            .unwrap_or_else(|| base_format.clone());
                        for _ in 0..pending_newlines {
                            job.append("\n", 0.0, fmt.clone());
                        }
                        pending_newlines = 0;
                    }
                    let mut bullet_fmt = base_format.clone();
                    bullet_fmt.color = Color32::GRAY;
                    let bullet = match list_stack.last_mut() {
                        Some(ListState::Ordered { next }) => {
                            let label = format!("{next}. ");
                            *next = next.saturating_add(1);
                            label
                        }
                        _ => "- ".to_string(),
                    };
                    job.append(&bullet, 0.0, bullet_fmt);
                }
                Tag::List(start) => {
                    match start {
                        Some(start) => list_stack.push(ListState::Ordered { next: start }),
                        None => list_stack.push(ListState::Unordered),
                    }
                }
                Tag::BlockQuote(_) | Tag::Link { .. } => {}
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Paragraph => {
                    pending_newlines = 2;
                }
                TagEnd::Item => {
                    pending_newlines = 1;
                }
                TagEnd::Heading(_) => {
                    if format_stack.len() > 1 {
                        format_stack.pop();
                    }
                    pending_newlines = 1;
                }
                TagEnd::Emphasis | TagEnd::Strong | TagEnd::CodeBlock => {
                    format_stack.pop();
                }
                TagEnd::List(_) => {
                    list_stack.pop();
                }
                TagEnd::BlockQuote | TagEnd::Link => {}
                _ => {}
            },
            Event::Rule => {
                let fmt = format_stack
                    .last()
                    .cloned()
                    .unwrap_or_else(|| base_format.clone());
                job.append("\n", 0.0, fmt);
            }
            Event::Html(_)
            | Event::InlineHtml(_)
            | Event::FootnoteReference(_)
            | Event::TaskListMarker(_)
            | Event::InlineMath(_)
            | Event::DisplayMath(_) => {}
        }
    }
}

fn default_format(ui: &Ui) -> TextFormat {
    let font_id = ui
        .style()
        .text_styles
        .get(&TextStyle::Body)
        .cloned()
        .unwrap_or_else(|| FontId::new(14.0, FontFamily::Proportional));
    TextFormat::simple(font_id, ui.visuals().text_color())
}

enum ListState {
    Unordered,
    Ordered { next: u64 },
}
