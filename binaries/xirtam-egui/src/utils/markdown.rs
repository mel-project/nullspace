use egui::text::LayoutJob;
use egui::{FontFamily, FontId, TextFormat, TextStyle, Ui};
use pulldown_cmark::{Event, Parser, Tag, TagEnd};

pub fn layout_md(ui: &Ui, input: &str) -> LayoutJob {
    let mut job = LayoutJob::default();
    let base_format = default_format(ui);
    let mut format_stack = vec![base_format.clone()];
    let mut pending_newline = false;

    for event in Parser::new(input) {
        match event {
            Event::Text(text) => {
                if pending_newline {
                    let fmt = format_stack.last().cloned().unwrap_or_else(|| base_format.clone());
                    job.append("\n", 0.0, fmt);
                    pending_newline = false;
                }
                let fmt = format_stack.last().cloned().unwrap_or_else(|| base_format.clone());
                job.append(&text, 0.0, fmt);
            }
            Event::Code(text) => {
                if pending_newline {
                    let fmt = format_stack.last().cloned().unwrap_or_else(|| base_format.clone());
                    job.append("\n", 0.0, fmt);
                    pending_newline = false;
                }
                let mut fmt = format_stack
                    .last()
                    .cloned()
                    .unwrap_or_else(|| base_format.clone());
                fmt.font_id = FontId::new(fmt.font_id.size, FontFamily::Monospace);
                job.append(&text, 0.0, fmt);
            }
            Event::SoftBreak | Event::HardBreak => {
                let fmt = format_stack.last().cloned().unwrap_or_else(|| base_format.clone());
                job.append("\n", 0.0, fmt);
            }
            Event::Start(tag) => match tag {
                Tag::Paragraph => {}
                Tag::Heading { .. } => {}
                Tag::Emphasis => {
                    let mut fmt = format_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| base_format.clone());
                    let family = match fmt.font_id.family {
                        FontFamily::Name(ref name) if name.as_ref() == "fantasque_bold" => {
                            "fantasque_bold_italic"
                        }
                        FontFamily::Name(ref name) if name.as_ref() == "fantasque_bold_italic" => {
                            "fantasque_bold_italic"
                        }
                        _ => "fantasque_italic",
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
                        FontFamily::Name(ref name) if name.as_ref() == "fantasque_italic" => {
                            "fantasque_bold_italic"
                        }
                        FontFamily::Name(ref name) if name.as_ref() == "fantasque_bold_italic" => {
                            "fantasque_bold_italic"
                        }
                        _ => "fantasque_bold",
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
                    let fmt = format_stack.last().cloned().unwrap_or_else(|| base_format.clone());
                    job.append("- ", 0.0, fmt);
                }
                Tag::List(_) | Tag::BlockQuote(_) | Tag::Link { .. } => {}
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::Item => {
                    pending_newline = true;
                }
                TagEnd::Emphasis | TagEnd::Strong | TagEnd::CodeBlock => {
                    format_stack.pop();
                }
                TagEnd::List(_) | TagEnd::BlockQuote | TagEnd::Link => {}
                _ => {}
            },
            Event::Rule => {
                let fmt = format_stack.last().cloned().unwrap_or_else(|| base_format.clone());
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

    job
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
