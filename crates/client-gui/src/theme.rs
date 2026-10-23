//! Fonts, icons and the lemon accent colour.

use egui::Color32;

use crate::settings::Theme;

pub const LEMON: Color32 = Color32::from_rgb(0xF4, 0xC4, 0x30);
/// Readable on light backgrounds too.
pub const LEMON_DEEP: Color32 = Color32::from_rgb(0xB8, 0x8A, 0x00);

pub fn install(ctx: &egui::Context, theme: Theme) {
    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    ctx.set_fonts(fonts);

    ctx.set_theme(match theme {
        Theme::System => egui::ThemePreference::System,
        Theme::Light => egui::ThemePreference::Light,
        Theme::Dark => egui::ThemePreference::Dark,
    });
    for (t, accent) in [(egui::Theme::Dark, LEMON), (egui::Theme::Light, LEMON_DEEP)] {
        ctx.style_mut_of(t, |style| {
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            // An app, not a document: clicks on text select rows, not words.
            style.interaction.selectable_labels = false;
            style.spacing.button_padding = egui::vec2(8.0, 4.0);
            let v = &mut style.visuals;
            v.hyperlink_color = accent;
            v.selection.bg_fill = accent.gamma_multiply(0.35);
            v.selection.stroke.color = accent;
        });
    }
}

/// The window icon: a lemon-coloured disc, drawn rather than shipped as a file.
pub fn icon() -> egui::IconData {
    const N: u32 = 64;
    let mut rgba = Vec::with_capacity((N * N * 4) as usize);
    let c = (N as f32 - 1.0) / 2.0;
    for y in 0..N {
        for x in 0..N {
            // A slightly wide ellipse, like a lemon.
            let dx = (x as f32 - c) / (c * 0.98);
            let dy = (y as f32 - c) / (c * 0.78);
            let d = (dx * dx + dy * dy).sqrt();
            let alpha = ((1.0 - d) * c * 0.8).clamp(0.0, 1.0);
            let shade = 1.0 - 0.18 * ((dx + dy + 1.4) / 2.8).clamp(0.0, 1.0);
            rgba.extend_from_slice(&[
                (LEMON.r() as f32 * shade) as u8,
                (LEMON.g() as f32 * shade) as u8,
                (LEMON.b() as f32 * shade) as u8,
                (alpha * 255.0) as u8,
            ]);
        }
    }
    egui::IconData {
        rgba,
        width: N,
        height: N,
    }
}
