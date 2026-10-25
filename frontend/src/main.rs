mod ai_panel;
mod api;
mod app;
mod dashboard;
mod flowmap;
mod i18n;
mod icons;
mod modals;
mod network;
mod packets;
mod state;
mod toolbar;
mod util;
mod welcome;

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
