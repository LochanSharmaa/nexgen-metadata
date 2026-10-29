fn main() {
    // Tauri's build script — generates the Tauri context (capabilities,
    // permissions, window configuration) for `tauri::generate_context!()`.
    // This is a no-op when building the `nexgen-server` or `generate_license`
    // binaries because they don't call `tauri::generate_context!()`.
    tauri_build::build()
}
