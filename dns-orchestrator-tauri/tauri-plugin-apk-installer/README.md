# tauri-plugin-apk-installer

A [Tauri v2](https://v2.tauri.app/) plugin for installing APK files on Android using the system package installer and `FileProvider`.

## Setup

Add to your `src-tauri/Cargo.toml`:

```toml
[dependencies]
tauri-plugin-apk-installer = "0.1"
```

Register the plugin in your Tauri app:

```rust
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_apk_installer::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

### Android Configuration

Your app must declare the install permission in `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
```

You also need a `FileProvider` configured with your app's package name. Add to your `AndroidManifest.xml` inside `<application>`:

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="${applicationId}.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths" />
</provider>
```

And create `res/xml/file_paths.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <external-path name="external" path="." />
    <cache-path name="cache" path="." />
</paths>
```

### Permissions

Add `apk-installer:default` to your Tauri capability file:

```json
{
  "permissions": [
    "apk-installer:default"
  ]
}
```

## Usage

### From Rust

```rust
use tauri_plugin_apk_installer::ApkInstallerExt;

app.apk_installer()
    .install_apk("/path/to/update.apk".to_string())
    .map_err(|e| format!("Failed to install APK: {}", e))?;
```

### From JavaScript

```javascript
import { invoke } from "@tauri-apps/api/core";

await invoke("plugin:apk-installer|install_apk", { path: "/path/to/update.apk" });
```

## How It Works

1. Receives an APK file path
2. On Android 7.0+ (API 24), converts the file path to a `content://` URI via `FileProvider`
3. On older Android, uses a `file://` URI directly
4. Launches the system package installer via `ACTION_VIEW` intent with `application/vnd.android.package-archive` MIME type

The plugin is a no-op on non-Android platforms and returns an error if called on desktop/iOS.

## Requirements

- Tauri v2
- Android API 24+ (minSdk)
- `REQUEST_INSTALL_PACKAGES` permission

## License

MIT
