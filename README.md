# PMonNT

**A Process Monitor for Windows** — A modern, feature-rich alternative to Task Manager and Process Explorer, built in Rust.

![Windows](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange?logo=rust)
![License](https://img.shields.io/badge/license-MIT-blue)

<!-- 
## Screenshots
![Main Window](docs/screenshots/main.png)
-->

## Features

### Process Management
- **Tree & Grouped Views** — View processes hierarchically or grouped by name
- **Real-time Metrics** — CPU, memory, GPU utilization, I/O rates, handle/thread counts
- **Process Control** — Kill, suspend, set priority, set CPU affinity
- **Memory Dumps** — Create minidumps or full dumps for debugging
- **Digital Signatures** — Verify Authenticode signatures on executables

### Security & Threat Detection
- **Multi-Provider Malware Reputation**
  - [VirusTotal](https://www.virustotal.com/) integration
  - [MalwareBazaar](https://bazaar.abuse.ch/) lookups
  - [ThreatFox](https://threatfox.abuse.ch/) IOC matching
- **YARA Scanning** — Scan process memory with custom YARA rules
- **Handle Leak Detection** — Track handle counts over time to identify leaks

### Advanced Inspection
- **Thread Details** — View thread start addresses, CPU time, priorities, suspend counts
- **Module List** — Enumerate loaded DLLs with paths and signatures
- **Security Tokens** — Inspect process privileges, groups, integrity levels
- **Network Connections** — View active TCP/UDP connections per process
- **Service Mapping** — See which Windows services are hosted by each process

### User Experience
- **Responsive UI** — Built with [egui](https://github.com/emilk/egui) for smooth 60fps rendering
- **Multiple Themes** — Dark, Light, Green Screen (retro), High Contrast
- **Keyboard Navigation** — Full keyboard support for power users
- **Persistent Layout** — Window sizes, column order, and preferences are saved

## Requirements

- **Windows 10/11** (x64)
- **Rust 1.75+** (for building from source)
- **Administrator privileges** recommended for full functionality

## Building

```bash
git clone https://github.com/bradwilliamson/pmonnt.git
cd pmonnt
cargo build --release
```

The binary will be at `target/release/pmonnt.exe`.

### Build Requirements

- Visual Studio Build Tools (for `windows` crate)
- Rust toolchain: `rustup default stable`

## Usage

```bash
# Run normally (some features limited without admin)
pmonnt-ui.exe

# Run as Administrator for full access
# Right-click → Run as administrator
```

### API Keys (Optional)

For malware reputation lookups, configure API keys via **Windows Credential Manager** or environment variables:

| Provider | Credential Manager Name | Environment Variable |
|----------|------------------------|---------------------|
| VirusTotal | `PMonNT/VirusTotalApiKey` | `VT_API_KEY` or `PMONNT_VT_API_KEY` |
| MalwareBazaar | `PMonNT/MalwareBazaarApiKey` | `PMONNT_MB_API_KEY` |
| ThreatFox | `PMonNT/ThreatFoxApiKey` | `PMONNT_THREATFOX_KEY` |

You can also configure these in the UI under **Reputation → Settings**.

## Project Structure

```
pmonnt/
├── pmonnt-core/     # Core library (process enum, Windows APIs, providers)
│   ├── src/
│   │   ├── win/         # Windows-specific implementations
│   │   ├── providers/   # MalwareBazaar, ThreatFox integrations
│   │   ├── yara/        # YARA scanning engine
│   │   └── ...
│   └── tests/
├── pmonnt-ui/       # GUI application (egui-based)
│   └── src/
│       ├── app/         # Application state and update logic
│       ├── ui_renderer/ # UI components and dialogs
│       └── ...
├── Cargo.toml       # Workspace configuration
└── README.md
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑/↓` | Navigate process list |
| `Enter` | Expand/collapse tree node |
| `Delete` | Kill selected process |
| `Ctrl+F` | Focus search box |
| `Escape` | Clear selection / close dialog |
| `F5` | Refresh process list |

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [egui](https://github.com/emilk/egui) — Immediate mode GUI library
- [windows-rs](https://github.com/microsoft/windows-rs) — Rust bindings for Windows APIs
- [yara-x](https://github.com/VirusTotal/yara-x) — YARA rule engine
- [abuse.ch](https://abuse.ch/) — MalwareBazaar and ThreatFox APIs
