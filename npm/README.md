# PledgeRecon (npm)

Rust-native dependency vulnerability scanner distributed via npm.

## Installation

```bash
npm install -g pledgerecon
```

## Usage

```bash
pledgerecon scan .
pledgerecon scan . --format json --output report.json
pledgerecon scan . --reachability --triage
pledgerecon sbom . --format cyclonedx --output sbom.json
```

## How It Works

This npm package is a thin wrapper that downloads the pre-built PledgeRecon
Rust binary for your platform from [GitHub Releases](https://github.com/pledgeandgrow/pledgerecon/releases)
during `npm install`. The binary is cached in `node_modules` and invoked
directly — no Node.js runtime overhead during scanning.

### Supported Platforms

| OS | Architecture | Target |
|---|---|---|
| macOS | x64 | `x86_64-apple-darwin` |
| macOS | arm64 (Apple Silicon) | `aarch64-apple-darwin` |
| Linux | x64 | `x86_64-unknown-linux-gnu` |
| Windows | x64 | `x86_64-pc-windows-msvc` |

### Fallback

If the binary download fails, install from source:

```bash
cargo install pledgerecon
```

## License

MIT
