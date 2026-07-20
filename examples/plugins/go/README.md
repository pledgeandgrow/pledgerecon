# PledgeRecon WASM Plugin — Go (TinyGo) Example (Goal 55)

This plugin flags dependencies on outdated or banned packages.

## Build

### Using TinyGo

```bash
# Install TinyGo (if not already installed)
# See: https://tinygo.org/getting-started/install/

# Compile
tinygo build -o banned_packages.wasm \
  -target wasi \
  -wasm-abi generic \
  -no-debug \
  banned_packages.go
```

## Usage

```bash
pledgerecon scan . --wasm-rules --wasm-rule ./examples/plugins/go/banned_packages.wasm
```

## What It Does

- Flags `unsafe-pkg` as **critical** (banned internal package)
- Flags `lodash@4.17.0` as **high** (known prototype pollution)
- Flags `express@3.0.0` as **medium** (end-of-life version)

## Notes

- TinyGo's `-wasm-abi generic` flag is required to export functions with C-style ABI
- The `main()` function is required by TinyGo but never called by PledgeRecon
- Memory management uses a simple bump allocator within the WASM linear memory
