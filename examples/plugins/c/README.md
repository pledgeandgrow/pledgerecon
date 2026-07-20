# PledgeRecon WASM Plugin — C Example (Goal 54)

This plugin flags dependencies on outdated or banned packages.

## Build

### Using wasi-sdk

```bash
# Install wasi-sdk (if not already installed)
# Download from: https://github.com/WebAssembly/wasi-sdk/releases

# Compile
/opt/wasi-sdk/bin/clang \
  --target=wasm32-wasi \
  -O2 \
  -Wl,--export=check \
  -Wl,--export=alloc \
  -o banned_packages.wasm \
  banned_packages.c
```

### Using clang (with WASI sysroot)

```bash
clang --target=wasm32-wasi \
  -O2 \
  -Wl,--export=check \
  -Wl,--export=alloc \
  -Wl,--export-memory \
  -o banned_packages.wasm \
  banned_packages.c
```

## Usage

```bash
pledgerecon scan . --wasm-rules --wasm-rule ./examples/plugins/c/banned_packages.wasm
```

## What It Does

- Flags `unsafe-pkg` as **critical** (banned internal package)
- Flags `lodash@4.17.0` as **high** (known prototype pollution)
- Flags `express@3.0.0` as **medium** (end-of-life version)
