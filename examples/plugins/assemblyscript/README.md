# PledgeRecon WASM Plugin — AssemblyScript Example (Goal 53)

This plugin flags dependencies on outdated or banned packages.

## Build

### Using AssemblyScript

```bash
# Install AssemblyScript
npm install

# Compile
npm run build
```

This produces `build/release.wasm`.

## Usage

```bash
pledgerecon scan . --wasm-rules --wasm-rule ./build/release.wasm
```

## What It Does

- Flags `unsafe-pkg` as **critical** (banned internal package)
- Flags `lodash@4.17.0` as **high** (known prototype pollution)

## Notes

- AssemblyScript compiles TypeScript-like code to WASM
- No external dependencies required beyond the AssemblyScript compiler
- Uses a simple bump allocator for memory management
