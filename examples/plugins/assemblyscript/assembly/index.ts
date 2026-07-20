// PledgeRecon WASM Plugin — AssemblyScript Example (Goal 53)
//
// This plugin flags any dependency on "unsafe-pkg" as a critical vulnerability.
// It demonstrates the PledgeRecon WASM plugin interface using AssemblyScript.
//
// Build:
//   npm install
//   npm run build
//
// Usage:
//   pledgerecon scan . --wasm-rules --wasm-rule ./examples/plugins/assemblyscript/build/release.wasm

// ─── WASM Exports ───────────────────────────────────────────────────────

// Allocate memory for the host to write input JSON into.
// Returns a pointer to a buffer of at least `size` bytes.
let heapOffset: i32 = 64; // Start at offset 64 to leave room for static data

export function alloc(size: i32): i32 {
  const ptr = heapOffset;
  heapOffset += size;
  // Align to 8 bytes
  heapOffset = (heapOffset + 7) & ~7;
  return ptr;
}

// Shared memory export
export const memory = new WebAssembly.Memory({ initial: 1 });

// Main check function — receives a pointer+length to input JSON,
// returns a pointer to output JSON (null-terminated), or 0 for no finding.
export function check(ptr: i32, len: i32): i32 {
  // Read input JSON from memory
  const inputBytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    inputBytes[i] = load<u8>(ptr + i);
  }
  const inputStr = String.fromUTF8(inputBytes);

  // Parse JSON input
  // AssemblyScript doesn't have a built-in JSON parser, so we do simple string matching
  const isUnsafePkg = inputStr.includes('"unsafe-pkg"');
  const isOutdatedLodash = inputStr.includes('"lodash"') && inputStr.includes('"4.17.0"');

  let outputJson: string;

  if (isUnsafePkg) {
    outputJson = '{"is_vulnerable":true,"severity":"critical","summary":"Internal package \'unsafe-pkg\' is banned","description":"This package has been flagged by security policy.","fix_version":null}';
  } else if (isOutdatedLodash) {
    outputJson = '{"is_vulnerable":true,"severity":"high","summary":"lodash 4.17.0 has known prototype pollution","description":"Upgrade to lodash 4.17.21 or later to fix CVE-2021-23337.","fix_version":"4.17.21"}';
  } else {
    // Not vulnerable — return 0 (no finding)
    return 0;
  }

  // Write output JSON to memory
  const outputBytes = String.toUTF8(outputJson);
  const outputLen = outputBytes.length;
  const outputPtr = alloc(outputLen + 1); // +1 for null terminator

  for (let i = 0; i < outputLen; i++) {
    store<u8>(outputPtr + i, outputBytes[i]);
  }
  store<u8>(outputPtr + outputLen, 0); // null terminator

  return outputPtr;
}
