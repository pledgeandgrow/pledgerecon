// PledgeRecon WASM Plugin — Go (TinyGo) Example (Goal 55)
//
// This plugin flags dependencies on outdated or banned packages.
// It demonstrates the PledgeRecon WASM plugin interface using Go via TinyGo.
//
// Build (with TinyGo):
//   tinygo build -o banned_packages.wasm \
//     -target wasi \
//     -wasm-abi generic \
//     -no-debug \
//     banned_packages.go
//
// Usage:
//   pledgerecon scan . --wasm-rules --wasm-rule ./examples/plugins/go/banned_packages.wasm

package main

import (
	"strings"
	"unsafe"
)

// Simple bump allocator for WASM memory
var heap [65536]byte
var heapOffset int = 64

//export alloc
func alloc(size int32) int32 {
	ptr := int32(heapOffset)
	heapOffset += int(size)
	// Align to 8 bytes
	heapOffset = (heapOffset + 7) & ^7
	if heapOffset >= len(heap) {
		return 0 // Out of memory
	}
	return ptr
}

//export check
func check(ptr int32, length int32) int32 {
	// Read input from WASM memory
	inputBytes := make([]byte, length)
	for i := int32(0); i < length; i++ {
		inputBytes[i] = *(*byte)(unsafe.Pointer(uintptr(ptr + i)))
	}
	input := string(inputBytes)

	var output string

	switch {
	case strings.Contains(input, `"unsafe-pkg"`):
		output = `{"is_vulnerable":true,"severity":"critical","summary":"Internal package 'unsafe-pkg' is banned","description":"This package has been flagged by security policy.","fix_version":null}`

	case strings.Contains(input, `"lodash"`) && strings.Contains(input, `"4.17.0"`):
		output = `{"is_vulnerable":true,"severity":"high","summary":"lodash 4.17.0 has known prototype pollution","description":"Upgrade to lodash 4.17.21 or later to fix CVE-2021-23337.","fix_version":"4.17.21"}`

	case strings.Contains(input, `"express"`) && strings.Contains(input, `"3.0.0"`):
		output = `{"is_vulnerable":true,"severity":"medium","summary":"express 3.x is end-of-life","description":"Express 3.x is no longer maintained and may have unpatched vulnerabilities.","fix_version":"4.0.0"}`

	default:
		return 0 // No finding
	}

	// Write output to WASM memory
	outputBytes := []byte(output)
	outputLen := int32(len(outputBytes))
	outputPtr := alloc(outputLen + 1) // +1 for null terminator
	if outputPtr == 0 {
		return 0
	}

	for i := int32(0); i < outputLen; i++ {
		*(*byte)(unsafe.Pointer(uintptr(outputPtr + i))) = outputBytes[i]
	}
	*(*byte)(unsafe.Pointer(uintptr(outputPtr + outputLen))) = 0 // null terminator

	return outputPtr
}

func main() {
	// TinyGo requires a main function for WASI target, but it's never called
	// by PledgeRecon — the host calls the exported `check` function directly.
}
