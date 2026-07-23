#!/usr/bin/env node
"use strict";

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const BINARY_NAME = "pledgerecon";
const PLATFORMS = {
  "darwin x64": "x86_64-apple-darwin",
  "darwin arm64": "aarch64-apple-darwin",
  "linux x64": "x86_64-unknown-linux-gnu",
  "win32 x64": "x86_64-pc-windows-msvc",
};

function getBinaryPath() {
  const platform = process.platform;
  const arch = process.arch;
  const key = `${platform} ${arch}`;
  const target = PLATFORMS[key];

  if (!target) {
    throw new Error(`Unsupported platform: ${key}`);
  }

  const ext = platform === "win32" ? ".exe" : "";
  const binPath = path.join(__dirname, "vendor", target, BINARY_NAME + ext);

  if (!fs.existsSync(binPath)) {
    throw new Error(
      `PledgeRecon binary not found at ${binPath}.\n` +
      `Try running "npm rebuild pledgerecon" to re-download.\n` +
      `If the problem persists, install from source: cargo install pledgerecon`
    );
  }

  return binPath;
}

function main() {
  let binPath;
  try {
    binPath = getBinaryPath();
  } catch (err) {
    process.stderr.write(err.message + "\n");
    process.exit(1);
  }

  const args = process.argv.slice(2);
  const child = spawn(binPath, args, {
    stdio: "inherit",
    windowsHide: false,
  });

  child.on("error", (err) => {
    process.stderr.write(`Failed to launch pledgerecon: ${err.message}\n`);
    process.exit(1);
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code ?? 1);
    }
  });
}

main();
