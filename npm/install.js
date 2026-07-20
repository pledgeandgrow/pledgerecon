"use strict";

const https = require("https");
const fs = require("fs");
const path = require("path");
const { createGunzip } = require("zlib");
const { pipeline } = require("stream");
const { execSync } = require("child_process");

const PACKAGE_VERSION = require("./package.json").version;
const GITHUB_REPO = "pledgeandgrow/pledgerecon";

const PLATFORMS = {
  "darwin x64": { target: "x86_64-apple-darwin", archive: "tar.gz" },
  "darwin arm64": { target: "aarch64-apple-darwin", archive: "tar.gz" },
  "linux x64": { target: "x86_64-unknown-linux-gnu", archive: "tar.gz" },
  "linux arm64": { target: "aarch64-unknown-linux-gnu", archive: "tar.gz" },
  "win32 x64": { target: "x86_64-pc-windows-msvc", archive: "zip" },
};

function getPlatformInfo() {
  const platform = process.platform;
  const arch = process.arch;
  const key = `${platform} ${arch}`;
  const info = PLATFORMS[key];

  if (!info) {
    throw new Error(`Unsupported platform: ${key}`);
  }

  return info;
}

function download(url) {
  return new Promise((resolve, reject) => {
    const followRedirect = (redirectUrl, maxRedirects = 5) => {
      if (maxRedirects === 0) {
        reject(new Error("Too many redirects"));
        return;
      }

      https.get(redirectUrl, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          followRedirect(res.headers.location, maxRedirects - 1);
          return;
        }

        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode} for ${redirectUrl}`));
          return;
        }

        resolve(res);
      }).on("error", reject);
    };

    followRedirect(url);
  });
}

async function extractTarGz(stream, destDir) {
  const tar = require("child_process");
  const tmpFile = path.join(destDir, "_download.tar.gz");

  await new Promise((resolve, reject) => {
    const file = fs.createWriteStream(tmpFile);
    stream.pipe(file);
    file.on("finish", () => {
      file.close(resolve);
    });
    file.on("error", reject);
  });

  execSync(`tar xzf "${tmpFile}" -C "${destDir}"`, { stdio: "inherit" });
  fs.unlinkSync(tmpFile);
}

async function extractZip(stream, destDir) {
  const tmpFile = path.join(destDir, "_download.zip");

  await new Promise((resolve, reject) => {
    const file = fs.createWriteStream(tmpFile);
    stream.pipe(file);
    file.on("finish", () => {
      file.close(resolve);
    });
    file.on("error", reject);
  });

  // Use PowerShell on Windows, unzip on others
  if (process.platform === "win32") {
    execSync(`powershell -Command "Expand-Archive -Path '${tmpFile}' -DestinationPath '${destDir}' -Force"`, { stdio: "inherit" });
  } else {
    execSync(`unzip -o "${tmpFile}" -d "${destDir}"`, { stdio: "inherit" });
  }

  fs.unlinkSync(tmpFile);
}

async function install() {
  let info;
  try {
    info = getPlatformInfo();
  } catch (err) {
    console.error(`[pledgerecon] ${err.message}`);
    console.error("[pledgerecon] You can install from source: cargo install pledgerecon");
    process.exit(1);
  }

  const vendorDir = path.join(__dirname, "vendor", info.target);
  fs.mkdirSync(vendorDir, { recursive: true });

  // Check if binary already exists (e.g., from a previous install)
  const ext = process.platform === "win32" ? ".exe" : "";
  const binPath = path.join(vendorDir, "pledgerecon" + ext);
  if (fs.existsSync(binPath)) {
    console.log("[pledgerecon] Binary already installed, skipping download.");
    return;
  }

  const tag = `v${PACKAGE_VERSION}`;
  const archiveExt = info.archive === "zip" ? "zip" : "tar.gz";
  const fileName = `pledgerecon-${tag}-${info.target}.${archiveExt}`;
  const url = `https://github.com/${GITHUB_REPO}/releases/download/${tag}/${fileName}`;

  console.log(`[pledgerecon] Downloading ${fileName}...`);
  console.log(`[pledgerecon] URL: ${url}`);

  try {
    const stream = await download(url);

    if (info.archive === "zip") {
      await extractZip(stream, vendorDir);
    } else {
      await extractTarGz(stream, vendorDir);
    }

    // Verify binary exists
    if (!fs.existsSync(binPath)) {
      // The archive might contain the binary at a different path, search for it
      const files = findFiles(vendorDir, "pledgerecon" + ext);
      if (files.length > 0) {
        // Move it to the expected location
        if (files[0] !== binPath) {
          fs.copyFileSync(files[0], binPath);
        }
      } else {
        throw new Error(`Binary not found after extraction. Expected: ${binPath}`);
      }
    }

    // Make executable on Unix
    if (process.platform !== "win32") {
      fs.chmodSync(binPath, 0o755);
    }

    console.log("[pledgerecon] Installation complete!");
  } catch (err) {
    console.error(`[pledgerecon] Download failed: ${err.message}`);
    console.error(`[pledgerecon] You can install from source: cargo install pledgerecon`);
    console.error(`[pledgerecon] Or download manually from: https://github.com/pledgeandgrow/pledgerecon/releases`);
    process.exit(1);
  }
}

function findFiles(dir, name) {
  const results = [];
  function walk(d) {
    const entries = fs.readdirSync(d, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(d, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.name === name) {
        results.push(fullPath);
      }
    }
  }
  walk(dir);
  return results;
}

install().catch((err) => {
  console.error(`[pledgerecon] Install error: ${err.message}`);
  process.exit(1);
});
