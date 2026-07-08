#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

node <<'NODE'
const fs = require("fs");
const path = require("path");

const makefile = fs.readFileSync("Makefile", "utf8");
const targets = new Set(
  [...makefile.matchAll(/^([A-Za-z0-9_.-]+):(?:\s|$)/gm)]
    .map((match) => match[1])
    .filter((target) => !target.startsWith("."))
);

const docFiles = [
  "README.md",
  "CONTRIBUTING.md",
  "docs/api-reference.md",
  "docs/architecture-design.md",
].filter((file) => fs.existsSync(file));

let failures = 0;
const fail = (message) => {
  console.error(`FAIL: ${message}`);
  failures += 1;
};

for (const file of docFiles) {
  const text = fs.readFileSync(file, "utf8");
  for (const match of text.matchAll(/\bmake\s+([A-Za-z0-9_.-]+)/g)) {
    const target = match[1];
    if (!targets.has(target)) {
      fail(`${file} documents make ${target}, but Makefile has no ${target} target`);
    }
  }
}

const requiredMentions = {
  verify: ["README.md", "CONTRIBUTING.md"],
  "docker-build": ["README.md", "CONTRIBUTING.md"],
  "release-audit": ["README.md", "CONTRIBUTING.md"],
  "browser-smoke": ["README.md", "CONTRIBUTING.md"],
  clean: ["README.md", "CONTRIBUTING.md"],
};

for (const [target, files] of Object.entries(requiredMentions)) {
  if (!targets.has(target)) {
    fail(`Makefile must keep target ${target}`);
  }

  const pattern = new RegExp(`\\bmake\\s+${target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
  for (const file of files) {
    if (!fs.existsSync(file)) {
      fail(`${file} is required for release command documentation`);
      continue;
    }

    const text = fs.readFileSync(file, "utf8");
    if (!pattern.test(text)) {
      fail(`${file} must document make ${target}`);
    }
  }
}

if (failures > 0) {
  process.exit(1);
}

console.log(`PASS: ${docFiles.length} documentation files reference existing Makefile targets`);
NODE
