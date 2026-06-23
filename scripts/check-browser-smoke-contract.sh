#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

node <<'NODE'
const fs = require("fs");

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exitCode = 1;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

const adminSource = fs.readFileSync("web/admin/src/main.tsx", "utf8");
const smokeSource = fs.readFileSync("scripts/browser-smoke.sh", "utf8");
const adminRoutesBlock = adminSource.match(/const adminRoutes = \[([\s\S]*?)\];/);
if (!adminRoutesBlock) {
  fail("web/admin/src/main.tsx must define const adminRoutes");
  process.exit();
}

const adminRoutes = uniqueSorted([...adminRoutesBlock[1].matchAll(/path:\s*"([^"]+)"/g)].map((match) => match[1]));
const smokeRoutes = uniqueSorted([...smokeSource.matchAll(/open_admin_page\s+"([^"]+)"/g)].map((match) => match[1]));

const missingSmoke = adminRoutes.filter((route) => !smokeRoutes.includes(route));
const extraSmoke = smokeRoutes.filter((route) => !adminRoutes.includes(route));

if (adminRoutes.length === 0) fail("adminRoutes must contain at least one route");
if (smokeRoutes.length === 0) fail("browser-smoke.sh must cover admin routes with open_admin_page");
if (missingSmoke.length) fail(`browser-smoke.sh is missing admin route coverage: ${missingSmoke.join(", ")}`);
if (extraSmoke.length) fail(`browser-smoke.sh covers routes not present in adminRoutes: ${extraSmoke.join(", ")}`);

if (process.exitCode) process.exit(process.exitCode);
console.log("PASS: browser smoke admin route coverage matches adminRoutes");
NODE
