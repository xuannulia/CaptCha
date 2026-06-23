#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
PIDS=()

SERVER_HTTP_ADDR="${CAPTCHA_BROWSER_SMOKE_SERVER_HTTP_ADDR:-127.0.0.1:18180}"
SERVER_GRPC_ADDR="${CAPTCHA_BROWSER_SMOKE_SERVER_GRPC_ADDR:-127.0.0.1:19190}"
RUNTIME_PORT="${CAPTCHA_BROWSER_SMOKE_RUNTIME_PORT:-15183}"
ADMIN_PORT="${CAPTCHA_BROWSER_SMOKE_ADMIN_PORT:-15184}"
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
PWCLI="${PWCLI:-$CODEX_HOME/skills/playwright/scripts/playwright_cli.sh}"

cleanup() {
	local status=$?
	if [[ -f "$PWCLI" ]]; then
		bash "$PWCLI" close-all >/dev/null 2>&1 || true
		bash "$PWCLI" kill-all >/dev/null 2>&1 || true
	fi
	for pid in "${PIDS[@]:-}"; do
		kill "$pid" 2>/dev/null || true
	done
	for pid in "${PIDS[@]:-}"; do
		wait "$pid" 2>/dev/null || true
	done
	rm -rf "$ROOT_DIR/.playwright-cli"
	if [[ "$status" -ne 0 ]]; then
		echo "browser smoke failed; logs are in $TMP_DIR" >&2
		for log in "$TMP_DIR"/*.log; do
			[[ -e "$log" ]] || continue
			echo "--- $log ---" >&2
			tail -n 200 "$log" >&2 || true
		done
	else
		rm -rf "$TMP_DIR"
	fi
}
trap cleanup EXIT

cd "$ROOT_DIR"

if ! command -v npx >/dev/null 2>&1; then
	echo "npx is required for browser smoke" >&2
	exit 1
fi
if [[ ! -f "$PWCLI" ]]; then
	echo "Playwright CLI wrapper not found: $PWCLI" >&2
	exit 1
fi

wait_http() {
	local url=$1
	for _ in {1..120}; do
		if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.25
	done
	echo "timed out waiting for $url" >&2
	return 1
}

start_bg() {
	local name=$1
	shift
	"$@" >"$TMP_DIR/$name.log" 2>&1 &
	PIDS+=("$!")
}

start_bg_in() {
	local name=$1
	local dir=$2
	shift 2
	(
		cd "$dir"
		"$@"
	) >"$TMP_DIR/$name.log" 2>&1 &
	PIDS+=("$!")
}

snapshot_contains() {
	local snapshot=$1
	local expected=$2
	if ! grep -q "$expected" "$snapshot"; then
		echo "expected snapshot to contain: $expected" >&2
		cat "$snapshot" >&2
		return 1
	fi
}

smoke_step() {
	printf 'browser smoke: %s\n' "$*" >&2
}

run_smoke_step() {
	local label=$1
	shift
	smoke_step "$label"
	"$@"
}

snapshot_ref() {
	local snapshot=$1
	local pattern=$2
	local ref
	ref="$(awk -v pattern="$pattern" '
		$0 ~ pattern {
			if (match($0, /\[ref=[^]]+\]/)) {
				value = substr($0, RSTART + 5, RLENGTH - 6)
				print value
				exit
			}
		}
	' "$snapshot")"
	if [[ -z "$ref" ]]; then
		echo "could not find snapshot ref for pattern: $pattern" >&2
		cat "$snapshot" >&2
		return 1
	fi
	printf '%s\n' "$ref"
}

json_string() {
	node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$1"
}

start_browser_session() {
	bash "$PWCLI" close-all >/dev/null 2>&1 || true
	bash "$PWCLI" kill-all >/dev/null 2>&1 || true
	bash "$PWCLI" open about:blank >"$TMP_DIR/browser-open.log"
}

pw_goto() {
	local url=$1
	local log=$2
	local encoded_url
	encoded_url="$(json_string "$url")"
	bash "$PWCLI" --json run-code "async (page) => {
		await page.goto($encoded_url);
		await page.waitForLoadState('domcontentloaded');
		return page.url();
	}" >"$log"
}

open_admin_page() {
	local path=$1
	local name=$2
	shift 2
	local snapshot="$TMP_DIR/admin-${name}.yml"
	pw_goto "http://127.0.0.1:$ADMIN_PORT$path" "$TMP_DIR/admin-${name}-open.log"
	sleep 1
	bash "$PWCLI" snapshot >"$snapshot"
	for expected in "$@"; do
		snapshot_contains "$snapshot" "$expected"
	done
}

open_runtime_challenge() {
	local captcha_type=$1
	local prompt=$2
	local mode="${3:-click}"
	local name
	name="$(printf '%s' "$captcha_type" | tr '[:upper:]' '[:lower:]' | tr '_' '-')"
	local runtime_url="http://127.0.0.1:$RUNTIME_PORT/?client_id=demo&scene=login&captcha_type=$captcha_type"
	pw_goto "$runtime_url" "$TMP_DIR/runtime-${name}-open.log"
	bash "$PWCLI" snapshot >"$TMP_DIR/runtime-${name}.yml"
	snapshot_contains "$TMP_DIR/runtime-${name}.yml" "$prompt"
	snapshot_contains "$TMP_DIR/runtime-${name}.yml" "验证"
	if [[ "$mode" == "disabled" ]]; then
		local disabled
		disabled="$(bash "$PWCLI" --json run-code 'async (page) => {
			return await page.getByRole("button", { name: "验证" }).isDisabled();
		}')"
		node -e '
			const fs = require("fs");
			const output = JSON.parse(fs.readFileSync(0, "utf8"));
			if (output.result !== true && output.result !== "true") {
				console.error(`expected verify button to be disabled, got: ${JSON.stringify(output.result)}`);
				process.exit(1);
			}
		' <<<"$disabled"
		return
	fi
	local verify_ref
	verify_ref="$(snapshot_ref "$TMP_DIR/runtime-${name}.yml" 'button "验证"')"
	bash "$PWCLI" click "$verify_ref" >"$TMP_DIR/runtime-${name}-click.log"
	sleep 1
	bash "$PWCLI" snapshot >"$TMP_DIR/runtime-${name}-after-click.yml"
	snapshot_contains "$TMP_DIR/runtime-${name}-after-click.yml" "验证失败，请重试"
}

open_runtime_pow_challenge() {
	local runtime_url="http://127.0.0.1:$RUNTIME_PORT/?client_id=demo&scene=login&captcha_type=PROOF_OF_WORK"
	pw_goto "$runtime_url" "$TMP_DIR/runtime-proof-of-work-open.log"
	sleep 2
	bash "$PWCLI" snapshot >"$TMP_DIR/runtime-proof-of-work.yml"
	snapshot_contains "$TMP_DIR/runtime-proof-of-work.yml" "正在进行安全计算"
	snapshot_contains "$TMP_DIR/runtime-proof-of-work.yml" "ticket 已签发"
}

open_runtime_random_challenge() {
	local runtime_url="http://127.0.0.1:$RUNTIME_PORT/?client_id=demo&scene=verify&captcha_type=RANDOM"
	pw_goto "$runtime_url" "$TMP_DIR/runtime-random-open.log"
	sleep 1
	bash "$PWCLI" snapshot >"$TMP_DIR/runtime-random.yml"
	if grep -q "加载失败" "$TMP_DIR/runtime-random.yml"; then
		echo "random runtime challenge failed to load" >&2
		cat "$TMP_DIR/runtime-random.yml" >&2
		return 1
	fi
	snapshot_contains "$TMP_DIR/runtime-random.yml" "验证"
}

open_demo_random_selector() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-random-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /随机验证 RANDOM/ }).click();
		await page.waitForFunction(() => {
			const values = Array.from(document.querySelectorAll(".demo-metrics dd")).map((node) => node.textContent?.trim() || "");
			return values[0] === "RANDOM" && values[1] && values[1] !== "-";
		});
		const values = await page.locator(".demo-metrics dd").evaluateAll((nodes) => nodes.map((node) => node.textContent?.trim() || ""));
		const bar = await page.locator(".browser-bar").innerText();
		return { request: values[0], actual: values[1], status: values[2], bar };
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const result = JSON.parse(output.result);
		const concrete = new Set([
			"PROOF_OF_WORK", "GESTURE", "CURVE", "CURVE_V2", "CURVE_V3",
			"SLIDER", "SLIDER_V2", "ROTATE", "CONCAT", "ROTATE_DEGREE",
			"WORD_IMAGE_CLICK", "IMAGE_CLICK", "JIGSAW", "GRID_IMAGE_CLICK"
		]);
		if (result.request !== "RANDOM" || !concrete.has(result.actual) || result.status !== "待验证" || !result.bar.includes(result.actual)) {
			console.error(`unexpected demo random result: ${JSON.stringify(result)}`);
			process.exit(1);
		}
	' <<<"$result"
}

open_demo_failure_reset_checks() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-failure-reset-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /文字点选 WORD_IMAGE_CLICK/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=WORD_IMAGE_CLICK")));
		await page.waitForTimeout(300);
		const wordFrame = page.frames().find((frame) => frame.url().includes("captcha_type=WORD_IMAGE_CLICK"));
		const wordBoard = wordFrame.locator(".board");
		await wordBoard.waitFor();
		async function clickBoardAt(board, x, y) {
			await board.dispatchEvent("click", await board.evaluate((el, point) => {
				const rect = el.getBoundingClientRect();
				return {
					clientX: rect.left + rect.width * point.x / 320,
					clientY: rect.top + rect.height * point.y / 160,
					bubbles: true,
					cancelable: true
				};
			}, { x, y }));
		}
		await clickBoardAt(wordBoard, 160, 80);
		await page.waitForTimeout(150);
		const progressResult = {
			marks: await wordFrame.locator(".mark").count(),
			footer: await wordFrame.locator("footer").innerText()
		};
		await clickBoardAt(wordBoard, 160, 80);
		await page.waitForTimeout(150);
		const cancelResult = {
			marks: await wordFrame.locator(".mark").count(),
			footer: await wordFrame.locator("footer").innerText()
		};

		await wordFrame.getByRole("button", { name: "刷新" }).click();
		await page.waitForTimeout(300);
		const targetCount = await wordFrame.locator("header strong").innerText().then((text) => {
			const prompt = text.split("：")[1] || "";
			return Math.max(3, prompt.split("、").filter(Boolean).length);
		});
		for (const point of [{ x: 20, y: 20 }, { x: 20, y: 140 }, { x: 300, y: 140 }, { x: 300, y: 20 }].slice(0, targetCount)) {
			await clickBoardAt(wordBoard, point.x, point.y);
		}
		await wordFrame.getByRole("button", { name: "验证" }).click();
		await page.waitForTimeout(800);
		const wordResult = {
			marks: await wordFrame.locator(".mark").count(),
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await wordFrame.locator("footer").innerText()
		};

		await page.getByRole("button", { name: /滑块拼图 SLIDER/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=SLIDER&")));
		await page.waitForTimeout(300);
		const sliderFrame = page.frames().find((frame) => frame.url().includes("captcha_type=SLIDER&"));
		const control = sliderFrame.locator(".drag-control");
		await control.waitFor();
		const initialSliderVerifyDisabled = await sliderFrame.getByRole("button", { name: "验证" }).isDisabled();
		async function dragControl(ratio) {
			const eventInit = await control.evaluate((el, payload) => {
				const rect = el.getBoundingClientRect();
				return {
					clientX: rect.left + rect.width * payload.ratio,
					clientY: rect.top + rect.height / 2,
					pointerId: 31,
					pointerType: "mouse",
					button: 0,
					buttons: payload.buttons,
					bubbles: true,
					cancelable: true
				};
			}, { ratio, buttons: 1 });
			await control.dispatchEvent("pointerdown", eventInit);
			await control.dispatchEvent("pointerup", { ...eventInit, buttons: 0 });
		}
		await dragControl(0.9);
		await page.waitForTimeout(900);
		const sliderResult = {
			initialVerifyDisabled: initialSliderVerifyDisabled,
			resetVerifyDisabled: await sliderFrame.getByRole("button", { name: "验证" }).isDisabled(),
			value: await control.getAttribute("aria-valuenow"),
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await sliderFrame.locator("footer").innerText()
		};
		return { progress: progressResult, cancel: cancelResult, word: wordResult, slider: sliderResult };
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const result = JSON.parse(output.result);
		if (result.progress.marks !== 1 || !result.progress.footer.includes("已选择 1/")) {
			console.error(`unexpected word click progress result: ${JSON.stringify(result.progress)}`);
			process.exit(1);
		}
		if (result.cancel.marks !== 0 || result.cancel.footer.includes("已选择")) {
			console.error(`unexpected word click cancel result: ${JSON.stringify(result.cancel)}`);
			process.exit(1);
		}
		if (result.word.marks !== 0 || result.word.status !== "失败" || result.word.sideResult !== "失败" || !result.word.footer.includes("验证失败，请重试")) {
			console.error(`unexpected word click reset result: ${JSON.stringify(result.word)}`);
			process.exit(1);
		}
		if (!result.slider.initialVerifyDisabled || !result.slider.resetVerifyDisabled || result.slider.value !== "0" || result.slider.status !== "失败" || result.slider.sideResult !== "失败" || !result.slider.footer.includes("验证失败，请重试")) {
			console.error(`unexpected slider reset result: ${JSON.stringify(result.slider)}`);
			process.exit(1);
		}
	' <<<"$result"
}

open_demo_gesture_straight_failure_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-gesture-straight-failure-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /手势描绘 GESTURE/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=GESTURE")));
		await page.waitForTimeout(300);
		const frame = page.frames().find((candidate) => candidate.url().includes("captcha_type=GESTURE"));
		const board = frame.locator(".board");
		await board.waitFor();
		const endpoints = await frame.evaluate(async () => {
			const img = document.querySelector(".board > img");
			if (!img) throw new Error("missing gesture image");
			if (!img.complete || !img.naturalWidth) {
				await new Promise((resolve, reject) => {
					img.addEventListener("load", resolve, { once: true });
					img.addEventListener("error", reject, { once: true });
				});
			}
			const canvas = document.createElement("canvas");
			canvas.width = img.naturalWidth;
			canvas.height = img.naturalHeight;
			const context = canvas.getContext("2d");
			context.drawImage(img, 0, 0);
			const data = context.getImageData(0, 0, canvas.width, canvas.height).data;
			const start = { sumX: 0, sumY: 0, count: 0 };
			const end = { sumX: 0, sumY: 0, count: 0 };
			for (let y = 0; y < canvas.height; y += 1) {
				for (let x = 0; x < canvas.width; x += 1) {
					const index = (y * canvas.width + x) * 4;
					const red = data[index];
					const green = data[index + 1];
					const blue = data[index + 2];
					const alpha = data[index + 3];
					if (alpha < 180) continue;
					if (red < 80 && green > 130 && green < 215 && blue > 100 && blue < 215) {
						start.sumX += x;
						start.sumY += y;
						start.count += 1;
					}
					if (red > 190 && green < 110 && blue < 150) {
						end.sumX += x;
						end.sumY += y;
						end.count += 1;
					}
				}
			}
			if (start.count < 20 || end.count < 20) {
				throw new Error(`could not infer gesture endpoints, start=${start.count}, end=${end.count}`);
			}
			return {
				start: { x: Math.round(start.sumX / start.count), y: Math.round(start.sumY / start.count) },
				end: { x: Math.round(end.sumX / end.count), y: Math.round(end.sumY / end.count) }
			};
		});
		const path = [];
		for (let i = 0; i < 9; i += 1) {
			const ratio = i / 8;
			path.push({
				x: Math.round(endpoints.start.x + (endpoints.end.x - endpoints.start.x) * ratio),
				y: Math.round(endpoints.start.y + (endpoints.end.y - endpoints.start.y) * ratio),
				delay: i === 0 ? 0 : 85
			});
		}
		async function eventInit(point, buttons) {
			return await board.evaluate((el, payload) => {
				const rect = el.getBoundingClientRect();
				return {
					clientX: rect.left + rect.width * payload.point.x / 320,
					clientY: rect.top + rect.height * payload.point.y / 160,
					pointerId: 39,
					pointerType: "mouse",
					button: 0,
					buttons: payload.buttons,
					bubbles: true,
					cancelable: true
				};
			}, { point, buttons });
		}
		await board.dispatchEvent("pointerdown", await eventInit(path[0], 1));
		for (const point of path.slice(1, -1)) {
			await page.waitForTimeout(point.delay);
			await board.dispatchEvent("pointermove", await eventInit(point, 1));
		}
		const last = path[path.length - 1];
		await page.waitForTimeout(last.delay);
		await board.dispatchEvent("pointerup", await eventInit(last, 0));
		await page.waitForTimeout(900);
		return {
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await frame.locator("footer").innerText(),
			points: await frame.locator(".path-dot, .path-cursor").count()
		};
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const result = JSON.parse(output.result);
		if (result.status !== "失败" || result.sideResult !== "失败" || !result.footer.includes("验证失败，请重试") || result.points !== 0) {
			console.error(`unexpected gesture straight failure result: ${JSON.stringify(result)}`);
			process.exit(1);
		}
	' <<<"$result"
}

open_demo_jigsaw_drag_swap_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-jigsaw-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /乱序拼图 JIGSAW/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=JIGSAW")));
		await page.waitForTimeout(300);
		const jigsawFrame = page.frames().find((frame) => frame.url().includes("captcha_type=JIGSAW"));
		const board = jigsawFrame.locator(".board");
		await board.waitFor();
		const tileCount = await jigsawFrame.locator(".jigsaw-tile").count();
		const targets = await jigsawFrame.evaluate(async (tileCount) => {
			const img = document.querySelector(".board > img");
			if (!img) throw new Error("missing jigsaw image");
			if (!img.complete || !img.naturalWidth) {
				await new Promise((resolve, reject) => {
					img.addEventListener("load", resolve, { once: true });
					img.addEventListener("error", reject, { once: true });
				});
			}
			const canvas = document.createElement("canvas");
			canvas.width = img.naturalWidth;
			canvas.height = img.naturalHeight;
			const context = canvas.getContext("2d");
			context.drawImage(img, 0, 0);
			const { data, width, height } = context.getImageData(0, 0, canvas.width, canvas.height);
			const cols = Math.max(1, Math.round(Math.sqrt(tileCount || 4)));
			const rows = Math.max(1, Math.round((tileCount || 4) / cols));
			const tileW = width / cols;
			const tileH = height / rows;
			function diff(x1, y1, x2, y2) {
				x1 = Math.max(0, Math.min(width - 1, Math.round(x1)));
				x2 = Math.max(0, Math.min(width - 1, Math.round(x2)));
				y1 = Math.max(0, Math.min(height - 1, Math.round(y1)));
				y2 = Math.max(0, Math.min(height - 1, Math.round(y2)));
				const a = (y1 * width + x1) * 4;
				const b = (y2 * width + x2) * 4;
				return Math.abs(data[a] - data[b]) + Math.abs(data[a + 1] - data[b + 1]) + Math.abs(data[a + 2] - data[b + 2]);
			}
			function tilePosition(index) {
				return { col: index % cols, row: Math.floor(index / cols) };
			}
			function sourcePoint(sourceIndex, localX, localY) {
				const tile = tilePosition(sourceIndex);
				return {
					x: tile.col * tileW + localX,
					y: tile.row * tileH + localY
				};
			}
			function seamScore(sourceByCell) {
				let score = 0;
				let samples = 0;
				for (let row = 0; row < rows; row += 1) {
					for (let col = 0; col < cols - 1; col += 1) {
						const left = row * cols + col;
						const right = left + 1;
						for (let y = 6; y < tileH - 6; y += 4) {
							const a = sourcePoint(sourceByCell[left], tileW - 2, y);
							const b = sourcePoint(sourceByCell[right], 2, y);
							score += diff(a.x, a.y, b.x, b.y);
							samples += 1;
						}
					}
				}
				for (let row = 0; row < rows - 1; row += 1) {
					for (let col = 0; col < cols; col += 1) {
						const top = row * cols + col;
						const bottom = top + cols;
						for (let x = 6; x < tileW - 6; x += 4) {
							const a = sourcePoint(sourceByCell[top], x, tileH - 2);
							const b = sourcePoint(sourceByCell[bottom], x, 2);
							score += diff(a.x, a.y, b.x, b.y);
							samples += 1;
						}
					}
				}
				return samples ? score / samples : Number.POSITIVE_INFINITY;
			}
			const totalTiles = cols * rows;
			if (totalTiles < 2) throw new Error(`unexpected jigsaw tile count: ${tileCount}`);
			let bestPair = [0, 1];
			let bestScore = Number.POSITIVE_INFINITY;
			for (let first = 0; first < totalTiles; first += 1) {
				for (let second = first + 1; second < totalTiles; second += 1) {
					const sourceByCell = Array.from({ length: totalTiles }, (_, index) => index);
					[sourceByCell[first], sourceByCell[second]] = [sourceByCell[second], sourceByCell[first]];
					const score = seamScore(sourceByCell);
					if (score < bestScore) {
						bestScore = score;
						bestPair = [first, second];
					}
				}
			}
			return bestPair.map((index) => {
				const tile = tilePosition(index);
				return {
					x: Math.round((tile.col + 0.5) * 320 / cols),
					y: Math.round((tile.row + 0.5) * 160 / rows),
					score: Math.round(bestScore)
				};
			});
		}, tileCount);
		async function pointerEvent(point, type, buttons) {
			return await board.evaluate((el, payload) => {
				const rect = el.getBoundingClientRect();
				return {
					clientX: rect.left + rect.width * payload.point.x / 320,
					clientY: rect.top + rect.height * payload.point.y / 160,
					pointerId: 77,
					pointerType: "mouse",
					button: 0,
					buttons: payload.buttons,
					bubbles: true,
					cancelable: true
				};
			}, { point, buttons });
		}
		const start = targets[0];
		const end = targets[1];
		await board.dispatchEvent("pointerdown", await pointerEvent(start, "pointerdown", 1));
		for (let i = 1; i <= 4; i += 1) {
			await page.waitForTimeout(80);
			await board.dispatchEvent("pointermove", await pointerEvent({
				x: Math.round(start.x + (end.x - start.x) * i / 5),
				y: Math.round(start.y + (end.y - start.y) * i / 5)
			}, "pointermove", 1));
		}
		await page.waitForTimeout(90);
		await board.dispatchEvent("pointerup", await pointerEvent(end, "pointerup", 0));
		await page.waitForFunction(() => document.querySelector(".browser-bar strong")?.textContent?.trim() === "通过");
		return {
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await jigsawFrame.locator("footer").innerText(),
			tileCount,
			targets
		};
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const result = JSON.parse(output.result);
		if (result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发") || result.tileCount !== 4) {
			console.error(`unexpected jigsaw drag swap result: ${JSON.stringify(result)}`);
			process.exit(1);
		}
	' <<<"$result"
}

open_demo_point_click_success_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-point-click-success-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		const cases = [
			{
				type: "WORD_IMAGE_CLICK",
				button: /文字点选 WORD_IMAGE_CLICK/
			},
			{
				type: "IMAGE_CLICK",
				button: /图标点选 IMAGE_CLICK/
			}
		];
		const results = [];
		for (const item of cases) {
			await page.getByRole("button", { name: item.button }).click();
			await page.waitForFunction((type) => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes(`captcha_type=${type}`)), item.type);
			await page.waitForTimeout(300);
			const frame = page.frames().find((candidate) => candidate.url().includes(`captcha_type=${item.type}`));
			const board = frame.locator(".board");
			await board.waitFor();
			const points = await frame.evaluate(async (type) => {
				const promptText = document.querySelector("header strong")?.textContent || "";
				const targetCount = Math.max(1, (promptText.split("：")[1] || "").split("、").filter(Boolean).length);
				const palette = type === "WORD_IMAGE_CLICK"
					? [
						{ r: 31, g: 41, b: 55 },
						{ r: 37, g: 99, b: 235 },
						{ r: 190, g: 24, b: 93 },
						{ r: 126, g: 34, b: 206 }
					]
					: [
						{ r: 37, g: 99, b: 235 },
						{ r: 20, g: 184, b: 166 },
						{ r: 225, g: 29, b: 72 }
					];
				const img = document.querySelector(".board > img");
				if (!img) throw new Error("missing point-click image");
				if (!img.complete || !img.naturalWidth) {
					await new Promise((resolve, reject) => {
						img.addEventListener("load", resolve, { once: true });
						img.addEventListener("error", reject, { once: true });
					});
				}
				const canvas = document.createElement("canvas");
				canvas.width = img.naturalWidth;
				canvas.height = img.naturalHeight;
				const context = canvas.getContext("2d");
				context.drawImage(img, 0, 0);
				const { data, width, height } = context.getImageData(0, 0, canvas.width, canvas.height);
				function closeTo(pixel, color) {
					return Math.abs(pixel.r - color.r) + Math.abs(pixel.g - color.g) + Math.abs(pixel.b - color.b) < 18;
				}
				const points = [];
				for (let index = 0; index < targetCount; index += 1) {
					const color = palette[index % palette.length];
					let count = 0;
					let minX = width;
					let minY = height;
					let maxX = -1;
					let maxY = -1;
					for (let y = 0; y < height; y += 1) {
						for (let x = 0; x < width; x += 1) {
							const offset = (y * width + x) * 4;
							const pixel = { r: data[offset], g: data[offset + 1], b: data[offset + 2], a: data[offset + 3] };
							if (pixel.a > 180 && closeTo(pixel, color)) {
								count += 1;
								minX = Math.min(minX, x);
								minY = Math.min(minY, y);
								maxX = Math.max(maxX, x);
								maxY = Math.max(maxY, y);
							}
						}
					}
					if (count < 60) {
						throw new Error(`could not infer ${type} target ${index}: count=${count}`);
					}
					points.push({
						x: Math.round((minX + maxX) / 2),
						y: Math.round((minY + maxY) / 2),
						count
					});
				}
				return points;
			}, item.type);
			async function clickBoardAt(point) {
				await board.dispatchEvent("click", await board.evaluate((el, payload) => {
					const rect = el.getBoundingClientRect();
					return {
						clientX: rect.left + rect.width * payload.x / 320,
						clientY: rect.top + rect.height * payload.y / 160,
						bubbles: true,
						cancelable: true
					};
				}, point));
			}
			await clickBoardAt(points[0]);
			await page.waitForTimeout(90);
			await clickBoardAt(points[0]);
			await page.waitForTimeout(90);
			const canceledMarks = await frame.locator(".mark").count();
			for (const point of points) {
				await clickBoardAt(point);
				await page.waitForTimeout(90);
			}
			await frame.getByRole("button", { name: "验证" }).click();
			await page.waitForFunction(() => document.querySelector(".browser-bar strong")?.textContent?.trim() === "通过");
			results.push({
				type: item.type,
				status: await page.locator(".browser-bar strong").innerText(),
				sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
				footer: await frame.locator("footer").innerText(),
				marks: await frame.locator(".mark").count(),
				canceledMarks,
				expectedMarks: points.length
			});
		}
		return results;
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const results = JSON.parse(output.result);
		for (const result of results) {
			if (result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发") || result.marks !== result.expectedMarks || result.canceledMarks !== 0) {
				console.error(`unexpected point click success result: ${JSON.stringify(result)}`);
				process.exit(1);
			}
		}
	' <<<"$result"
}

open_demo_grid_click_success_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-grid-click-success-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /图片格子 GRID_IMAGE_CLICK/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=GRID_IMAGE_CLICK")));
		await page.waitForTimeout(300);
		const frame = page.frames().find((candidate) => candidate.url().includes("captcha_type=GRID_IMAGE_CLICK"));
		const board = frame.locator(".board");
		await board.waitFor();
		const targets = await frame.evaluate(async () => {
			const img = document.querySelector(".board > img");
			if (!img) throw new Error("missing grid image");
			if (!img.complete || !img.naturalWidth) {
				await new Promise((resolve, reject) => {
					img.addEventListener("load", resolve, { once: true });
					img.addEventListener("error", reject, { once: true });
				});
			}
			const canvas = document.createElement("canvas");
			canvas.width = img.naturalWidth;
			canvas.height = img.naturalHeight;
			const context = canvas.getContext("2d");
			context.drawImage(img, 0, 0);
			const { data, width, height } = context.getImageData(0, 0, canvas.width, canvas.height);
			const cols = 3;
			const rows = 3;
			const counts = Array.from({ length: cols * rows }, (_, index) => ({ index, count: 0 }));
			for (let y = 0; y < height; y += 1) {
				for (let x = 0; x < width; x += 1) {
					const offset = (y * width + x) * 4;
					const red = data[offset];
					const green = data[offset + 1];
					const blue = data[offset + 2];
					const alpha = data[offset + 3];
					if (alpha > 220 && red >= 20 && red <= 75 && green >= 75 && green <= 130 && blue >= 180 && blue <= 255) {
						const col = Math.min(cols - 1, Math.floor(x / (width / cols)));
						const row = Math.min(rows - 1, Math.floor(y / (height / rows)));
						counts[row * cols + col].count += 1;
					}
				}
			}
			const targets = counts
				.filter((item) => item.count > 900)
				.sort((a, b) => b.count - a.count)
				.slice(0, 3)
				.map((item) => ({
					x: Math.round(((item.index % cols) + 0.5) * 300 / cols),
					y: Math.round((Math.floor(item.index / cols) + 0.5) * 300 / rows),
					count: item.count
				}));
			if (targets.length !== 3) throw new Error(`unexpected grid targets: ${JSON.stringify(counts)}`);
			return targets;
		});
		async function clickBoardAt(point) {
			await board.dispatchEvent("click", await board.evaluate((el, payload) => {
				const rect = el.getBoundingClientRect();
				return {
					clientX: rect.left + rect.width * payload.x / 300,
					clientY: rect.top + rect.height * payload.y / 300,
					bubbles: true,
					cancelable: true
				};
			}, point));
		}
		await clickBoardAt(targets[0]);
		await page.waitForTimeout(90);
		await clickBoardAt(targets[0]);
		await page.waitForTimeout(90);
		const canceledMarks = await frame.locator(".mark").count();
		for (const point of targets) {
			await clickBoardAt(point);
			await page.waitForTimeout(90);
		}
		await frame.getByRole("button", { name: "验证" }).click();
		await page.waitForFunction(() => document.querySelector(".browser-bar strong")?.textContent?.trim() === "通过");
		return {
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await frame.locator("footer").innerText(),
			marks: await frame.locator(".mark").count(),
			canceledMarks,
			targets
		};
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const result = JSON.parse(output.result);
		if (result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发") || result.marks !== 3 || result.canceledMarks !== 0) {
			console.error(`unexpected grid click success result: ${JSON.stringify(result)}`);
			process.exit(1);
		}
	' <<<"$result"
}

open_demo_grid_click_failure_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-grid-click-failure-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /图片格子 GRID_IMAGE_CLICK/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=GRID_IMAGE_CLICK")));
		await page.waitForTimeout(300);
		const frame = page.frames().find((candidate) => candidate.url().includes("captcha_type=GRID_IMAGE_CLICK"));
		const board = frame.locator(".board");
		await board.waitFor();
		const wrongCells = await frame.evaluate(async () => {
			const img = document.querySelector(".board > img");
			if (!img) throw new Error("missing grid image");
			if (!img.complete || !img.naturalWidth) {
				await new Promise((resolve, reject) => {
					img.addEventListener("load", resolve, { once: true });
					img.addEventListener("error", reject, { once: true });
				});
			}
			const canvas = document.createElement("canvas");
			canvas.width = img.naturalWidth;
			canvas.height = img.naturalHeight;
			const context = canvas.getContext("2d");
			context.drawImage(img, 0, 0);
			const { data, width, height } = context.getImageData(0, 0, canvas.width, canvas.height);
			const cols = 3;
			const rows = 3;
			const counts = Array.from({ length: cols * rows }, (_, index) => ({ index, count: 0 }));
			for (let y = 0; y < height; y += 1) {
				for (let x = 0; x < width; x += 1) {
					const offset = (y * width + x) * 4;
					const red = data[offset];
					const green = data[offset + 1];
					const blue = data[offset + 2];
					const alpha = data[offset + 3];
					if (alpha > 220 && red >= 20 && red <= 75 && green >= 75 && green <= 130 && blue >= 180 && blue <= 255) {
						const col = Math.min(cols - 1, Math.floor(x / (width / cols)));
						const row = Math.min(rows - 1, Math.floor(y / (height / rows)));
						counts[row * cols + col].count += 1;
					}
				}
			}
			const targetIndexes = new Set(counts.filter((item) => item.count > 900).map((item) => item.index));
			const wrong = counts
				.filter((item) => !targetIndexes.has(item.index))
				.slice(0, 3)
				.map((item) => ({
					x: Math.round(((item.index % cols) + 0.5) * 300 / cols),
					y: Math.round((Math.floor(item.index / cols) + 0.5) * 300 / rows),
					index: item.index
				}));
			if (wrong.length !== 3) throw new Error(`unexpected wrong grid cells: ${JSON.stringify(counts)}`);
			return wrong;
		});
		async function clickBoardAt(point) {
			await board.dispatchEvent("click", await board.evaluate((el, payload) => {
				const rect = el.getBoundingClientRect();
				return {
					clientX: rect.left + rect.width * payload.x / 300,
					clientY: rect.top + rect.height * payload.y / 300,
					bubbles: true,
					cancelable: true
				};
			}, point));
		}
		for (const point of wrongCells) {
			await clickBoardAt(point);
			await page.waitForTimeout(90);
		}
		await frame.getByRole("button", { name: "验证" }).click();
		await page.waitForFunction(() => document.querySelector(".browser-bar strong")?.textContent?.trim() === "失败");
		await page.waitForTimeout(400);
		return {
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await frame.locator("footer").innerText(),
			marks: await frame.locator(".mark").count(),
			wrongCells
		};
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const result = JSON.parse(output.result);
		if (result.status !== "失败" || result.sideResult !== "失败" || !result.footer.includes("验证失败，请重试") || result.marks !== 0) {
			console.error(`unexpected grid click failure result: ${JSON.stringify(result)}`);
			process.exit(1);
		}
	' <<<"$result"
}

open_demo_curve_wrong_offset_failure_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-curve-wrong-offset-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		const cases = [
			{ type: "CURVE", button: /滑动曲线 CURVE/, frameNeedle: "captcha_type=CURVE&", pointerId: 81 },
			{ type: "CURVE_V2", button: /滑动曲线 V2 CURVE_V2/, frameNeedle: "captcha_type=CURVE_V2", pointerId: 82 },
			{ type: "CURVE_V3", button: /滑动曲线 V3 CURVE_V3/, frameNeedle: "captcha_type=CURVE_V3", pointerId: 83 }
		];
		const results = [];
		for (const item of cases) {
			await page.getByRole("button", { name: item.button }).click();
			await page.waitForFunction((needle) => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes(needle)), item.frameNeedle);
			await page.waitForTimeout(300);
			const frame = page.frames().find((candidate) => candidate.url().includes(item.frameNeedle));
			const control = frame.locator(".slider-move");
			await control.waitFor();
			const max = Number(await control.getAttribute("aria-valuemax"));
			const wrongValue = Math.min(28, Math.max(8, max - 18));
			async function eventInit(value, buttons) {
				return await control.evaluate((el, payload) => {
					const rect = el.getBoundingClientRect();
					return {
						clientX: rect.left + 31.5 + payload.value,
						clientY: rect.top + rect.height / 2,
						pointerId: payload.pointerId,
						pointerType: "mouse",
						button: 0,
						buttons: payload.buttons,
						bubbles: true,
						cancelable: true
					};
				}, { value, max, buttons, pointerId: item.pointerId });
			}
			await control.dispatchEvent("pointerdown", await eventInit(0, 1));
			await page.waitForTimeout(160);
			await control.dispatchEvent("pointermove", await eventInit(wrongValue, 1));
			await page.waitForTimeout(180);
			await control.dispatchEvent("pointerup", await eventInit(wrongValue, 0));
			await page.waitForFunction(() => document.querySelector(".browser-bar strong")?.textContent?.trim() === "失败");
			await page.waitForTimeout(300);
			results.push({
				type: item.type,
				status: await page.locator(".browser-bar strong").innerText(),
				sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
				footer: await frame.locator("footer").innerText(),
				buttonDisabled: await frame.locator("footer button").isDisabled()
			});
		}
		return results;
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const results = JSON.parse(output.result);
		for (const result of results) {
			if (result.status !== "失败" || result.sideResult !== "失败" || !result.footer.includes("验证失败，请重试") || !result.buttonDisabled) {
				console.error(`unexpected curve wrong offset failure result: ${JSON.stringify(result)}`);
				process.exit(1);
			}
		}
	' <<<"$result"
}

open_demo_curve_match_success_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-curve-match-success-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		async function inferCurveTargetX(frame) {
			return await frame.evaluate(async () => {
				const canvas = document.querySelector("#tianai-captcha-curve-bg-canvas");
				const image = document.querySelector("#tianai-captcha-slider-bg-img");
				const control = document.querySelector(".slider-move");
				if (!canvas || !image || !control) throw new Error("missing curve match elements");
				await new Promise((resolve) => requestAnimationFrame(resolve));
				const max = Number(control.getAttribute("aria-valuemax") || 0);
				const profile = JSON.parse(canvas.dataset.curveProfile || "{}");
				const moving = Array.isArray(profile.moving_points) ? profile.moving_points : [];
				const drives = Array.isArray(profile.drive_points) ? profile.drive_points : [];
				if (Object.prototype.hasOwnProperty.call(profile, "fixed_points")) {
					throw new Error("curve profile must not expose fixed_points");
				}
				if (moving.length < 12 || drives.length !== moving.length) {
					throw new Error(`invalid curve profile: moving=${moving.length}, drives=${drives.length}`);
				}
				const img = new Image();
				img.decoding = "async";
				img.src = image.currentSrc || image.src;
				await img.decode();
				const width = img.naturalWidth;
				const height = img.naturalHeight;
				const bitmap = document.createElement("canvas");
				bitmap.width = width;
				bitmap.height = height;
				const context = bitmap.getContext("2d", { willReadFrequently: true });
				context.drawImage(img, 0, 0, width, height);
				const data = context.getImageData(0, 0, width, height);
				const style = profile.visual_style || (profile.variant === 2 ? "dual-noise" : profile.variant === 3 ? "ring-deform" : "single-rope");
				function offsetOf(x, y) {
					return (y * data.width + x) * 4;
				}
				function isTargetPixel(red, green, blue, alpha) {
					if (alpha < 30) return false;
					const saturation = Math.max(red, green, blue) - Math.min(red, green, blue);
					if (style === "dual-noise") {
						return red > 165 && blue > 135 && green < 185 && saturation > 40;
					}
					if (style === "ring-deform") {
						return red > 235 && green >= 90 && green <= 145 && blue >= 90 && blue <= 130 && saturation > 95;
					}
					return blue > 180 && green > 150 && red < 180 && blue - red > 60;
				}
				const targetMask = new Uint8Array(width * height);
				let targetPixelCount = 0;
				for (let y = 0; y < height; y += 1) {
					for (let x = 0; x < width; x += 1) {
						const offset = offsetOf(x, y);
						if (isTargetPixel(data.data[offset], data.data[offset + 1], data.data[offset + 2], data.data[offset + 3])) {
							targetMask[y * width + x] = 1;
							targetPixelCount += 1;
						}
					}
				}
				if (targetPixelCount < moving.length * 4) {
					throw new Error(`could not segment curve target pixels: ${targetPixelCount}`);
				}
				const candidateCanvas = document.createElement("canvas");
				candidateCanvas.width = width;
				candidateCanvas.height = height;
				const candidateContext = candidateCanvas.getContext("2d", { willReadFrequently: true });
				candidateContext.lineCap = "round";
				candidateContext.lineJoin = "round";
				candidateContext.strokeStyle = "#000";
				candidateContext.lineWidth = style === "dual-noise" ? 12 : style === "ring-deform" ? 8 : 10;
				function candidateOverlapScore(points) {
					candidateContext.clearRect(0, 0, width, height);
					candidateContext.beginPath();
					candidateContext.moveTo(points[0].x, points[0].y);
					for (let index = 1; index < points.length; index += 1) {
						candidateContext.lineTo(points[index].x, points[index].y);
					}
					candidateContext.stroke();
					const candidateData = candidateContext.getImageData(0, 0, width, height).data;
					let candidateCount = 0;
					let overlap = 0;
					for (let index = 0; index < width * height; index += 1) {
						if (candidateData[index * 4 + 3] <= 20) continue;
						candidateCount += 1;
						if (targetMask[index]) overlap += 1;
					}
					if (!candidateCount || !targetPixelCount) return 0;
					const precision = overlap / candidateCount;
					const recall = overlap / targetPixelCount;
					return precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
				}
				let best = { value: 0, score: -1 };
				for (let candidate = 0; candidate <= max; candidate += 1) {
					const predictedPoints = [];
					for (let index = 1; index < moving.length - 1; index += 1) {
						const drive = drives[index] || { x: 0, y: 0 };
						predictedPoints.push({
							x: Number(moving[index].x) - Number(drive.x || 0) * candidate,
							y: Number(moving[index].y) - Number(drive.y || 0) * candidate
						});
					}
					const score = candidateOverlapScore(predictedPoints);
					if (score > best.score) {
						best = { value: candidate, score };
					}
				}
				if (!Number.isFinite(best.score) || best.score < 0.24) {
					throw new Error(`could not infer curve match target from pixels: ${JSON.stringify(best)}`);
				}
				return best.value;
			});
		}
		const cases = [
			{ type: "CURVE", button: /滑动曲线 CURVE/, frameNeedle: "captcha_type=CURVE&", pointerId: 42 },
			{ type: "CURVE_V2", button: /滑动曲线 V2 CURVE_V2/, frameNeedle: "captcha_type=CURVE_V2", pointerId: 43 },
			{ type: "CURVE_V3", button: /滑动曲线 V3 CURVE_V3/, frameNeedle: "captcha_type=CURVE_V3", pointerId: 44 }
		];
		const results = [];
		for (const item of cases) {
			await page.getByRole("button", { name: item.button }).click();
			await page.waitForFunction((needle) => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes(needle)), item.frameNeedle);
			await page.waitForTimeout(300);
			const frame = page.frames().find((candidate) => candidate.url().includes(item.frameNeedle));
			const control = frame.locator(".slider-move");
			await control.waitFor();
			const max = Number(await control.getAttribute("aria-valuemax"));
			const target = Math.max(0, Math.min(max, await inferCurveTargetX(frame)));
			async function eventInit(value, buttons) {
				return await control.evaluate((el, payload) => {
					const rect = el.getBoundingClientRect();
					return {
						clientX: rect.left + 31.5 + payload.value,
						clientY: rect.top + rect.height / 2,
						pointerId: payload.pointerId,
						pointerType: "mouse",
						button: 0,
						buttons: payload.buttons,
						bubbles: true,
						cancelable: true
					};
				}, { value, max, buttons, pointerId: item.pointerId });
			}
			const steps = [0, Math.round(target * 0.32), Math.round(target * 0.67), target];
			await control.dispatchEvent("pointerdown", await eventInit(steps[0], 1));
			for (const value of steps.slice(1, -1)) {
				await page.waitForTimeout(150);
				await control.dispatchEvent("pointermove", await eventInit(value, 1));
			}
			await page.waitForTimeout(180);
			await control.dispatchEvent("pointerup", await eventInit(target, 0));
			await page.waitForFunction(() => {
				const status = document.querySelector(".browser-bar strong")?.textContent?.trim();
				return status === "通过" || status === "失败";
			});
			results.push({
				type: item.type,
				target,
				status: await page.locator(".browser-bar strong").innerText(),
				sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
				footer: await frame.locator("footer").innerText(),
				rootCount: await frame.locator("#tianai-captcha.tianai-captcha-slider").count(),
				bgCanvasCount: await frame.locator("#tianai-captcha-slider-bg-canvas").count(),
				moveCanvasCount: await frame.locator("#tianai-captcha-curve-bg-canvas").count(),
				endpointCount: await frame.locator(".tianai-captcha-curve-ball-div").count(),
				pieceCount: await frame.locator(".curve-piece").count()
			});
		}
		return results;
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		if (!Object.prototype.hasOwnProperty.call(output, "result")) {
			console.error(`curve match smoke did not return a result: ${JSON.stringify(output)}`);
			process.exit(1);
		}
		const results = JSON.parse(output.result);
		for (const result of results) {
			if (result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发") || result.rootCount !== 1 || result.bgCanvasCount !== 1 || result.moveCanvasCount !== 1 || result.endpointCount !== 2 || result.pieceCount !== 0) {
				console.error(`unexpected curve match success result: ${JSON.stringify(result)}`);
				process.exit(1);
			}
		}
	' <<<"$result"
}

open_demo_path_success_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-path-success-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		function withDelays(points, baseDelay = 90) {
			return points.map((point, index) => ({ ...point, delay: index === 0 ? 0 : baseDelay + (index % 3) * 20 }));
		}
		async function inferGesturePath(frame) {
			const points = await frame.evaluate(async () => {
				const img = document.querySelector(".board > img");
				if (!img) throw new Error("missing gesture image");
				if (!img.complete || !img.naturalWidth) {
					await new Promise((resolve, reject) => {
						img.addEventListener("load", resolve, { once: true });
						img.addEventListener("error", reject, { once: true });
					});
				}
				const canvas = document.createElement("canvas");
				canvas.width = img.naturalWidth;
				canvas.height = img.naturalHeight;
				const context = canvas.getContext("2d");
				context.drawImage(img, 0, 0);
				const data = context.getImageData(0, 0, canvas.width, canvas.height).data;
				const width = canvas.width;
				const height = canvas.height;
				const mask = new Uint8Array(width * height);
				const guidePixels = [];
				const start = { sumX: 0, sumY: 0, count: 0 };
				const end = { sumX: 0, sumY: 0, count: 0 };
				for (let y = 0; y < height; y += 1) {
					for (let x = 0; x < width; x += 1) {
						const index = (y * width + x) * 4;
						const red = data[index];
						const green = data[index + 1];
						const blue = data[index + 2];
						const alpha = data[index + 3];
						if (alpha < 180) continue;
						const isGuide = (red > 90 && red < 170 && green < 120 && blue > 150) ||
							(red > 20 && red < 80 && green > 70 && green < 130 && blue > 170) ||
							(red > 10 && red < 70 && green > 200 && blue > 200) ||
							(red > 25 && red < 75 && green > 85 && green < 145 && blue < 70) ||
							(red > 95 && red < 175 && green > 35 && green < 105 && blue < 80);
						if (isGuide) {
							mask[y * width + x] = 1;
							guidePixels.push({ x, y, index: y * width + x });
						}
						if (red < 80 && green > 130 && green < 215 && blue > 100 && blue < 215) {
							start.sumX += x;
							start.sumY += y;
							start.count += 1;
						}
						if (red > 190 && green < 110 && blue < 150) {
							end.sumX += x;
							end.sumY += y;
							end.count += 1;
						}
					}
				}
				if (guidePixels.length < 120 || start.count < 20 || end.count < 20) {
					throw new Error(`could not infer gesture pixels: guide=${guidePixels.length}, start=${start.count}, end=${end.count}`);
				}
				const startPoint = start.count > 0
					? { x: Math.round(start.sumX / start.count), y: Math.round(start.sumY / start.count) }
					: guidePixels[0];
				const endPoint = end.count > 0
					? { x: Math.round(end.sumX / end.count), y: Math.round(end.sumY / end.count) }
					: guidePixels[guidePixels.length - 1];
				function nearestGuideIndex(point) {
					let best = guidePixels[0];
					let bestDistance = Number.POSITIVE_INFINITY;
					for (const candidate of guidePixels) {
						const distance = (candidate.x - point.x) ** 2 + (candidate.y - point.y) ** 2;
						if (distance < bestDistance) {
							bestDistance = distance;
							best = candidate;
						}
					}
					return best.index;
				}
				const startIndex = nearestGuideIndex(startPoint);
				const endIndex = nearestGuideIndex(endPoint);
				const previous = new Int32Array(width * height);
				previous.fill(-2);
				const queue = new Int32Array(width * height);
				let head = 0;
				let tail = 0;
				queue[tail++] = startIndex;
				previous[startIndex] = -1;
				const offsets = [-width - 1, -width, -width + 1, -1, 1, width - 1, width, width + 1];
				while (head < tail && previous[endIndex] === -2) {
					const current = queue[head++];
					const x = current % width;
					const y = Math.floor(current / width);
					for (const offset of offsets) {
						const next = current + offset;
						const nx = next % width;
						const ny = Math.floor(next / width);
						if (next < 0 || next >= previous.length || Math.abs(nx - x) > 1 || Math.abs(ny - y) > 1) continue;
						if (!mask[next] || previous[next] !== -2) continue;
						previous[next] = current;
						queue[tail++] = next;
						if (next === endIndex) break;
					}
				}
				if (previous[endIndex] === -2) {
					throw new Error(`could not trace gesture path: guide=${guidePixels.length}, start=${startIndex}, end=${endIndex}`);
				}
				const rawPath = [];
				for (let cursor = endIndex; cursor >= 0; cursor = previous[cursor]) {
					rawPath.push({ x: cursor % width, y: Math.floor(cursor / width) });
					if (previous[cursor] === -1) break;
				}
				rawPath.reverse();
				function distance(a, b) {
					return Math.hypot(a.x - b.x, a.y - b.y);
				}
				function resamplePath(path, count) {
					const length = path.slice(1).reduce((sum, point, index) => sum + distance(path[index], point), 0);
					if (length <= 0) return [startPoint, endPoint];
					const sampled = [];
					let segmentIndex = 1;
					let segmentStart = 0;
					for (let i = 0; i < count; i += 1) {
						const target = length * i / (count - 1);
						while (segmentIndex < path.length - 1) {
							const segmentLength = distance(path[segmentIndex - 1], path[segmentIndex]);
							if (segmentStart + segmentLength >= target) break;
							segmentStart += segmentLength;
							segmentIndex += 1;
						}
						const a = path[segmentIndex - 1];
						const b = path[segmentIndex];
						const segmentLength = Math.max(1, distance(a, b));
						const ratio = Math.max(0, Math.min(1, (target - segmentStart) / segmentLength));
						sampled.push({
							x: Math.round(a.x + (b.x - a.x) * ratio),
							y: Math.round(a.y + (b.y - a.y) * ratio)
						});
					}
					return sampled;
				}
				const sampled = resamplePath(rawPath, 28);
				sampled[0] = startPoint;
				sampled[sampled.length - 1] = endPoint;
				return sampled;
			});
			if (points.length < 12) {
				throw new Error(`insufficient inferred gesture path: ${JSON.stringify(points)}`);
			}
			return withDelays(points, 80);
		}
		const cases = [
			{
				type: "GESTURE",
				button: /手势描绘 GESTURE/,
				frameNeedle: "captcha_type=GESTURE",
				pointerId: 41,
				inferPath: inferGesturePath
			}
		];
		const results = [];
		for (const item of cases) {
			await page.getByRole("button", { name: item.button }).click();
			await page.waitForFunction((needle) => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes(needle)), item.frameNeedle);
			await page.waitForTimeout(300);
			const frame = page.frames().find((candidate) => candidate.url().includes(item.frameNeedle));
			const board = frame.locator(".board");
			await board.waitFor();
			const path = item.inferPath ? await item.inferPath(frame) : item.path;
			async function eventInit(point, buttons) {
				return await board.evaluate((el, payload) => {
					const rect = el.getBoundingClientRect();
					return {
						clientX: rect.left + rect.width * payload.point.x / 320,
						clientY: rect.top + rect.height * payload.point.y / 160,
						pointerId: payload.pointerId,
						pointerType: "mouse",
						button: 0,
						buttons: payload.buttons,
						bubbles: true,
						cancelable: true
					};
				}, { point, buttons, pointerId: item.pointerId });
			}
			await board.dispatchEvent("pointerdown", await eventInit(path[0], 1));
			for (const point of path.slice(1, -1)) {
				await page.waitForTimeout(point.delay);
				await board.dispatchEvent("pointermove", await eventInit(point, 1));
			}
			const last = path[path.length - 1];
			await page.waitForTimeout(last.delay);
			await board.dispatchEvent("pointerup", await eventInit(last, 0));
			await page.waitForTimeout(1400);
			results.push({
				type: item.type,
				points: path.length,
				status: await page.locator(".browser-bar strong").innerText(),
				sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
				footer: await frame.locator("footer").innerText()
			});
		}
		return results;
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const results = JSON.parse(output.result);
		for (const result of results) {
			if (result.points < 4 || result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发")) {
				console.error(`unexpected path success result: ${JSON.stringify(result)}`);
				process.exit(1);
			}
		}
	' <<<"$result"
}

open_demo_slider_success_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-slider-success-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		const cases = [
			{ type: "SLIDER", button: /滑块拼图 SLIDER/, frameNeedle: "captcha_type=SLIDER&" },
			{ type: "SLIDER_V2", button: /滑块增强 SLIDER_V2/, frameNeedle: "captcha_type=SLIDER_V2" }
		];
		const results = [];
		for (const item of cases) {
			await page.getByRole("button", { name: item.button }).click();
			await page.waitForFunction((needle) => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes(needle)), item.frameNeedle);
			await page.waitForTimeout(300);
			const frame = page.frames().find((candidate) => candidate.url().includes(item.frameNeedle));
			const control = frame.locator(".drag-control");
			const piece = frame.locator(".piece");
			const boardImage = frame.locator(".board > img").first();
			await control.waitFor();
			await piece.waitFor();
			await boardImage.waitFor();
			const target = await frame.evaluate(async () => {
				async function imageDataFor(selector) {
					const img = document.querySelector(selector);
					if (!img) throw new Error(`missing image ${selector}`);
					if (!img.complete || !img.naturalWidth) {
						await new Promise((resolve, reject) => {
							img.addEventListener("load", resolve, { once: true });
							img.addEventListener("error", reject, { once: true });
						});
					}
					const canvas = document.createElement("canvas");
					canvas.width = img.naturalWidth;
					canvas.height = img.naturalHeight;
					const context = canvas.getContext("2d");
					context.drawImage(img, 0, 0);
					return { width: canvas.width, height: canvas.height, data: context.getImageData(0, 0, canvas.width, canvas.height).data };
				}
				const bg = await imageDataFor(".board > img");
				const pieceData = await imageDataFor(".piece");
				let bgEdgeCount = 0;
				const edgeColumns = Array(bg.width).fill(0);
				const edgeRows = Array(bg.height).fill(0);
				for (let y = 0; y < bg.height; y += 1) {
					for (let x = 0; x < bg.width; x += 1) {
						const index = (y * bg.width + x) * 4;
						const red = bg.data[index];
						const green = bg.data[index + 1];
						const blue = bg.data[index + 2];
						const alpha = bg.data[index + 3];
						if (alpha > 200 && red >= 104 && red <= 132 && green >= 114 && green <= 144 && blue >= 126 && blue <= 156) {
							bgEdgeCount += 1;
							edgeColumns[x] += 1;
							edgeRows[y] += 1;
						}
					}
				}
				const groups = [];
				let currentGroup = null;
				for (let x = 0; x < edgeColumns.length; x += 1) {
					const count = edgeColumns[x];
					if (count <= 0) continue;
					if (!currentGroup || x > currentGroup.maxX + 1) {
						currentGroup = { minX: x, maxX: x, count, maxColumn: count };
						groups.push(currentGroup);
					} else {
						currentGroup.maxX = x;
						currentGroup.count += count;
						currentGroup.maxColumn = Math.max(currentGroup.maxColumn, count);
					}
				}
				const gapGroup = groups
					.filter((group) => group.maxX - group.minX >= 18 && group.count >= 35)
					.sort((a, b) => b.count - a.count || b.maxColumn - a.maxColumn)[0];
				let pieceOpaqueCount = 0;
				let pieceMinX = pieceData.width;
				let pieceMaxX = -1;
				for (let y = 0; y < pieceData.height; y += 1) {
					for (let x = 0; x < pieceData.width; x += 1) {
						const alpha = pieceData.data[(y * pieceData.width + x) * 4 + 3];
						if (alpha > 20) {
							pieceOpaqueCount += 1;
							pieceMinX = Math.min(pieceMinX, x);
							pieceMaxX = Math.max(pieceMaxX, x);
						}
					}
				}
				if (!gapGroup || pieceOpaqueCount < 200) {
					throw new Error(`could not infer slider target, bgEdge=${bgEdgeCount}, groups=${JSON.stringify(groups)}, pieceOpaque=${pieceOpaqueCount}`);
				}
				const activeRows = edgeRows.map((count, y) => ({ count, y })).filter((row) => row.count > 0);
				const x = Math.round(gapGroup.minX - pieceMinX);
				return {
					x,
					bgEdgeCount,
					pieceOpaqueCount,
					bgBounds: {
						minX: gapGroup.minX,
						maxX: gapGroup.maxX,
						minY: Math.min(...activeRows.map((row) => row.y)),
						maxY: Math.max(...activeRows.map((row) => row.y))
					},
					darkGroups: groups,
					pieceBounds: { minX: pieceMinX, maxX: pieceMaxX }
				};
			});
			const max = Number(await control.getAttribute("aria-valuemax"));
			if (!Number.isFinite(max) || target.x <= 0 || target.x > max) {
				throw new Error(`unexpected slider target ${JSON.stringify(target)}, max=${max}`);
			}
			async function pieceLeftInViewUnits() {
				return await piece.evaluate((el) => {
					const pieceRect = el.getBoundingClientRect();
					const boardRect = el.parentElement.getBoundingClientRect();
					return Math.round((pieceRect.left - boardRect.left) / boardRect.width * 320);
				});
			}
			const beforeLeft = await pieceLeftInViewUnits();
			async function eventInit(value, buttons) {
				return await control.evaluate((el, payload) => {
					const rect = el.getBoundingClientRect();
					const ratio = payload.value / payload.max;
					return {
						clientX: rect.left + rect.width * ratio,
						clientY: rect.top + rect.height / 2,
						pointerId: payload.pointerId,
						pointerType: "mouse",
						button: 0,
						buttons: payload.buttons,
						bubbles: true,
						cancelable: true
					};
				}, { value, max, buttons, pointerId: item.type === "SLIDER" ? 91 : 92 });
			}
			await control.dispatchEvent("pointerdown", await eventInit(0, 1));
			await page.waitForTimeout(120);
			await control.dispatchEvent("pointermove", await eventInit(target.x, 1));
			await page.waitForTimeout(150);
			const duringLeft = await pieceLeftInViewUnits();
			await control.dispatchEvent("pointerup", await eventInit(target.x, 0));
			await page.waitForFunction(() => document.querySelector(".browser-bar strong")?.textContent?.trim() === "通过");
			results.push({
				type: item.type,
				target,
				max,
				beforeLeft,
				duringLeft,
				status: await page.locator(".browser-bar strong").innerText(),
				sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
				footer: await frame.locator("footer").innerText(),
				value: await control.getAttribute("aria-valuenow")
			});
		}
		return results;
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const results = JSON.parse(output.result);
		for (const result of results) {
			const value = Number(result.value);
			if (Math.abs(value - result.target.x) > 1 || Math.abs(result.duringLeft - result.target.x) > 3 || result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发")) {
				console.error(`unexpected slider success result: ${JSON.stringify(result)}`);
				process.exit(1);
			}
		}
	' <<<"$result"
}

open_demo_rotate_success_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-rotate-success-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /旋转校准 ROTATE/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=ROTATE")));
		await page.waitForTimeout(300);
		const rotateFrame = page.frames().find((frame) => frame.url().includes("captcha_type=ROTATE"));
		const control = rotateFrame.locator(".drag-control");
		const image = rotateFrame.locator(".rotating-image");
		await control.waitFor();
		await image.waitFor();
		const beforeTransform = await image.evaluate((el) => el.style.transform || "");
		const answer = await rotateFrame.evaluate(async () => {
			const image = document.querySelector(".rotating-image");
			if (!image) throw new Error("missing rotate image");
			const img = new Image();
			img.decoding = "async";
			img.src = image.currentSrc || image.src;
			await img.decode();
			const canvas = document.createElement("canvas");
			canvas.width = img.naturalWidth;
			canvas.height = img.naturalHeight;
			const context = canvas.getContext("2d", { willReadFrequently: true });
			context.drawImage(img, 0, 0);
			const data = context.getImageData(0, 0, canvas.width, canvas.height);
			function isBlue(bytes, offset) {
				const red = bytes[offset];
				const green = bytes[offset + 1];
				const blue = bytes[offset + 2];
				const alpha = bytes[offset + 3];
				return alpha > 180 && blue > 160 && green > 60 && green < 150 && red < 90 && blue - red > 100;
			}
			const observed = new Uint8Array(data.width * data.height);
			let observedCount = 0;
			for (let y = 0; y < data.height; y += 1) {
				for (let x = 0; x < data.width; x += 1) {
					const index = y * data.width + x;
					if (isBlue(data.data, index * 4)) {
						observed[index] = 1;
						observedCount += 1;
					}
				}
			}
			if (observedCount < 400) throw new Error(`rotate image blue region is too small: ${observedCount}`);
			const model = document.createElement("canvas");
			model.width = data.width;
			model.height = data.height;
			const modelContext = model.getContext("2d", { willReadFrequently: true });
			const cx = data.width / 2;
			const cy = data.height / 2;
			function rotatePoint(x, y, angle) {
				const radians = angle * Math.PI / 180;
				return {
					x: cx + x * Math.cos(radians) - y * Math.sin(radians),
					y: cy + x * Math.sin(radians) + y * Math.cos(radians)
				};
			}
			function drawModel(start) {
				modelContext.clearRect(0, 0, model.width, model.height);
				const points = [
					rotatePoint(0, -72, start),
					rotatePoint(62, 42, start),
					rotatePoint(0, 16, start),
					rotatePoint(-62, 42, start)
				];
				modelContext.fillStyle = "rgb(37, 99, 235)";
				modelContext.beginPath();
				modelContext.moveTo(points[0].x, points[0].y);
				for (const point of points.slice(1)) modelContext.lineTo(point.x, point.y);
				modelContext.closePath();
				modelContext.fill();
				modelContext.fillStyle = "rgb(250, 204, 21)";
				modelContext.beginPath();
				modelContext.arc(cx, cy, 22, 0, Math.PI * 2);
				modelContext.fill();
				return modelContext.getImageData(0, 0, model.width, model.height).data;
			}
			let bestStart = 0;
			let bestMismatch = Number.POSITIVE_INFINITY;
			for (let candidate = 0; candidate < 360; candidate += 1) {
				const modelData = drawModel(candidate);
				let mismatch = 0;
				for (let index = 0; index < observed.length; index += 1) {
					if (observed[index] !== (isBlue(modelData, index * 4) ? 1 : 0)) mismatch += 1;
				}
				if (mismatch < bestMismatch) {
					bestMismatch = mismatch;
					bestStart = candidate;
				}
			}
			return (360 - bestStart) % 360;
		});
		if (answer <= 0) throw new Error(`unexpected rotate answer ${answer}`);
		async function eventInit(value, buttons) {
			return await control.evaluate((el, payload) => {
				const rect = el.getBoundingClientRect();
				const ratio = payload.value / 359;
				return {
					clientX: rect.left + rect.width * ratio,
					clientY: rect.top + rect.height / 2,
					pointerId: 51,
					pointerType: "mouse",
					button: 0,
					buttons: payload.buttons,
					bubbles: true,
					cancelable: true
				};
			}, { value, buttons });
		}
		await control.dispatchEvent("pointerdown", await eventInit(0, 1));
		await page.waitForTimeout(130);
		await control.dispatchEvent("pointermove", await eventInit(answer, 1));
		await page.waitForTimeout(150);
		const duringTransform = await image.evaluate((el) => el.style.transform || "");
		await control.dispatchEvent("pointerup", await eventInit(answer, 0));
		await page.waitForFunction(() => document.querySelector(".browser-bar strong")?.textContent?.trim() === "通过");
		return {
			answer,
			beforeTransform,
			duringTransform,
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await rotateFrame.locator("footer").innerText(),
			value: await control.getAttribute("aria-valuenow")
		};
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const result = JSON.parse(output.result);
		if (result.beforeTransform === result.duringTransform || result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发")) {
			console.error(`unexpected rotate success result: ${JSON.stringify(result)}`);
			process.exit(1);
		}
	' <<<"$result"
}

open_demo_rotate_degree_success_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-rotate-degree-success-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /角度刻度 ROTATE_DEGREE/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=ROTATE_DEGREE")));
		await page.waitForTimeout(300);
		const degreeFrame = page.frames().find((frame) => frame.url().includes("captcha_type=ROTATE_DEGREE"));
		const control = degreeFrame.locator(".drag-control");
		const needle = degreeFrame.locator(".degree-needle");
		const image = degreeFrame.locator(".board img").first();
		await control.waitFor();
		await needle.waitFor();
		await image.waitFor();
		const target = await image.evaluate(async (el) => {
			const img = el;
			if (!img.complete || !img.naturalWidth) {
				await new Promise((resolve, reject) => {
					img.addEventListener("load", resolve, { once: true });
					img.addEventListener("error", reject, { once: true });
				});
			}
			if (!img.naturalWidth || !img.naturalHeight) {
				throw new Error("rotate degree image has no natural size");
			}
			const canvas = document.createElement("canvas");
			canvas.width = img.naturalWidth;
			canvas.height = img.naturalHeight;
			const context = canvas.getContext("2d");
			context.drawImage(img, 0, 0);
			const data = context.getImageData(0, 0, canvas.width, canvas.height).data;
			let count = 0;
			let sumX = 0;
			let sumY = 0;
			for (let y = 0; y < canvas.height; y += 1) {
				for (let x = 0; x < canvas.width; x += 1) {
					const index = (y * canvas.width + x) * 4;
					const red = data[index];
					const green = data[index + 1];
					const blue = data[index + 2];
					if (red > 180 && green < 120 && blue < 130 && red - green > 70 && red - blue > 70) {
						count += 1;
						sumX += x;
						sumY += y;
					}
				}
			}
			if (count < 20) {
				throw new Error(`could not find red target tick, count=${count}`);
			}
			const avgX = sumX / count;
			const avgY = sumY / count;
			const dx = avgX - canvas.width / 2;
			const dy = avgY - canvas.height / 2;
			const angle = Math.round((Math.atan2(dx, -dy) * 180 / Math.PI + 360) % 360);
			return { angle, count, avgX, avgY };
		});
		const max = Number(await control.getAttribute("aria-valuemax"));
		if (!Number.isFinite(max) || max <= 0) throw new Error(`unexpected rotate degree max: ${max}`);
		if (target.angle <= 0 || target.angle > max) throw new Error(`unexpected rotate degree target: ${JSON.stringify(target)}, max=${max}`);
		const beforeTransform = await needle.evaluate((el) => el.style.transform || "");
		async function eventInit(value, buttons) {
			return await control.evaluate((el, payload) => {
				const rect = el.getBoundingClientRect();
				const ratio = payload.value / payload.max;
				return {
					clientX: rect.left + rect.width * ratio,
					clientY: rect.top + rect.height / 2,
					pointerId: 81,
					pointerType: "mouse",
					button: 0,
					buttons: payload.buttons,
					bubbles: true,
					cancelable: true
				};
			}, { value, max, buttons });
		}
		await control.dispatchEvent("pointerdown", await eventInit(0, 1));
		await page.waitForTimeout(120);
		await control.dispatchEvent("pointermove", await eventInit(target.angle, 1));
		await page.waitForTimeout(150);
		const duringTransform = await needle.evaluate((el) => el.style.transform || "");
		await control.dispatchEvent("pointerup", await eventInit(target.angle, 0));
		await page.waitForFunction(() => document.querySelector(".browser-bar strong")?.textContent?.trim() === "通过");
		return {
			target,
			max,
			beforeTransform,
			duringTransform,
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await degreeFrame.locator("footer").innerText(),
			value: await control.getAttribute("aria-valuenow")
		};
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		const result = JSON.parse(output.result);
		const value = Number(result.value);
		if (result.target.count < 20 || Math.abs(value - result.target.angle) > 1 || result.beforeTransform === result.duringTransform || result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发")) {
			console.error(`unexpected rotate degree success result: ${JSON.stringify(result)}`);
			process.exit(1);
		}
	' <<<"$result"
}

open_demo_concat_success_check() {
	local demo_url="http://127.0.0.1:$RUNTIME_PORT/demo"
	local result
	pw_goto "$demo_url" "$TMP_DIR/demo-concat-success-open.log"
	result="$(bash "$PWCLI" --json run-code 'async (page) => {
		await page.getByRole("button", { name: /滑动还原 CONCAT/ }).click();
		await page.waitForFunction(() => Array.from(document.querySelectorAll("iframe")).some((el) => el.src.includes("captcha_type=CONCAT")));
		await page.waitForTimeout(300);
		const concatFrame = page.frames().find((frame) => frame.url().includes("captcha_type=CONCAT"));
		const control = concatFrame.locator(".drag-control");
		const topPiece = concatFrame.locator(".concat-piece-top");
		await control.waitFor();
		await topPiece.waitFor();
		async function pieceLeftInViewUnits(piece) {
			return await piece.evaluate((el) => {
				const pieceRect = el.getBoundingClientRect();
				const boardRect = el.parentElement.getBoundingClientRect();
				return Math.round((pieceRect.left - boardRect.left) / boardRect.width * 320);
			});
		}
		const inferred = await concatFrame.evaluate(async () => {
			async function imageData(src) {
				const img = new Image();
				img.decoding = "async";
				img.src = src;
				await img.decode();
				const canvas = document.createElement("canvas");
				canvas.width = img.naturalWidth;
				canvas.height = img.naturalHeight;
				const context = canvas.getContext("2d");
				context.drawImage(img, 0, 0);
				return context.getImageData(0, 0, canvas.width, canvas.height);
			}
			function offsetOf(data, x, y) {
				return (y * data.width + x) * 4;
			}
			function alphaAt(data, x, y) {
				return data.data[offsetOf(data, x, y) + 3];
			}
			function rgbDelta(aData, ax, ay, bData, bx, by) {
				const aOffset = offsetOf(aData, ax, ay);
				const bOffset = offsetOf(bData, bx, by);
				return Math.abs(aData.data[aOffset] - bData.data[bOffset]) +
					Math.abs(aData.data[aOffset + 1] - bData.data[bOffset + 1]) +
					Math.abs(aData.data[aOffset + 2] - bData.data[bOffset + 2]);
			}
			const bg = document.querySelector(".board > img");
			const piece = document.querySelector(".concat-piece-top");
			const control = document.querySelector(".drag-control");
			const max = Number(control.getAttribute("aria-valuemax"));
			const bgData = await imageData(bg.src);
			const pieceData = await imageData(piece.src);
			const viewWidth = 320;
			const shift = pieceData.width - viewWidth;
			const pieceEdge = Array.from({ length: pieceData.width }, (_, x) => {
				for (let y = 1; y < pieceData.height; y += 1) {
					if (alphaAt(pieceData, x, y) < 20) return y;
				}
				return -1;
			}).filter((value) => value > 4 && value < pieceData.height - 4);
			if (pieceEdge.length < pieceData.width * 0.75) {
				throw new Error(`could not locate concat moving-half split: ${pieceEdge.length}/${pieceData.width}`);
			}
			pieceEdge.sort((a, b) => a - b);
			const splitY = pieceEdge[Math.floor(pieceEdge.length / 2)];
			let best = 0;
			let bestScore = Number.POSITIVE_INFINITY;
			for (let candidate = 0; candidate <= max; candidate += 1) {
				let score = 0;
				let count = 0;
				for (let x = 6; x < viewWidth - 6; x += 3) {
					const pieceX = Math.round(x + shift - candidate);
					if (pieceX < 0 || pieceX >= pieceData.width) continue;
					for (const delta of [1, 3, 6, 10]) {
						if (splitY - delta < 0 || splitY + delta >= bgData.height) continue;
						score += rgbDelta(pieceData, pieceX, splitY - delta, bgData, x, splitY + delta);
						count += 1;
					}
				}
				const normalized = count ? score / count : Number.POSITIVE_INFINITY;
				if (normalized < bestScore) {
					bestScore = normalized;
					best = candidate;
				}
			}
			return {
				answer: best,
				max,
				shift,
				bestScore,
				splitY,
				bottomCount: document.querySelectorAll(".concat-piece-bottom").length
			};
		});
		const beforeTopLeft = await pieceLeftInViewUnits(topPiece);
		const answer = inferred.answer;
		const max = inferred.max;
		if (answer <= 0 || answer > max || inferred.bottomCount !== 0 || Math.abs(beforeTopLeft + inferred.shift) > 3) {
			throw new Error(`unexpected concat inference ${JSON.stringify({ ...inferred, beforeTopLeft })}`);
		}
		async function eventInit(value, buttons) {
			return await control.evaluate((el, payload) => {
				const rect = el.getBoundingClientRect();
				const ratio = payload.value / payload.max;
				return {
					clientX: rect.left + rect.width * ratio,
					clientY: rect.top + rect.height / 2,
					pointerId: 71,
					pointerType: "mouse",
					button: 0,
					buttons: payload.buttons,
					bubbles: true,
					cancelable: true
				};
			}, { value, max, buttons });
		}
		await control.dispatchEvent("pointerdown", await eventInit(0, 1));
		await page.waitForTimeout(120);
		await control.dispatchEvent("pointermove", await eventInit(answer, 1));
		await page.waitForTimeout(150);
		const duringTopLeft = await pieceLeftInViewUnits(topPiece);
		await control.dispatchEvent("pointerup", await eventInit(answer, 0));
		await page.waitForFunction(() => {
			const status = document.querySelector(".browser-bar strong")?.textContent?.trim();
			return status === "通过" || status === "失败";
		});
		return {
			answer,
			max,
			shift: inferred.shift,
			beforeTopLeft,
			duringTopLeft,
			bottomCount: inferred.bottomCount,
			status: await page.locator(".browser-bar strong").innerText(),
			sideResult: await page.locator(".demo-metrics dd").nth(2).innerText(),
			footer: await concatFrame.locator("footer").innerText(),
			value: await control.getAttribute("aria-valuenow")
		};
	}')"
	node -e '
		const fs = require("fs");
		const output = JSON.parse(fs.readFileSync(0, "utf8"));
		if (!Object.prototype.hasOwnProperty.call(output, "result")) {
			console.error(`concat smoke did not return a result: ${JSON.stringify(output)}`);
			process.exit(1);
		}
		const result = JSON.parse(output.result);
		if (Math.abs(result.duringTopLeft - (result.answer - result.shift)) > 3 || result.bottomCount !== 0 || result.status !== "通过" || result.sideResult !== "通过" || !result.footer.includes("ticket 已签发")) {
			console.error(`unexpected concat success result: ${JSON.stringify(result)}`);
			process.exit(1);
		}
	' <<<"$result"
}

start_bg captcha-server env \
	CAPTCHA_ENV=development \
	CAPTCHA_PRODUCTION=false \
	CAPTCHA_ADDR="$SERVER_HTTP_ADDR" \
	CAPTCHA_GRPC_ADDR="$SERVER_GRPC_ADDR" \
	CAPTCHA_RUNTIME_URL="http://127.0.0.1:$RUNTIME_PORT" \
	go run ./cmd/captcha-server
wait_http "http://$SERVER_HTTP_ADDR/healthz"

start_bg_in runtime "$ROOT_DIR/web/runtime" env \
	VITE_API_BASE="http://$SERVER_HTTP_ADDR" \
	npx vite --host 127.0.0.1 --port "$RUNTIME_PORT"
wait_http "http://127.0.0.1:$RUNTIME_PORT/"

start_bg_in admin "$ROOT_DIR/web/admin" env \
	VITE_API_BASE="http://$SERVER_HTTP_ADDR" \
	npx vite --host 127.0.0.1 --port "$ADMIN_PORT"
wait_http "http://127.0.0.1:$ADMIN_PORT/"

run_smoke_step "start browser session" start_browser_session

run_smoke_step "runtime random challenge" open_runtime_random_challenge
run_smoke_step "demo random selector" open_demo_random_selector
run_smoke_step "demo failure reset checks" open_demo_failure_reset_checks
run_smoke_step "demo gesture straight-line failure" open_demo_gesture_straight_failure_check
run_smoke_step "demo jigsaw drag swap" open_demo_jigsaw_drag_swap_check
run_smoke_step "demo point click success" open_demo_point_click_success_check
run_smoke_step "demo grid click success" open_demo_grid_click_success_check
run_smoke_step "demo grid click failure" open_demo_grid_click_failure_check
run_smoke_step "demo curve wrong-offset failure" open_demo_curve_wrong_offset_failure_check
run_smoke_step "demo curve match success" open_demo_curve_match_success_check
run_smoke_step "demo path success" open_demo_path_success_check
run_smoke_step "demo slider success" open_demo_slider_success_check
run_smoke_step "demo rotate success" open_demo_rotate_success_check
run_smoke_step "demo rotate degree success" open_demo_rotate_degree_success_check
run_smoke_step "demo concat success" open_demo_concat_success_check
run_smoke_step "runtime proof-of-work challenge" open_runtime_pow_challenge
run_smoke_step "runtime gesture render" open_runtime_challenge "GESTURE" "按提示描绘图形" "disabled"
run_smoke_step "runtime curve v3 render" open_runtime_challenge "CURVE_V3" "拖动滑块使圆环曲线匹配" "disabled"
run_smoke_step "runtime curve v2 render" open_runtime_challenge "CURVE_V2" "拖动滑块使增强曲线匹配" "disabled"
run_smoke_step "runtime curve render" open_runtime_challenge "CURVE" "拖动滑块使曲线匹配" "disabled"
run_smoke_step "runtime slider v2 render" open_runtime_challenge "SLIDER_V2" "拖动增强滑块完成拼图" "disabled"
run_smoke_step "runtime slider render" open_runtime_challenge "SLIDER" "拖动滑块完成拼图" "disabled"
run_smoke_step "runtime rotate render" open_runtime_challenge "ROTATE" "旋转图形至正向" "disabled"
run_smoke_step "runtime concat render" open_runtime_challenge "CONCAT" "拖动滑块完成拼图" "disabled"
run_smoke_step "runtime rotate degree render" open_runtime_challenge "ROTATE_DEGREE" "拖动指针指向红色刻度" "disabled"
run_smoke_step "runtime word click render" open_runtime_challenge "WORD_IMAGE_CLICK" "依次点击：" "disabled"
run_smoke_step "runtime image click render" open_runtime_challenge "IMAGE_CLICK" "依次点击：" "disabled"
run_smoke_step "runtime jigsaw render" open_runtime_challenge "JIGSAW" "拖动或点击交换错位拼图" "disabled"
run_smoke_step "runtime grid image click render" open_runtime_challenge "GRID_IMAGE_CLICK" "选择所有包含蓝色圆形的图片" "disabled"

admin_url="http://127.0.0.1:$ADMIN_PORT/overview"
smoke_step "admin overview navigation"
pw_goto "$admin_url" "$TMP_DIR/admin-open.log"
bash "$PWCLI" snapshot >"$TMP_DIR/admin-snapshot.yml"
snapshot_contains "$TMP_DIR/admin-snapshot.yml" "概览"
snapshot_contains "$TMP_DIR/admin-snapshot.yml" "运行中"
admin_applications_ref="$(snapshot_ref "$TMP_DIR/admin-snapshot.yml" 'menuitem ".*应用"')"
bash "$PWCLI" click "$admin_applications_ref" >"$TMP_DIR/admin-click.log"
sleep 1
bash "$PWCLI" snapshot >"$TMP_DIR/admin-applications.yml"
snapshot_contains "$TMP_DIR/admin-applications.yml" "demo-app"
snapshot_contains "$TMP_DIR/admin-applications.yml" "fail_open"

run_smoke_step "admin overview route" open_admin_page "/overview" "overview" "概览" "验证通过率" "运行状态"
run_smoke_step "admin applications route" open_admin_page "/applications" "applications" "应用" "demo-app" "fail_open"
run_smoke_step "admin routes route" open_admin_page "/routes" "routes" "路由策略" "路径" "模式"
run_smoke_step "admin ip policies route" open_admin_page "/ip-policies" "ip-policies" "IP 策略" "CIDR" "动作"
run_smoke_step "admin policy simulate route" open_admin_page "/policy-simulate" "policy-simulate" "策略模拟" "Client ID" "模拟"
run_smoke_step "admin resources route" open_admin_page "/resources" "resources" "资源" "验证码" "来源"
run_smoke_step "admin audit route" open_admin_page "/audit" "audit" "审计" "原因" "结果"
run_smoke_step "admin risk features route" open_admin_page "/risk-features" "risk-features" "训练特征" "导出 JSONL" "标签"
run_smoke_step "admin risk models route" open_admin_page "/risk-models" "risk-models" "模型版本" "模式" "状态"

echo "browser smoke passed"
