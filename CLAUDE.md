# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A badminton club (羽球社) management web app for 台元健身中心 (Taiyuan Fitness Center). It helps players coordinate court reservations, track memberships, manage expenses, and analyze participation frequency.

## Architecture

This project has no build system. There are only two meaningful files:

- **`index.html`** — The entire frontend: a single-page app with embedded CSS + vanilla JS, organized into 6 emoji tabs.
- **`worker.js`** — A Cloudflare Worker providing the backend API + KV storage.

The Worker is deployed separately via the Cloudflare dashboard (copy-paste into the web editor). The frontend is served directly from GitHub Pages or as a static file.

## Deployment

- **Worker URL:** `https://gym-query.linlinlailai.workers.dev`
- **Worker deployment:** Paste `worker.js` into the Cloudflare Workers web editor and click Deploy. No CLI tooling is configured.
- **KV binding:** The Worker requires a KV namespace bound as `BALL_KV`.
- **Secret:** The Worker requires a Secret named `CLUB_PASSWORD` (Settings → Variables and Secrets, type **Secret**, not KV). Its value is the correct answer to the frontend's verification question — never write the answer into the code or docs (the repo is public).
- **Deploy order when an API/auth contract changes:** set secrets → deploy `worker.js` → push `index.html`. If the frontend goes live first, CORS preflight rejects the new header and every write fails.

## Write Authentication

All writes (POST/PUT/DELETE, except `/login`, which is the gym member login) go through `checkClubPassword()` in `worker.js`: the `X-Club-Password` header must equal `encodeURIComponent(env.CLUB_PASSWORD)` (URI-encoded because headers can't carry Chinese). Missing/wrong → `401 { authRequired: true }`; secret not set → `500`. GET requests are open.

On the frontend, **every write must use `apiWrite(path, options)`, not raw `fetch`.** It attaches the header, and on a missing/wrong answer it asks the multiple-choice question `CLUB_QUESTION` ("團主是誰？") with options `CLUB_CHOICES` (via `askText({ choices })`), retries, and stores the accepted answer in `localStorage` (`clubPassword`). If the user cancels, it returns a `{ success: false }` Response so callers' existing error handling still works. Only 6 options means this deters casual edits, not a determined attacker.

`askText({ title, message, placeholder, type, isError, choices })` is the shared modal (`#askOverlay`): a text input normally, or a grid of option buttons when `choices` is given. Resolves to the string, or `null` on cancel.

## Frontend Structure (index.html)

Six tabs (previously seven — 🛒 買球記帳 was merged into 💰 分帳計算):

| Tab | Function | Description |
|-----|----------|-------------|
| 📋 通知產生器 | `createTimeButtons()` / `createPlayerButtons()` | Generate LINE messages for court bookings |
| 🔍 會員快速查詢 | `initMembershipTab()` | Look up gym membership expiry via CAPTCHA login |
| 🏸 戰術板 | `initTacticalBoard()` | Drag-drop player positions on court diagram (has fullscreen mode) |
| 🏆 計分板 | `initScoreboard()` | In-game point tracking (has fullscreen mode) |
| 💰 分帳計算 | `initSplitCalcTab()` / `initBallInventory()` | Two sub-tabs (see below) |
| 📒 公帳紀錄 | `initPublicAccountTab()` | Club fund ledger: income/expense records + running balance |

The page always opens on 📋 通知產生器 — the last-used tab is intentionally **not** remembered.

### Mobile layout (≤768px)

- **Tab bar:** a sticky 3×2 grid (`.tab-icon` emoji above `.tab-label`). After scrolling down past ~160px, `initCompactTabs()` adds `.compact`, shrinking it to a single thin row of emoji only; it expands again near the top (<40px). The two thresholds are deliberately different to avoid flicker.
- **Time slot buttons:** all six sit in one row (6-column grid).

### Fullscreen mode (戰術板 & 計分板)

Both tabs share one implementation: `setFullscreen(el, open)` toggles `.fullscreen` on the element and `fs-open` on `<body>`. Wrappers are `toggleTacticalFullscreen()` (also re-places dots via `recalculatePlayerPositions()`) and `toggleScoreboardFullscreen()` (also holds a screen Wake Lock). `initFullscreen()` blocks `touchmove` inside `.fullscreen` (needed on iOS Safari) and closes on Esc. Each fullscreen element contains its own `.fs-close-btn` (✕).

Tactical board dots/shuttlecock use `touch-action: none` and an enlarged `::after` hit area so dragging doesn't scroll the page. In fullscreen, `.formation-bar` is exempt from the `touchmove` block so it can scroll sideways.

Tactical fullscreen layout: `#tacticalControls` becomes an absolutely positioned top bar sharing the row with ✕ (icon-only — button text lives in `.tc-label`, hidden in fullscreen); only the formation bar sits below the court. The court height is `100dvh - 140px` (minus safe areas); if you add rows above/below the court in fullscreen, adjust that number. While drawing in fullscreen, 🔄 重置 is hidden to make room for the color swatches.

### 🏸 戰術板 — 箭頭與站位

- **Positions** (`currentPositions`) and **arrows** (`arrows = [{ x1, y1, x2, y2, color }]`) are both stored as **percentages** of the court, so they survive resizing/fullscreen. `recalculatePlayerPositions()` re-places dots and calls `renderArrows()`, which redraws the `#arrowLayer` SVG in pixel coordinates.
- **Drawing:** `toggleDrawMode()` turns on drawing (`.drawing` on the court). `initArrowDrawing()` handles mouse/touch; a press on a dot or the shuttlecock still drags it instead of drawing, and lines under 15px are discarded as accidental taps.
- **Colors:** `ARROW_COLORS` (yellow / red / white / blue); the swatches (`#arrowColors`, built by `renderArrowColors()`) only show while drawing (`.drawing` on `#tacticalControls`). New arrows take the current `arrowColor`; arrows without `color` (older saved formations) render yellow. `renderArrows()` creates one SVG `<marker>` per color in use so arrowheads match their line.
- **Formations:** `PRESET_FORMATIONS` are built in (預設 / 進攻・前後站 / 防守・左右站). User-saved ones (positions + arrows) live in `localStorage` under `tacticalFormations`, so they are per-device, not shared. `renderFormationBar()` builds chips with DOM APIs (`textContent`), so user-typed names are never injected as HTML.

### 📋 通知產生器 — 時段與球員

- `const times = [...]` — time slot buttons (currently 18:00–20:30, every 30 min). The generated message sorts slots with `Object.keys(...).sort()`, so keep the `HH:MM` format.
- Players with `bench: true` in `players` are rendered into the collapsible 🪑 板凳 block instead of the main list. Moving a player between the main list and the bench = toggling this flag.

### 📋 通知產生器 — 🚫 禁用卡號紀錄

A collapsible block inside the notification tab (`initBanBlock()`) records players whose gym card is temporarily banned (ban date + date the card becomes usable again, computed in local time). Banned players still appear in the notification generator's player list but are flagged with a red warning. Records are stored in the backend via `/ban-records`.

### 💰 分帳計算 Sub-tabs

| Sub-tab | Content |
|---------|---------|
| **2026/03 舊分帳模式** | 🛒 買球記帳 (purchase records) + 球員頻率分級 (drag-drop tiers) + 🧮 分帳計算機 (tier-based cost splitting) |
| **新分帳模式 📦球的分配與庫存** (default) | 📦 進貨與分配 (purchase + player distribution with buyer) + 🏠 庫存狀態 (per-player progress bars) + 📈 用球趨勢 (Chart.js line chart) |

**Key constants at top of `<script>`:**
```js
const WORKER_URL = 'https://gym-query.linlinlailai.workers.dev';
const players = [...]; // 34 players: { id: "<card no><name><suffix>", label: "<中文名> <English name>", bench?: true }
```

## Backend API (worker.js)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/captcha` | Proxy gym CAPTCHA image + return session cookie |
| POST | `/login` | Authenticate with gym, return membership expiry date |
| GET | `/test` | Debug endpoint for the gym CAPTCHA fetch |
| GET | `/ball-purchases` | Fetch all purchase records from KV |
| POST | `/ball-purchases` | Add a new purchase record |
| DELETE | `/ball-purchases/:id` | Delete a purchase record |
| GET | `/frequency-tiers` | Fetch tier assignments (S/A/B/C/unassigned) |
| POST | `/frequency-tiers` | Save tier assignments |
| GET | `/payment-status` | Fetch split-calc payment status per player |
| POST | `/payment-status` | Save split-calc payment status |
| GET | `/ball-inventory` | Fetch all purchase + inventory log data |
| POST | `/ball-inventory/purchase` | Add a purchase with player distributions |
| PUT | `/ball-inventory/purchase/:id` | Edit an existing purchase record |
| DELETE | `/ball-inventory/purchase/:id` | Delete a purchase record |
| POST | `/ball-inventory/update-stock` | Update a player's remaining tube count |
| GET | `/public-account` | Fetch club fund ledger records |
| POST | `/public-account` | Add an income/expense record |
| DELETE | `/public-account/:id` | Delete a ledger record |
| GET | `/ban-records` | Fetch banned-card records |
| POST | `/ban-records` | Add a record (`playerId`, `playerLabel`, `banDate`, `availDate`) |
| DELETE | `/ban-records/:id` | Delete a banned-card record |

**KV keys:**
- `ball_purchases` — array of purchase objects
- `frequency_tiers` — object with S/A/B/C/unassigned arrays
- `payment_status` — object mapping player name → paid boolean
- `ball_inventory` — `{ purchases: [...], inventoryLogs: [...] }` for ball distribution & stock tracking
- `public_account` — array of club fund ledger records
- `ban_records` — array of `{ id, playerId, playerLabel, banDate, availDate }`

When adding a new endpoint, also add it to the `endpoints` list in the fallback response at the end of the router in `worker.js`. New write endpoints are protected automatically by `checkClubPassword()`; call them from the frontend with `apiWrite()`.

## Frequency Tier Logic

Players are sorted into tiers by annual attendance, each tier carrying a share weight used to proportionally divide annual court costs:

| Tier | Frequency | Default Shares |
|------|-----------|----------------|
| S | 100+/year | 10 |
| A | 50–100/year | 6 |
| B | 20–50/year | 3 |
| C | ≤20/year | 1 |

Share weights are adjustable via range sliders; costs auto-recalculate on any change.

## Editing Notes

- `index.html` is committed with **CRLF** line endings. Scripts that rewrite the file (e.g. Python, or Git Bash `sed -i`) must preserve CRLF, otherwise the whole file shows up as changed in the diff.
- `worker.js` can be unit-tested locally with Node: copy it to a `.mjs` file, `import worker from ...`, and call `worker.fetch(new Request(...), env)` with a mock `env` (`CLUB_PASSWORD` + a `Map`-backed `BALL_KV`).
- No test suite exists. To check the mobile layout, serve the folder (`python -m http.server`) and view it at phone width; headless Edge/Chrome can't shrink the window below ~500px, so wrap the page in a 375px-wide `<iframe>` when taking screenshots.

## Archive Files

`index_old.html`, `index_old20260216.html`, `index_simple_20250718.html`, and `old.html` are historical snapshots — do not modify them.
