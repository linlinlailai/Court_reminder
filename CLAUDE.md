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

## Frontend Structure (index.html)

Six tabs, each initialized with a dedicated `init*Tab()` function:

| Tab | Function | Description |
|-----|----------|-------------|
| 📋 Notification | `initNotificationTab()` | Generate LINE messages for court bookings |
| 🔍 Membership | `initMembershipTab()` | Look up gym membership expiry via CAPTCHA login |
| 🏸 Tactical Board | `initTacticalBoard()` | Drag-drop player positions on court diagram |
| 🏆 Scoreboard | `initScoreboard()` | In-game point tracking |
| 🛒 Ball Tracker | `initBallPurchase()` | Log ball purchases, shared expense tracking |
| 💰 Split Calc | `initSplitCalcTab()` | Tier-based annual cost splitting with drag-drop |

**Key constants at top of `<script>`:**
```js
const WORKER_URL = 'https://gym-query.linlinlailai.workers.dev';
const players = [...]; // 28 players with bilingual names
```

## Backend API (worker.js)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/captcha` | Proxy gym CAPTCHA image + return session cookie |
| POST | `/login` | Authenticate with gym, return membership expiry date |
| GET | `/ball-purchases` | Fetch all purchase records from KV |
| POST | `/ball-purchases` | Add a new purchase record |
| DELETE | `/ball-purchases/:id` | Delete a purchase record |
| GET | `/frequency-tiers` | Fetch tier assignments (S/A/B/C/unassigned) |
| POST | `/frequency-tiers` | Save tier assignments |

**KV keys:** `ball_purchases` (array of purchase objects), `frequency_tiers` (object with S/A/B/C/unassigned arrays).

## Frequency Tier Logic

Players are sorted into tiers by annual attendance, each tier carrying a share weight used to proportionally divide annual court costs:

| Tier | Frequency | Default Shares |
|------|-----------|----------------|
| S | 100+/year | 10 |
| A | 50–100/year | 6 |
| B | 20–50/year | 3 |
| C | ≤20/year | 1 |

Share weights are adjustable via range sliders; costs auto-recalculate on any change.

## Archive Files

`index_old.html`, `index_old20260216.html`, `index_simple_20250718.html`, and `old.html` are historical snapshots — do not modify them.
