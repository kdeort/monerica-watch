# Monerica Watch (v0.1)

An open-source, zero-dependency watchdog that monitors all 1,423+ Monero services in [Monerica's `data.json`](https://monerica.com/data.json) and alerts users when a service:
- Changes its **KYC Policy** (e.g., `Guaranteed No KYC` → `Shotgun KYC`)
- Changes its **Verification Status** (`Verified` → `Questionable` or `Scam`)
- Receives an inline **Scam / Reliability Warning**
- Joins or leaves the directory

## Features Live in v0.1
- **Zero-Dependency Diff Engine (`monerica_watch.py`):** Uses only Python 3 standard library.
- **Static Web Dashboard (`index.html`):** Filterable dark-mode alert table with zero trackers.
- **RSS 2.0 Alert Feed (`data/feed.xml`):** Subscribe in any RSS reader.
- **Telegram Webhook Support:** Optional instant push alerts via environment variables.

## v1.0 Roadmap (Funded via Kuno — 4 XMR Goal)
- [ ] **Milestone 1 (1.5 XMR):** SimpleX Chat & Matrix bot integration so users can subscribe to KYC/scam alerts without Telegram.
- [ ] **Milestone 2 (1.5 XMR):** Automated `.onion` & clearnet uptime prober to detect when listed services go offline before users send funds.
- [ ] **Milestone 3 (1.0 XMR):** Dedicated Tor `.onion` mirror and No-JS server-side HTML archive.

## Supporters Wall
- *Become the first supporter on Kuno to have your handle listed here!*