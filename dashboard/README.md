# Ironward Dashboard

Local web UI for Ironward scan history — stats, recent findings, per-repo security score.

Self-hosted. Zero cloud. All data lives in `~/.ironward/ironward.db` on your machine.

## Quickstart

```bash
cd dashboard
npm install
npm run seed        # optional: populate with example findings
npm run dev
# open http://localhost:3737
```

## Install with your own scans

Run the CLI with recording enabled:

```bash
# one-shot
IRONWARD_RECORD=1 npx ironward scan-secrets src/
IRONWARD_RECORD=1 npx ironward scan-url https://your-site.com

# tag scans with a repo slug so the Repos page groups them
IRONWARD_RECORD=1 IRONWARD_REPO=rayentr/myapp npx ironward scan-secrets src/
```

The CLI POSTs each scan to `http://localhost:3737/api/ingest` by default. Point it elsewhere with:

```bash
IRONWARD_DASHBOARD_URL=http://my-dashboard.tailnet:3737 npx ironward scan-secrets src/
```

## Clearing data

Seed rows are tagged with `is_demo = 1`, so you can wipe them without touching real scans.

```bash
npm run wipe:demo     # remove only the example/demo entries
npm run wipe          # remove ALL scan history (real + demo)
```

Or click **Clear data ▾** in the dashboard header for the same options.

## Database

- **Path** — `~/.ironward/ironward.db` by default, overridable via `IRONWARD_DB`.
- **Schema** — auto-migrated on first query via [src/lib/db.ts](src/lib/db.ts).
- **Tables** — `scans`, `findings`.

## Pages

- `/` — Overview: stats + recent findings
- `/findings` — Full findings list with severity / status filters
- `/repos` — Per-repo security score (0-100, penalty-weighted)
- `POST /api/ingest` — CLI/MCP ingest endpoint

## Build

```bash
npm run build
npm start
```

## License

MIT · part of [ironward](https://www.npmjs.com/package/ironward).
